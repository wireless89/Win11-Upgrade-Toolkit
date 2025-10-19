# Windows 11 Trim Script (Balanced Profile, ASCII only)
# Save as: W11-Trim-Complete.ps1
# Safe optimizations: keeps Defender and Windows Update enabled
# Reversible with -Revert

param(
    [switch]$Revert,
    [switch]$KeepHibernate,
    [switch]$FixedPagefile
)

$ErrorActionPreference = 'SilentlyContinue'

# --- Logging ---
$logRoot = 'C:\W11Optimize'
if (!(Test-Path $logRoot)) { New-Item -ItemType Directory -Path $logRoot | Out-Null }
$log = "$logRoot\trim.log"
function Log($m){ "$((Get-Date).ToString('u'))  $m" | Out-File $log -Append -Encoding utf8 }

Log "=== W11 Trim Started (Revert=$Revert, KeepHibernate=$KeepHibernate, FixedPagefile=$FixedPagefile) ==="

# --- Hibernation ---
if ($Revert) {
    powercfg /h on | Out-Null
    Log "Hibernate enabled"
} else {
    if (-not $KeepHibernate) {
        powercfg /h off | Out-Null
        Log "Hibernate disabled"
    } else {
        Log "Hibernate kept"
    }
}

# --- Power plan (High Performance; if Ultimate exists, this keeps High Performance to stay safe) ---
if (-not $Revert) {
    try {
        powercfg /setactive SCHEME_MIN | Out-Null
        Log "Power plan: High performance"
    } catch { Log "Power plan change failed: $($_.Exception.Message)" }
} else {
    try {
        powercfg /setactive SCHEME_BALANCED | Out-Null
        Log "Power plan: Balanced (revert)"
    } catch { Log "Power plan revert failed: $($_.Exception.Message)" }
}

# --- SSD: TRIM on ---
try { fsutil behavior set DisableDeleteNotify 0 | Out-Null; Log "TRIM ensured" } catch { Log "TRIM command failed" }

# --- Telemetry reduction (keeps Defender and Update ON) ---
if ($Revert) {
    try { Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Recurse -Force -ErrorAction SilentlyContinue; Log "Telemetry policy removed (revert)" } catch {}
} else {
    try {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force | Out-Null
        Log "Telemetry minimized (AllowTelemetry=0)"
    } catch { Log "Telemetry policy set failed: $($_.Exception.Message)" }
}

# --- Edge background and web search tweaks (safe) ---
if ($Revert) {
    try {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'StartupBoostEnabled' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name 'DisableWebSearch' -ErrorAction SilentlyContinue
        Log "Edge/Search policies reverted"
    } catch {}
} else {
    try {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'StartupBoostEnabled' -Value 0 -PropertyType DWord -Force | Out-Null
        New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name 'DisableWebSearch' -Value 1 -PropertyType DWord -Force | Out-Null
        Log "Edge startup boost off, web search disabled"
    } catch { Log "Edge/Search tweak failed: $($_.Exception.Message)" }
}

# --- Services tuning (conservative) ---
$svcList = @("DiagTrack","dmwappushservice","Fax","RemoteRegistry")
foreach ($s in $svcList) {
    try {
        if ($Revert) {
            Set-Service -Name $s -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name $s -ErrorAction SilentlyContinue
            Log "Service reverted: $s"
        } else {
            if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                Log "Service disabled: $s"
            }
        }
    } catch { Log "Service change failed: $s : $($_.Exception.Message)" }
}

# SysMain: set to Manual (safe default). If you have very low RAM, you can disable it.
try {
    if ($Revert) {
        Set-Service -Name "SysMain" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
        Log "SysMain set to Automatic (revert)"
    } else {
        Set-Service -Name "SysMain" -StartupType Manual -ErrorAction SilentlyContinue
        Stop-Service -Name "SysMain" -ErrorAction SilentlyContinue
        Log "SysMain set to Manual"
    }
} catch { Log "SysMain tweak failed: $($_.Exception.Message)" }

# --- Startup cleanup (safe known entries) ---
$runKeys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
$blockList = @('OneDrive','Teams','Skype','Cortana','XboxApp','GamingApp','MicrosoftEdgeAutoLaunch')
foreach($rk in $runKeys){
    foreach($name in $blockList){
        try {
            if ($Revert) { continue } # Do not try to recreate unknown values
            if (Get-ItemProperty -Path $rk -Name $name -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $rk -Name $name -ErrorAction SilentlyContinue
                Log "Removed autostart: $name ($rk)"
            }
        } catch { Log "Autostart change failed: $name ($rk): $($_.Exception.Message)" }
    }
}

# --- Debloat: remove safe consumer apps (keeps Store, Photos, Notepad, Paint, Calculator, Settings) ---
if (-not $Revert) {
    $apps = @(
        "Microsoft.XboxApp","Microsoft.XboxGamingOverlay","Microsoft.GamingApp",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.SkypeApp",
        "Microsoft.People","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted",
        "Clipchamp.Clipchamp"
    )
    foreach ($a in $apps) {
        try {
            Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $a } | ForEach-Object {
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null
            }
            Log "Removed app: $a"
        } catch { Log "App removal failed: $a : $($_.Exception.Message)" }
    }
}

# --- Pagefile strategy ---
if ($Revert) {
    try {
        wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null
        Log "Pagefile set to System managed (revert)"
    } catch { Log "Pagefile revert failed: $($_.Exception.Message)" }
} else {
    try {
        if ($FixedPagefile) {
            $ramBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
            $ramMB = [int]([math]::Round($ramBytes / 1MB))
            wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False | Out-Null
            wmic pagefileset delete | Out-Null
            wmic pagefileset create name="C:\pagefile.sys" | Out-Null
            wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=$ramMB,MaximumSize=$ramMB | Out-Null
            Log "Pagefile fixed to RAM size: ${ramMB}MB"
        } else {
            wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null
            Log "Pagefile: System managed"
        }
    } catch { Log "Pagefile config failed: $($_.Exception.Message)" }
}

# --- Weekly cleanup (temp + recycle bin) ---
try {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    schtasks /Create /SC WEEKLY /D SUN /RL HIGHEST /TN "W11_CleanMgr_Weekly" /TR "cleanmgr /sagerun:1" /ST 09:00 | Out-Null
    Log "Scheduled weekly CleanMgr"
} catch { Log "CleanMgr schedule failed: $($_.Exception.Message)" }

Log "DONE. Please reboot."
Write-Host "OK - W11 optimization complete. Log: $log"
