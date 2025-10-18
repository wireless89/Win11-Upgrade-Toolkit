# W11-Trim-Complete-V2.ps1  (ASCII only)
# Profiles: Balanced (safe default), Pro (cleaner), Aggressive (most clean)
# Reversible where sensible; writes detailed log to C:\W11Optimize\trim.log

param(
  [ValidateSet("Balanced","Pro","Aggressive")] [string]$Mode = "Balanced",
  [switch]$Revert,
  [switch]$KeepHibernate,
  [switch]$DryRun,
  [switch]$SkipAppRemoval
)

$ErrorActionPreference = "SilentlyContinue"
$LogDir = "C:\W11Optimize"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$Log = Join-Path $LogDir "trim.log"
function Log($m){ ("{0}  {1}" -f (Get-Date).ToString("u"), $m) | Out-File $Log -Append -Encoding ascii; Write-Host $m }

Log "=== W11-Trim-V2 start  Mode=$Mode  Revert=$Revert  DryRun=$DryRun ==="

function Do($desc,[scriptblock]$sb){
  Log ">> $desc"
  if ($DryRun){ Log "   (dry-run) skipped"; return }
  try { & $sb; Log "   OK" } catch { Log "   WARN: $($_.Exception.Message)" }
}

# 0) Restore point (best effort)
Do "Create system restore point (best effort)" { Checkpoint-Computer -Description "W11-Trim-V2 ($Mode)" -RestorePointType "MODIFY_SETTINGS" }

# 1) Power + Hibernation
if ($Revert){
  Do "Enable Hibernate" { powercfg /h on | Out-Null }
  Do "Set power plan Balanced" { powercfg /setactive SCHEME_BALANCED | Out-Null }
} else {
  if (-not $KeepHibernate) { Do "Disable Hibernate" { powercfg /h off | Out-Null } }
  Do "Set power plan High Performance" { powercfg /setactive SCHEME_MIN | Out-Null }
}

# 2) SSD / TRIM
Do "Ensure TRIM" { fsutil behavior set DisableDeleteNotify 0 | Out-Null }

# 3) Telemetry & privacy (policies + tasks)
if ($Revert){
  Do "Remove telemetry policy" { Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Recurse -Force -ErrorAction SilentlyContinue }
  Do "Re-enable CEIP tasks" {
    schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /ENABLE | Out-Null
    schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /ENABLE | Out-Null
  }
} else {
  Do "Minimize telemetry (AllowTelemetry=0)" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force | Out-Null
  }
  Do "Disable CEIP tasks" {
    schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE | Out-Null
    schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE | Out-Null
  }
}

# 4) Services (conservative; Aggressive disables more)
function SetSvc($name,$mode){
  if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    if ($mode -eq "Disable") {
      Stop-Service $name -ErrorAction SilentlyContinue
      Set-Service $name -StartupType Disabled -ErrorAction SilentlyContinue
    } elseif ($mode -eq "Manual") {
      Set-Service $name -StartupType Manual -ErrorAction SilentlyContinue
    } elseif ($mode -eq "Auto") {
      Set-Service $name -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service $name -ErrorAction SilentlyContinue
    }
  }
}

if ($Revert){
  Do "Revert services (DiagTrack, dmwappush, RemoteRegistry Manual; SysMain Auto)" {
    SetSvc "DiagTrack" "Manual"
    SetSvc "dmwappushservice" "Manual"
    SetSvc "RemoteRegistry" "Manual"
    SetSvc "SysMain" "Auto"
  }
} else {
  Do "Tune services (disable some, SysMain Manual)" {
    SetSvc "DiagTrack" "Disable"
    SetSvc "dmwappushservice" "Disable"
    SetSvc "RemoteRegistry" "Disable"
    SetSvc "SysMain" "Manual"
    Stop-Service "SysMain" -ErrorAction SilentlyContinue
    if ($Mode -eq "Aggressive") {
      SetSvc "Fax" "Disable"
      SetSvc "RetailDemo" "Disable"
    }
  }
}

# 5) Edge/Start/Search tweaks
if ($Revert){
  Do "Revert Edge/Search policies" {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
  }
} else {
  Do "Disable Edge StartupBoost, disable web search" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "DisableWebSearch" -Value 1 -PropertyType DWord -Force | Out-Null
  }
}

# 6) Debloat apps (safe list; Pro/Aggressive extend)
if (-not $SkipAppRemoval -and -not $Revert) {
  $apps = @(
    "Microsoft.XboxApp","Microsoft.XboxGamingOverlay","Microsoft.GamingApp",
    "Microsoft.MicrosoftSolitaireCollection","Microsoft.SkypeApp",
    "Microsoft.People","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted",
    "Clipchamp.Clipchamp","Microsoft.Todos","Microsoft.MSPaintPreview"
  )
  if ($Mode -eq "Pro" -or $Mode -eq "Aggressive") {
    $apps += @("MicrosoftTeams","Microsoft.YourPhone")  # Widgets/Teams consumer cruft
  }
  if ($Mode -eq "Aggressive") {
    $apps += @("Microsoft.News","Microsoft.MicrosoftOfficeHub","Microsoft.ZuneMusic","Microsoft.ZuneVideo")
  }
  Do "Remove provisioned + user apps (non-critical)" {
    foreach ($a in $apps) {
      Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
      Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $a } | ForEach-Object {
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null
      }
    }
  }
}

# 7) Autostarts (safe)
if (-not $Revert) {
  Do "Autostarts: remove common noise" {
    $runHKLM = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    $runHKCU = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    foreach ($rk in @($runHKLM,$runHKCU)) {
      foreach ($name in @('OneDrive','Teams','Skype','Cortana','GamingApp','MicrosoftEdgeAutoLaunch')) {
        if (Get-ItemProperty -Path $rk -Name $name -ErrorAction SilentlyContinue) {
          Remove-ItemProperty -Path $rk -Name $name -ErrorAction SilentlyContinue
        }
      }
    }
  }
}

# 8) Pagefile strategy (safe by default)
if ($Revert){
  Do "Pagefile revert to System managed" { wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null }
} else {
  Do "Pagefile System managed (safe default)" { wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null }
}

# 9) Weekly cleanup task
if ($Revert){
  Do "Remove weekly CleanMgr task" { schtasks /Delete /TN "W11_CleanMgr_Weekly" /F | Out-Null }
} else {
  Do "Create weekly CleanMgr task (Sun 09:00)" {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    schtasks /Create /SC WEEKLY /D SUN /RL HIGHEST /TN "W11_CleanMgr_Weekly" /TR "cleanmgr /sagerun:1" /ST 09:00 | Out-Null
  }
}

Log "=== Done. Reboot recommended. Log: $Log ==="
Write-Host "OK - Trim V2 complete ($Mode). Log: $Log"