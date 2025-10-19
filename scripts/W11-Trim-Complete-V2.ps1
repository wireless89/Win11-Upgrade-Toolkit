# W11-Trim-Complete-V2.ps1  (ASCII only)
# Profiles: Balanced (safe), Pro (cleaner), Aggressive (most clean)
# Error model: DoWarn (log & continue), DoFatal (log & abort), DoSkip (log skip)
# Log: C:\W11Optimize\trim.log

param(
  [ValidateSet("Balanced","Pro","Aggressive")] [string]$Mode = "Pro",
  [switch]$Revert,
  [switch]$KeepHibernate,
  [switch]$DryRun,
  [switch]$SkipAppRemoval
)

$ErrorActionPreference = "SilentlyContinue"

# --- Paths & Log ---
$LogDir = "C:\W11Optimize"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$Log = Join-Path $LogDir "trim.log"
function Log($m){ ("{0}  {1}" -f (Get-Date).ToString("u"), $m) | Out-File $Log -Append -Encoding ascii; Write-Host $m }

# --- Unified step executor ---
function Invoke-Step {
  param(
    [Parameter(Mandatory=$true)][string]$Desc,
    [Parameter(Mandatory=$true)][scriptblock]$Action,
    [ValidateSet('Warn','Fatal','Skip')][string]$Severity = 'Warn'
  )
  Log ">> $Desc"
  if ($Severity -eq 'Skip') { Log "   SKIP"; return }
  if ($DryRun) { Log "   (dry-run) skipped"; return }
  try {
    & $Action
    Log "   OK"
  } catch {
    $msg = $_.Exception.Message
    if ($Severity -eq 'Fatal') { Log "   ERR: $msg"; throw "Fatal step failed: $Desc" }
    else { Log "   WARN: $msg" }
  }
}
function DoWarn  { param($d,$a) Invoke-Step -Desc $d -Action $a -Severity 'Warn'  }
function DoFatal { param($d,$a) Invoke-Step -Desc $d -Action $a -Severity 'Fatal' }
function DoSkip  { param($d)    Invoke-Step -Desc $d -Action { } -Severity 'Skip' }
# Back-compat alias
function Do      { param($d,$a) Invoke-Step -Desc $d -Action $a -Severity 'Warn'  }

# --- Service helper ---
function SetSvc($name,$mode){
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if (!$svc) { return }
  switch ($mode) {
    "Disable" { Stop-Service $name -ErrorAction SilentlyContinue; Set-Service $name -StartupType Disabled -ErrorAction SilentlyContinue }
    "Manual"  { Set-Service $name -StartupType Manual   -ErrorAction SilentlyContinue }
    "Auto"    { Set-Service $name -StartupType Automatic-ErrorAction SilentlyContinue; Start-Service $name -ErrorAction SilentlyContinue }
  }
}

# --- Header ---
Log "=== W11-Trim-V2 start  Mode=$Mode  Revert=$Revert  DryRun=$DryRun  SkipAppRemoval=$SkipAppRemoval ==="

# 0) Restore point (best effort, Warn)
DoWarn "Create system restore point" {
  Checkpoint-Computer -Description "W11-Trim-V2 ($Mode)" -RestorePointType "MODIFY_SETTINGS"
}

# 1) Power & Hibernate
if ($Revert) {
  DoWarn "Enable Hibernate" { powercfg /h on | Out-Null }
  DoWarn "Set power plan Balanced" { powercfg /setactive SCHEME_BALANCED | Out-Null }
} else {
  if ($KeepHibernate) { DoSkip "Hibernate kept by user choice" }
  else { DoWarn "Disable Hibernate" { powercfg /h off | Out-Null } }
  DoWarn "Set power plan High performance" { powercfg /setactive SCHEME_MIN | Out-Null }
}

# 2) SSD / TRIM (Warn or Fatal – we keep Warn to avoid aborting on exotic systems)
DoWarn "Ensure TRIM (DisableDeleteNotify=0)" { fsutil behavior set DisableDeleteNotify 0 | Out-Null }

# 3) Telemetry & privacy
if ($Revert) {
  DoWarn "Remove telemetry policy (HKLM Policies DataCollection)" {
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Recurse -Force -ErrorAction SilentlyContinue
  }
  DoWarn "Enable CEIP tasks" {
    schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /ENABLE | Out-Null
    schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /ENABLE | Out-Null
  }
} else {
  DoWarn "Minimize telemetry (AllowTelemetry=0)" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force | Out-Null
  }
  DoWarn "Disable CEIP tasks" {
    schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE | Out-Null
    schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE | Out-Null
  }
}

# 4) Edge/Search tweaks
if ($Revert) {
  DoWarn "Revert Edge/Search policies" {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
  }
} else {
  DoWarn "Disable Edge StartupBoost, disable web search" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "DisableWebSearch" -Value 1 -PropertyType DWord -Force | Out-Null
  }
}

# 5) Services (conservative; Aggressive disables more)
if ($Revert) {
  DoWarn "Revert services (DiagTrack/dmwappush/RemoteRegistry Manual; SysMain Auto)" {
    SetSvc "DiagTrack" "Manual"
    SetSvc "dmwappushservice" "Manual"
    SetSvc "RemoteRegistry" "Manual"
    SetSvc "SysMain" "Auto"
  }
} else {
  DoWarn "Tune services (disable DiagTrack/dmwappush/RemoteRegistry; SysMain Manual)" {
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

# 6) Debloat apps
if ($Revert) {
  DoSkip "App removal revert not performed (non-trivial to restore removed provisioned packages)"
} elseif (-not $SkipAppRemoval) {
  $apps = @(
    "Microsoft.XboxApp","Microsoft.XboxGamingOverlay","Microsoft.GamingApp",
    "Microsoft.MicrosoftSolitaireCollection","Microsoft.SkypeApp",
    "Microsoft.People","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted",
    "Clipchamp.Clipchamp","Microsoft.Todos","Microsoft.MSPaintPreview"
  )
  if ($Mode -eq "Pro" -or $Mode -eq "Aggressive") {
    $apps += @("MicrosoftTeams","Microsoft.YourPhone")
  }
  if ($Mode -eq "Aggressive") {
    $apps += @("Microsoft.News","Microsoft.MicrosoftOfficeHub","Microsoft.ZuneMusic","Microsoft.ZuneVideo")
  }
  DoWarn "Remove provisioned + user apps (non-critical set)" {
    foreach ($a in $apps) {
      Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
      Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $a } | ForEach-Object {
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null
      }
    }
  }
} else {
  DoSkip "SkipAppRemoval requested"
}

# 7) Autostarts
if ($Revert) {
  DoSkip "Autostart revert not performed (values unknown)"
} else {
  DoWarn "Autostarts: remove common noise (HKLM/HKCU Run)" {
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

# 8) Pagefile strategy (safe default)
if ($Revert) {
  DoWarn "Pagefile revert to System managed" { wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null }
} else {
  DoWarn "Pagefile System managed (safe default)" { wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null }
}

# 9) Weekly cleanup task
if ($Revert) {
  DoWarn "Remove weekly CleanMgr task" { schtasks /Delete /TN "W11_CleanMgr_Weekly" /F | Out-Null }
} else {
  DoWarn "Create weekly CleanMgr task (Sun 09:00)" {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    schtasks /Create /SC WEEKLY /D SUN /RL HIGHEST /TN "W11_CleanMgr_Weekly" /TR "cleanmgr /sagerun:1" /ST 09:00 | Out-Null
  }
}

# 10) Summary
Log "=== Done. Reboot recommended. Log: $Log ==="
Write-Host "OK - Trim V2 complete ($Mode). Log: $Log"