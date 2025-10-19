# Win10-Optimize-MaxClean.ps1  (ASCII only)
# Variant C1: strong but safe. Focus on speed and low background load.
# Creates log: C:\W10Optimize\maxclean.log
# Usage:
#   powershell -noprofile -exec bypass -file Win10-Optimize-MaxClean.ps1
#   powershell -noprofile -exec bypass -file Win10-Optimize-MaxClean.ps1 -Revert

param([switch]$Revert)

$ErrorActionPreference = "SilentlyContinue"

# --- paths & log ---
$Base = "C:\W10Optimize"
$null = New-Item -ItemType Directory -Path $Base -Force
$Log  = Join-Path $Base "maxclean.log"
function Log($m){ ("{0}  {1}" -f (Get-Date).ToString("u"),$m) | Out-File $Log -Append -Encoding ascii; Write-Host $m }

# --- step helpers (no 'do' keyword) ---
function Step([string]$desc,[scriptblock]$act,[ValidateSet('Warn','Fatal','Skip')]$sev='Warn'){
  Log ">> $desc"
  if($sev -eq 'Skip'){ Log "   SKIP"; return }
  try{ & $act; Log "   OK" }catch{ if($sev -eq 'Fatal'){ Log "   ERR: $($_.Exception.Message)"; throw } else { Log "   WARN: $($_.Exception.Message)" } }
}
function StepWarn { param($d,$a) Step $d $a 'Warn' }
function StepFatal{ param($d,$a) Step $d $a 'Fatal' }
function StepSkip { param($d)    Step $d { } 'Skip' }

# --- svc helper ---
function SetSvc($name,$mode){
  $s = Get-Service -Name $name -ErrorAction SilentlyContinue
  if(!$s){ return }
  switch($mode){
    "Disable" { Stop-Service $name -ErrorAction SilentlyContinue; Set-Service $name -StartupType Disabled  -ErrorAction SilentlyContinue }
    "Manual"  { Set-Service $name -StartupType Manual    -ErrorAction SilentlyContinue }
    "Auto"    { Set-Service $name -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service $name -ErrorAction SilentlyContinue }
  }
}

Log "=== Win10 Optimize MaxClean start  Revert=$Revert ==="

# 0) restore point (best effort)
if($Revert){
  StepWarn "No restore point on revert (skipped)" { }
}else{
  StepWarn "Create system restore point" { Checkpoint-Computer -Description "W10-MaxClean" -RestorePointType MODIFY_SETTINGS }
}

# 1) Services (C1: strong but safe)
$svcDisable = @(
  "DiagTrack",           # Connected User Experiences and Telemetry
  "dmwappushservice",    # WPN service (telemetry channel)
  "RemoteRegistry",
  "Fax",
  "RetailDemo",
  "XblAuthManager","XblGameSave","XboxGipSvc","XboxNetApiSvc",
  "MapsBroker",          # offline maps
  "TabletInputService"   # handwriting/touch keyboard (keeps classic keyboard)
)
$svcManual = @("SysMain")   # was Superfetch; Manual to calm disk
if($Revert){
  StepWarn "Revert services (set Manual/Auto)" {
    foreach($n in $svcDisable){ SetSvc $n "Manual" }
    foreach($n in $svcManual ){ SetSvc $n "Auto" }
  }
}else{
  StepWarn "Disable non-essential services" {
    foreach($n in $svcDisable){ SetSvc $n "Disable" }
    foreach($n in $svcManual ){ SetSvc $n "Manual"  }
  }
}

# 2) Scheduled Tasks (disable, not delete)
$tasks = @(
  "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
  "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
  "\Microsoft\Windows\Autochk\Proxy",
  "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
  "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
  "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
  "\Microsoft\Windows\Feedback\Siuf\DmClient",
  "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
  "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
  "\Microsoft\Windows\PushToInstall\Registration",
  "\Microsoft\Windows\Shell\FamilySafetyMonitor",
  "\Microsoft\Windows\Shell\FamilySafetyRefresh",
  "\Microsoft\Windows\Shell\FamilySafetyUpload",
  "\Microsoft\Windows\Maps\MapsUpdateTask"
)
if($Revert){
  StepWarn "Enable scheduled tasks" { foreach($t in $tasks){ schtasks /Change /TN $t /ENABLE | Out-Null } }
}else{
  StepWarn "Disable telemetry/CEIP tasks" { foreach($t in $tasks){ schtasks /Change /TN $t /DISABLE | Out-Null } }
}

# 3) Edge background + ads/offers
if($Revert){
  StepWarn "Revert Edge/ads policies" {
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Recurse -Force -ErrorAction SilentlyContinue
  }
}else{
  StepWarn "Turn off Edge startup boost/background mode" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled"   -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "TabPreloaderEnabled"    -Value 0 -PropertyType DWord -Force | Out-Null
  }
  StepWarn "Disable Windows suggestions/ads (ContentDeliveryManager)" {
    $cdm = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    New-Item -Path $cdm -Force | Out-Null
    $names = @(
      "ContentDeliveryAllowed","OemPreInstalledAppsEnabled","PreInstalledAppsEnabled","PreInstalledAppsEverEnabled",
      "SilentInstalledAppsEnabled","SystemPaneSuggestionsEnabled","SubscribedContent-310093Enabled","SubscribedContent-338387Enabled",
      "SubscribedContent-338388Enabled","SubscribedContent-338389Enabled","SubscribedContent-353694Enabled","SoftLandingEnabled"
    )
    foreach($n in $names){ New-ItemProperty -Path $cdm -Name $n -Value 0 -PropertyType DWord -Force | Out-Null }
  }
}

# 4) Explorer/GUI speed tweaks
if($Revert){
  StepWarn "Revert animations/transparency" {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Animations" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MinAnimate" -Value 1 -PropertyType String -Force | Out-Null
  }
}else{
  StepWarn "Disable UI animations and transparency" {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Animations" -Value 0 -PropertyType DWord -Force | Out-Null
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MinAnimate" -Value 0 -PropertyType String -Force | Out-Null
  }
}

# 5) Autostarts (remove common noise)
if($Revert){
  StepSkip "Autostart revert skipped (unknown original values)"
}else{
  StepWarn "Clean common Run entries (HKCU/HKLM)" {
    foreach($rk in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')){
      foreach($n in @('OneDrive','Skype','Teams','Cortana','GamingApp','MicrosoftEdgeAutoLaunch')){
        if(Get-ItemProperty -Path $rk -Name $n -ErrorAction SilentlyContinue){ Remove-ItemProperty -Path $rk -Name $n -ErrorAction SilentlyContinue }
      }
    }
  }
}

# 6) Storage/IO tweaks
if($Revert){
  StepWarn "SysMain back to Auto" { SetSvc "SysMain" "Auto" }
}else{
  StepWarn "Ensure TRIM" { fsutil behavior set DisableDeleteNotify 0 | Out-Null }
  StepWarn "Cleanmgr run (temp + recycle)" {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin"   /v StateFlags0001 /t REG_DWORD /d 2 /f | Out-Null
    Start-Process -FilePath cleanmgr.exe -ArgumentList "/sagerun:1" -WindowStyle Hidden
  }
}

# 7) Windows Store auto updates off (saves IO)
if($Revert){
  StepWarn "Revert Store policy" { Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Recurse -Force -ErrorAction SilentlyContinue }
}else{
  StepWarn "Disable Store auto updates" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -PropertyType DWord -Force | Out-Null
  }
}

# 8) Error reporting off (less background chatter)
if($Revert){
  StepWarn "Revert Windows Error Reporting" { Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Recurse -Force -ErrorAction SilentlyContinue }
}else{
  StepWarn "Disable Windows Error Reporting UI" {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontShowUI" -Value 1 -PropertyType DWord -Force | Out-Null
  }
}

# 9) Defender keep (security), only update signatures now
if($Revert){
  StepSkip "Defender left untouched on revert"
}else{
  StepWarn "Update Defender signatures once" { Update-MpSignature | Out-Null }
}

Log "=== Done. Reboot recommended. Log: $Log ==="
Write-Host "OK - MaxClean complete. Log: $Log"
