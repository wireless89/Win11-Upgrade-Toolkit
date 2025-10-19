# Win10-Secure-Mode.ps1  (ASCII only)
# Windows 10 hardening without ESU. Balanced by default, Strict optional.
# Log file: C:\W11Secure\secure.log

param(
  [ValidateSet("Balanced","Strict")] [string]$Mode = "Balanced",
  [switch]$EnableCFA,                       # enable Controlled Folder Access (can block apps)
  [ValidateSet("None","Quad9","Cloudflare")] [string]$SystemDNS = "None"
)

$ErrorActionPreference = "SilentlyContinue"

# --- admin check ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Please run as Administrator." -ForegroundColor Yellow
  exit 1
}

# --- logging ---
$LogDir = "C:\W11Secure"
$null = New-Item -ItemType Directory -Path $LogDir -Force
$Log = Join-Path $LogDir "secure.log"
function Log($m){ ("{0}  {1}" -f (Get-Date).ToString("u"), $m) | Out-File $Log -Append -Encoding ascii; Write-Host $m }

# --- step executor ---
function Invoke-Step([string]$Desc, [scriptblock]$Action, [ValidateSet('Warn','Fatal','Skip')]$Severity='Warn'){
  Log ">> $Desc"
  if ($Severity -eq 'Skip') { Log "   SKIP"; return }
  try { & $Action; Log "   OK" } catch { if ($Severity -eq 'Fatal') { Log "   ERR: $($_.Exception.Message)"; throw } else { Log "   WARN: $($_.Exception.Message)" } }
}
function StepWarn { param($d,$a) Invoke-Step $d $a 'Warn' }
function StepFatal{ param($d,$a) Invoke-Step $d $a 'Fatal' }
function StepSkip { param($d)    Invoke-Step $d { } 'Skip' }

Log "=== Win10 Secure Mode start  Mode=$Mode  CFA=$EnableCFA  DNS=$SystemDNS ==="

# 1) Firewall enable all profiles
StepFatal "Enable Windows Firewall for Domain, Private, Public" {
  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

# 2) Defender baseline
StepWarn "Defender: realtime, cloud, PUA on" {
  Set-MpPreference -DisableRealtimeMonitoring $false
  Set-MpPreference -MAPSReporting 2
  Set-MpPreference -SubmitSamplesConsent 1
  Set-MpPreference -PUAProtection 1
  Set-MpPreference -CloudBlockLevel 2
  Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
}

# 3) ASR rules (Attack Surface Reduction)
# Balanced: some Audit (Warn), Strict: all Block.
$asrIds = @(
  "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Office child process
  "3B576869-A4EC-4529-8536-B80A7769E899", # Office code injection
  "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Office macro Win32 API
  "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", # Executable from email
  "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Obfuscated scripts
  "D3E037E1-3EB8-44C8-A917-57927947596D", # Credential stealing
  "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", # Unsigned/LOLBAS ps/wmi
  "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"  # LSASS credential dump
)
# Actions: 1=Block, 2=Audit, 0=Off
$actBalanced = @(2,2,2,1,2,1,2,1)
$actStrict   = @(1,1,1,1,1,1,1,1)

StepWarn "Apply Defender ASR rules ($Mode)" {
  $acts = if ($Mode -eq "Strict") { $actStrict } else { $actBalanced }
  Set-MpPreference -AttackSurfaceReductionRules_Ids $asrIds -AttackSurfaceReductionRules_Actions $acts
}

# 4) SmartScreen (Explorer + Edge)
StepWarn "Enable SmartScreen and PUA in Edge" {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Warn" -PropertyType String -Force | Out-Null
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
}

# 5) UAC sane defaults
StepWarn "Set UAC to secure defaults" {
  New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -PropertyType DWord -Force | Out-Null
}

# 6) Disable SMBv1 (legacy)
StepWarn "Disable SMBv1 if present" {
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
}

# 7) Optional: Controlled Folder Access
if ($EnableCFA) {
  StepWarn "Enable Controlled Folder Access (may block apps)" {
    Set-MpPreference -EnableControlledFolderAccess Enabled
    # To allow specific apps: Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Path\App.exe"
  }
} else {
  StepSkip "CFA not enabled (use -EnableCFA to enable)"
}

# 8) Optional: system DNS hardening
if ($SystemDNS -ne "None") {
  $servers = @()
  if ($SystemDNS -eq "Quad9")      { $servers = @("9.9.9.9","149.112.112.112") }
  if ($SystemDNS -eq "Cloudflare") { $servers = @("1.1.1.1","1.0.0.1") }
  StepWarn "Set system DNS to $SystemDNS -> $($servers -join ', ')" {
    Get-DnsClient | Where-Object { $_.InterfaceOperationalStatus -eq "Up" } | ForEach-Object {
      Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $servers
    }
  }
} else {
  StepSkip "DNS unchanged"
}

# 9) Update Defender signatures once
StepWarn "Update Defender signatures" {
  Update-MpSignature | Out-Null
}

Log "=== Win10 Secure Mode done. Please reboot. Log: $Log ==="
Write-Host "OK - Win10 Secure Mode complete. Log: $Log"