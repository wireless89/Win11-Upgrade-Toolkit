# Win10-Secure-Mode.ps1  — Windows 10 Hardening ohne ESU
# Default: konservativ (kaum False Positives). Optional: -Mode Strict (schärfer)
# Log: C:\W11Secure\secure.log

param(
  [ValidateSet("Balanced","Strict")] [string]$Mode = "Balanced",
  [switch]$EnableCFA,       # Controlled Folder Access aktivieren (kann Apps blocken)
  [ValidateSet("None","Quad9","Cloudflare")] [string]$SystemDNS = "None"
)

$ErrorActionPreference = "SilentlyContinue"

# --- Admin-Check ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Bitte als Administrator starten." -ForegroundColor Yellow
  exit 1
}

# --- Logging ---
$LogDir = "C:\W11Secure"
$null = New-Item -ItemType Directory -Path $LogDir -Force
$Log = Join-Path $LogDir "secure.log"
function Log($m){ ("{0}  {1}" -f (Get-Date).ToString("u"), $m) | Out-File $Log -Append -Encoding ascii; Write-Host $m }

# --- Step-Executor (stabil, mit Abbruch bei Fatal) ---
function Invoke-Step([string]$Desc, [scriptblock]$Action, [ValidateSet('Warn','Fatal','Skip')]$Severity='Warn'){
  Log ">> $Desc"
  if ($Severity -eq 'Skip') { Log "   SKIP"; return }
  try { & $Action; Log "   OK" } catch { if ($Severity -eq 'Fatal'){ Log "   ERR: $($_.Exception.Message)"; throw } else { Log "   WARN: $($_.Exception.Message)" } }
}
function StepWarn { param($d,$a) Invoke-Step $d $a 'Warn' }
function StepFatal{ param($d,$a) Invoke-Step $d $a 'Fatal' }
function StepSkip { param($d)    Invoke-Step $d { } 'Skip' }

Log "=== Win10 Secure Mode start  Mode=$Mode  CFA=$EnableCFA  DNS=$SystemDNS ==="

# 1) Firewall alle Profile an
StepFatal "Windows-Firewall aktivieren (alle Profile)" {
  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

# 2) Defender Baseline
StepWarn "Defender: Cloud/Realtime/PUA aktivieren" {
  Set-MpPreference -DisableRealtimeMonitoring $false
  Set-MpPreference -MAPSReporting 2                  # advanced MAPS
  Set-MpPreference -SubmitSamplesConsent 1           # automatisch sichere Samples
  Set-MpPreference -PUAProtection 1                  # PUA/PUP blockieren
  Set-MpPreference -CloudBlockLevel 2                # hoch
  Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
}

# 3) Defender ASR (Attack Surface Reduction) – sicherer Satz
# Hinweis: Einige Regeln stehen im Audit-Modus bei "Balanced", als Block bei "Strict".
$asrIds = @{
  # Office-Missbrauch
  "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block office child";         # Office startet Kindprozesse
  "3B576869-A4EC-4529-8536-B80A7769E899" = "Block office inject code";   # Office Code-Injektion
  "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block office macro win32";   # Win32-API aus Makros
  "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block executable email";     # exe aus Mail
  # Script/Obfuscation
  "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block obfuscated scripts";
  "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block credential stealing";
  # WMI/PS living-off-the-land
  "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block unsigned ps/wmi";      # unsignierte/verdächtige Scripts
  # LSASS-Schutz (Memory)
  "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block LSASS credential dump"
}
$ids   = $asrIds.Keys
$modeBalanced = @( "Warn","Warn","Warn","Block","Warn","Block","Warn","Block" ) # passende Reihenfolge
$modeStrict   = @( "Block","Block","Block","Block","Block","Block","Block","Block" )

StepWarn "ASR-Regeln anwenden ($Mode)" {
  $actions = if ($Mode -eq "Strict") { $modeStrict } else { $modeBalanced }
  # Map Actions -> 1=Block, 2=Audit(Warn), 0=Off
  $idsArr = @()
  $actArr = @()
  for($i=0;$i -lt $ids.Count;$i++){
    $idsArr += $ids[$i]
    $actArr += ($(if ($actions[$i] -eq "Block") { 1 } else { 2 }))
  }
  Set-MpPreference -AttackSurfaceReductionRules_Ids $idsArr -AttackSurfaceReductionRules_Actions $actArr
}

# 4) SmartScreen (Explorer + Edge Policies)
StepWarn "SmartScreen aktivieren (Explorer + Edge PUA)" {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Warn" -PropertyType String -Force | Out-Null
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
}

# 5) UAC sinnvoll hoch (keine Abschaltung)
StepWarn "UAC (Benutzerkontensteuerung) auf sicher setzen" {
  New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -PropertyType DWord -Force | Out-Null
}

# 6) SMBv1 deaktivieren (Alt-Protokoll, oft Angriffsvektor)
StepWarn "SMBv1 deaktivieren (falls vorhanden)" {
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
}

# 7) Optional: Controlled Folder Access (Exploit Guard)
if ($EnableCFA) {
  StepWarn "Controlled Folder Access aktivieren (kann Apps blockieren)" {
    Set-MpPreference -EnableControlledFolderAccess Enabled
    # Standardordner sind geschützt; Whitelist bei Bedarf:
    # Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\DeinProgramm\app.exe"
  }
} else {
  StepSkip "Controlled Folder Access nicht aktiviert (Parameter -EnableCFA nutzen)"
}

# 8) Optional: System-DNS härten
if ($SystemDNS -ne "None") {
  $servers = @()
  if ($SystemDNS -eq "Quad9")     { $servers = @("9.9.9.9","149.112.112.112") }
  if ($SystemDNS -eq "Cloudflare"){ $servers = @("1.1.1.1","1.0.0.1") }
  StepWarn "DNS-Server systemweit setzen: $SystemDNS -> $($servers -join ', ')" {
    Get-DnsClient | Where-Object {$_.InterfaceOperationalStatus -eq "Up"} | ForEach-Object {
      Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $servers
    }
  }
} else {
  StepSkip "DNS unverändert"
}

# 9) Updates/Einstellungen beibehalten (Win10 bekommt bis 10/2025 Security-Fixes)
StepWarn "Windows Update: Defender Signaturen sofort ziehen (einmalig)" {
  Update-MpSignature | Out-Null
}

Log "=== Secure Mode done. Bitte neu starten. Log: $Log ==="
Write-Host "OK – Win10 Secure Mode abgeschlossen. Log: $Log"
