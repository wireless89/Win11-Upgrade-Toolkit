<#
 PreUpgrade-W11-Prep-ASCII.ps1
 Purpose: Safe preparation for Win10 -> Win11 upgrade on older hardware.
 Notes:
 - ASCII-only output (no umlauts or special characters) to avoid encoding issues.
 - Works on Windows PowerShell 5.x. Run as Administrator.
 - Report log: C:\W11Prep\report.txt
#>

param(
  [switch]$SetBypass = $true,
  [switch]$NoSetBypass,
  [switch]$InstallPcHealthCheck,
  [string]$IsoPath,
  [string]$Sha256,
  [switch]$StartSetup,
  [switch]$Mbr2GptConvert,
  [switch]$Force
)

if ($NoSetBypass) { $SetBypass = $false }
$ErrorActionPreference = 'SilentlyContinue'

# --- Setup & Report ---
$prepRoot = 'C:\W11Prep'
if (-not (Test-Path $prepRoot)) { New-Item -ItemType Directory -Path $prepRoot | Out-Null }
$report = Join-Path $prepRoot 'report.txt'
function Rep($m){ $ts=(Get-Date).ToString('u'); "$ts  $m" | Out-File $report -Append -Encoding utf8; Write-Host $m }

"=== Windows 11 Pre-Upgrade Check: $(Get-Date) ===" | Out-File $report -Encoding utf8

# --- Admin check ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Please run this script as Administrator." -ForegroundColor Yellow
  exit 1
}

# --- System info ---
try { $os = Get-CimInstance Win32_OperatingSystem } catch {}
try { $cs = Get-CimInstance Win32_ComputerSystem } catch {}
try { $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 } catch {}

$arch = $env:PROCESSOR_ARCHITECTURE
$ramGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB),2)
$sysDrive = $os.SystemDrive
$freeGB = [math]::Round(((Get-PSDrive $sysDrive.TrimEnd('\')).Free/1GB),2)
$build = [System.Environment]::OSVersion.Version.Build
$edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID

Rep "OS: $($os.Caption) (Build $build), Edition: $edition, Arch: $arch"
Rep "CPU: $($cpu.Name)"
Rep "RAM: $ramGB GB"
Rep "System drive $sysDrive free: $freeGB GB"

# --- UEFI / Secure Boot ---
function Test-SecureBoot { try { return [bool](Confirm-SecureBootUEFI) } catch { return $false } }
try {
  $firmware = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control").PEFirmwareType
  $uefi = ($firmware -eq 2)
} catch { $uefi = $false }
$sb = Test-SecureBoot

Rep "Firmware: " + ($(if($uefi){"UEFI"}else{"Legacy BIOS"}))
Rep "Secure Boot: " + ($(if($sb){"ON"}else{"OFF or unsupported"}))

# --- System disk / partition style ---
$sysDisk = $null; $partStyle = $null; $diskNum = $null
try {
  $sysVolPart = Get-Partition -DriveLetter $sysDrive.TrimEnd(':','\')
  $sysDisk = ($sysVolPart | Get-Disk)
  $partStyle = $sysDisk.PartitionStyle
  $diskNum = $sysDisk.Number
  Rep "System disk number: $diskNum, Partition style: $partStyle"
} catch { Rep "Could not get system disk / partition style." }

# --- TPM ---
try {
  $tpm = Get-Tpm
  Rep ("TPM: Present={0}, Ready={1}" -f $tpm.TpmPresent, $tpm.TpmReady)
} catch { Rep "TPM not detected or disabled in firmware." }

# --- BitLocker ---
$bitlockerOn = $false
try {
  $bl = (Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction SilentlyContinue)
  if ($bl -and $bl.ProtectionStatus -eq 'On') { $bitlockerOn = $true }
  Rep "BitLocker (OS volume): " + ($(if($bitlockerOn){"ON"}else{"OFF"}))
} catch { Rep "BitLocker status not available." }

# --- Pending Reboot ---
function Test-PendingReboot {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
  )
  foreach ($p in $paths) {
    try {
      if (Test-Path $p) {
        if ($p -like "*Session Manager*") {
          if ((Get-ItemProperty $p -ErrorAction SilentlyContinue).PendingFileRenameOperations) { return $true }
        } else { return $true }
      }
    } catch {}
  }
  return $false
}
$pending = Test-PendingReboot
Rep "Pending reboot: " + ($(if($pending){"YES"}else{"no"}))

# --- Hints ---
if ($freeGB -lt 30) { Rep "WARNING: Less than 30 GB free on system drive." }
if (-not $uefi) { Rep "INFO: Legacy BIOS detected. UEFI required for Secure Boot." }
if (-not $sb) { Rep "INFO: Secure Boot is OFF. You can enable it after GPT + UEFI mode." }
try { if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) { Rep "INFO: No/disabled TPM - using bypass for upgrade is recommended." } } catch {}

# --- Bypass keys (optional) ---
if ($SetBypass) {
  try {
    New-Item -Path "HKLM:\SYSTEM\Setup\MoSetup" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\Setup\MoSetup" -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -PropertyType DWord -Force | Out-Null
    Rep "Bypass set: MoSetup\\AllowUpgradesWithUnsupportedTPMOrCPU = 1"
  } catch { Rep "Failed to set MoSetup bypass: $($_.Exception.Message)" }
  try {
    New-Item -Path "HKLM:\SYSTEM\Setup\LabConfig" -Force | Out-Null
    foreach ($n in 'BypassTPMCheck','BypassCPUCheck','BypassSecureBootCheck','BypassRAMCheck') {
      New-ItemProperty -Path "HKLM:\SYSTEM\Setup\LabConfig" -Name $n -Value 1 -PropertyType DWord -Force | Out-Null
    }
    Rep "Bypass set: LabConfig (TPM/CPU/SB/RAM) = 1"
  } catch { Rep "Failed to set LabConfig bypass: $($_.Exception.Message)" }
} else {
  Rep "Bypass keys skipped (NoSetBypass)."
}

# --- PC Health Check (optional) ---
if ($InstallPcHealthCheck) {
  try { winget install --id Microsoft.PCHealthCheck -e --source winget --accept-package-agreements --accept-source-agreements | Out-Null; Rep "PC Health Check installed." }
  catch { Rep "PC Health Check install failed (winget?)." }
}

# --- ISO hash & mount (optional) ---
$mountedLetter = $null
if ($IsoPath) {
  if (-not (Test-Path $IsoPath)) {
    Rep "ERROR: ISO not found: $IsoPath"
  } else {
    try {
      $hashObj = Get-FileHash -Path $IsoPath -Algorithm SHA256
      Rep "ISO SHA-256: $($hashObj.Hash)"
      if ($Sha256) {
        if ($hashObj.Hash.ToUpper() -eq $Sha256.ToUpper()) { Rep "Hash match: OK" }
        else { Rep "WARNING: Hash mismatch! Expected: $Sha256" }
      } else { Rep "Info: You can compare this hash with the Microsoft value." }
      $img = Mount-DiskImage -ImagePath $IsoPath -PassThru
      Start-Sleep -Seconds 2
      $vol = ($img | Get-Volume)
      $mountedLetter = $vol.DriveLetter + ":"
      Rep "ISO mounted as $mountedLetter"
    } catch { Rep "ISO handling failed: $($_.Exception.Message)" }
  }
}

# --- MBR -> GPT (optional) ---
function Can-Run-Mbr2Gpt {
  if ($build -lt 15063) { Rep "Convert in FullOS requires Build 15063+. Current: $build"; return $false }
  if (-not $sysDisk) { Rep "System disk not detected."; return $false }
  if ($partStyle -ne 'MBR') { Rep "Partition style already GPT - no conversion needed."; return $false }
  if ($pending) { Rep "Pending reboot detected - reboot before conversion."; return $false }
  return $true
}

if ($Mbr2GptConvert) {
  Rep "=== MBR -> GPT conversion requested ==="
  if (Can-Run-Mbr2Gpt) {
    if ($bitlockerOn) {
      try {
        Rep "BitLocker is ON - suspending protection for 1 reboot."
        Suspend-BitLocker -MountPoint $sysDrive -RebootCount 1 | Out-Null
        Rep "BitLocker protection suspended."
      } catch { Rep "WARNING: Could not suspend BitLocker." }
    }
    $mbr2gpt = "$env:SystemRoot\System32\mbr2gpt.exe"
    if (-not (Test-Path $mbr2gpt)) { Rep "ERROR: mbr2gpt.exe not found." }
    else {
      Rep "Validate: mbr2gpt /validate /disk:$diskNum /allowFullOS"
      $validate = Start-Process -FilePath $mbr2gpt -ArgumentList "/validate /disk:$diskNum /allowFullOS" -PassThru -Wait -NoNewWindow
      if ($validate.ExitCode -ne 0) {
        Rep "VALIDATE FAILED (ExitCode $($validate.ExitCode)). See C:\Windows\setupact.log / setuperr.log."
      } else {
        Rep "VALIDATE OK."
        $proceed = $false
        if ($Force) { $proceed = $true } else {
          Write-Host ""
          $ans = Read-Host "Proceed with conversion now? (Y/N)"
          if ($ans -match '^[YyJj]') { $proceed = $true }
        }
        if ($proceed) {
          Rep "Convert: mbr2gpt /convert /disk:$diskNum /allowFullOS"
          $convert = Start-Process -FilePath $mbr2gpt -ArgumentList "/convert /disk:$diskNum /allowFullOS" -PassThru -Wait -NoNewWindow
          if ($convert.ExitCode -eq 0) {
            Rep "CONVERSION SUCCESS."
            Rep "IMPORTANT: On next boot, enter firmware setup and set Boot Mode to UEFI."
            if ($sb -eq $false) { Rep "Note: After first UEFI boot you can enable Secure Boot in firmware." }
            Rep "Rebooting in 10 seconds..."
            Start-Sleep -Seconds 10
            Restart-Computer
            exit
          } else {
            Rep "CONVERSION FAILED (ExitCode $($convert.ExitCode)). See C:\Windows\setupact.log / setuperr.log"
          }
        } else { Rep "Conversion aborted by user." }
      }
    }
  }
}

# --- Setup start / hints ---
if ($mountedLetter) {
  $setupPath = Join-Path $mountedLetter 'setup.exe'
  if (Test-Path $setupPath) {
    $cmd = "`"$setupPath`" /auto upgrade /dynamicupdate enable"
    Rep "Recommended upgrade command (keep files and apps):"
    Rep "  $cmd"
    if ($StartSetup) {
      Rep "Starting setup now..."
      Start-Process -FilePath $setupPath -ArgumentList "/auto upgrade /dynamicupdate enable" -Wait
      Rep "Setup finished (there may be reboots)."
    } else {
      Rep "Setup not started automatically (use -StartSetup to auto-start)."
    }
  } else {
    Rep "setup.exe not found in mounted ISO."
  }
} else {
  Rep "No ISO mounted. You can mount the ISO later and run setup.exe manually."
}

Rep "Done. Report saved: $report"
Write-Host "`nFinished. Report: $report"
