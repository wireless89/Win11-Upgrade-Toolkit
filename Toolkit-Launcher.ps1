# Toolkit-Launcher.ps1 (ASCII only)
# Simple TUI to run common upgrade/repair actions
$ErrorActionPreference = "SilentlyContinue"
# function Header(){ Clear-Host; Write-Host "=== Win11 Upgrade Toolkit ===`n" }
# Resolve base path (where the launcher sits) and scripts/docs
$BaseDir   = Split-Path -Parent $PSCommandPath
$ScriptDir = Join-Path $BaseDir 'scripts'
$DocDir    = Join-Path $BaseDir 'docs'
function Header(){ Clear-Host; Write-Host "=== Win11 Upgrade Toolkit ===`nBase: $BaseDir`n" }

function PauseIt(){ Write-Host ""; Read-Host "Press ENTER to continue..." | Out-Null }
function Admin(){ $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=new-object Security.Principal.WindowsPrincipal($id); return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if (-not (Admin)) { Write-Host "Run as Administrator." -ForegroundColor Yellow; exit 1 }

do {
  Header
  Write-Host "1) Pre-Check (disk/uefi/tpm/space)"
  Write-Host "2) EFI/BCD Repair Wizard (UEFI boot fix)"
  Write-Host "3) Set Upgrade Bypass (TPM/CPU/SB/RAM)"
  Write-Host "4) Start Win11 Setup with bypass"
  Write-Host "5) Run Trim (Balanced/Pro/Aggressive)"
  Write-Host "6) Enable WinRE"
  Write-Host "0) Exit"
  $sel = Read-Host "`nSelect"
  switch ($sel) {
    "1" {
      Header
      Write-Host "[Pre-Check]"
      try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $disk = (Get-Partition -DriveLetter $os.SystemDrive.TrimEnd(':','\') | Get-Disk)
        $freeGB = [math]::Round(((Get-PSDrive $os.SystemDrive.TrimEnd('\')).Free/1GB),1)
        Write-Host ("OS: {0}  Build: {1}" -f $os.Caption, [Environment]::OSVersion.Version.Build)
        Write-Host ("Edition: {0}" -f (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID)
        try {$tpm = Get-Tpm; Write-Host ("TPM Present={0} Ready={1}" -f $tpm.TpmPresent,$tpm.TpmReady)} catch { Write-Host "TPM info N/A" }
        Write-Host ("System Disk: {0}  Style: {1}" -f $disk.Number, $disk.PartitionStyle)
        Write-Host ("Free on {0} : {1} GB" -f $os.SystemDrive, $freeGB)
      } catch { Write-Host "Pre-Check failed: $($_.Exception.Message)" }
      PauseIt
    }
    "2" {
      Header
      Write-Host "[EFI/BCD Repair Wizard]"
      Write-Host "This will rebuild the EFI partition and boot files (UEFI only)."
      $dl = Read-Host "EFI partition letter to use (default Z)"
      if ([string]::IsNullOrWhiteSpace($dl)) { $dl = "Z" }
      $win = Read-Host "Windows drive letter as seen in WinRE (default C)"
      if ([string]::IsNullOrWhiteSpace($win)) { $win = "C" }
      Write-Host "Steps:"
      Write-Host "  diskpart -> select disk <SYSTEM_DISK> -> select partition <EFI#> -> assign letter=$dl"
      Write-Host "  (or delete/create partition efi size=100 then assign letter=$dl)"
      Write-Host "Then run:"
      Write-Host ("  bcdboot {0}:\Windows /l de-de /s {1}: /f UEFI" -f $win,$dl)
      PauseIt
    }
    "3" {
      Header
      Write-Host "[Bypass Keys]"
      New-Item -Path 'HKLM:\SYSTEM\Setup\MoSetup' -Force | Out-Null
      New-ItemProperty -Path 'HKLM:\SYSTEM\Setup\MoSetup' -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType DWord -Force | Out-Null
      New-Item -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Force | Out-Null
      foreach($n in 'BypassTPMCheck','BypassCPUCheck','BypassSecureBootCheck','BypassRAMCheck'){ New-ItemProperty -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Name $n -Value 1 -PropertyType DWord -Force | Out-Null }
      Write-Host "Bypass set."
      PauseIt
    }
    "4" {
      Header
      Write-Host "[Start Setup with Bypass]"
      $iso = Read-Host "Mounted ISO drive letter (e.g. D or E)"
      $cmd = ("{0}:\setup.exe /product server /compat IgnoreWarning /auto upgrade /dynamicupdate disable" -f $iso.TrimEnd(':'))
      Write-Host "Run:"
      Write-Host "  $cmd"
      $go = Read-Host "Run now? (Y/N)"
      if ($go -match '^[YyJj]') { Start-Process -FilePath ("{0}:\setup.exe" -f $iso.TrimEnd(':')) -ArgumentList "/product server /compat IgnoreWarning /auto upgrade /dynamicupdate disable" }
      PauseIt
    }
    "5" {
      Header
      Write-Host "[Trim]"
      $mode = Read-Host "Mode: Balanced / Pro / Aggressive (default Pro)"
      if ([string]::IsNullOrWhiteSpace($mode)) { $mode="Pro" }
      $path = Join-Path $ScriptDir "W11-Trim-Complete-V2.ps1"
			if (!(Test-Path $path)) {
			  Write-Host "Trim script not found at: $path"
			} else {
			  Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$path`" -Mode $mode"
			}
      PauseIt
    }
    "6" {
      Header
      Write-Host "[Enable WinRE]"
      Start-Process cmd -Verb RunAs -ArgumentList "/c reagentc /enable && reagentc /info"
      PauseIt
    }
    "0" { break }
    default { }
  }
} while ($true)