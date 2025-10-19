# Toolkit-Launcher.ps1 (updated)
# Runs from C:\ProgramData\Win11UpgradeToolkit by default
$ErrorActionPreference = "SilentlyContinue"

# --- Resolve base paths (works no matter where you start it from) ---
$BaseDir   = Split-Path -Parent $PSCommandPath
if (-not $BaseDir) { $BaseDir = "C:\ProgramData\Win11UpgradeToolkit" }  # fallback
$ScriptDir = Join-Path $BaseDir 'scripts'
$DocDir    = Join-Path $BaseDir 'docs'

function Header(){
  Clear-Host
  Write-Host "=== Win11 Upgrade Toolkit ==="
  Write-Host ("Base: {0}" -f $BaseDir)
  Write-Host ""
}
function PauseIt(){ Write-Host ""; Read-Host "Press ENTER to continue..." | Out-Null }
function Admin(){
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Admin)) { Write-Host "Run as Administrator." -ForegroundColor Yellow; exit 1 }

do {
  Header
  Write-Host "1) Pre-Check (disk/uefi/tpm/space)"
  Write-Host "2) EFI/BCD Repair Wizard (UEFI boot fix)"
  Write-Host "3) Set Upgrade Bypass (via script in /scripts)"
  Write-Host "4) Start Win11 Setup with bypass (ISO drive)"
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
        $disk = (Get-Partition -DriveLetter $os.SystemDrive.TrimEnd(':','\') | Get-Disk)
        $freeGB = [math]::Round(((Get-PSDrive $os.SystemDrive.TrimEnd('\')).Free/1GB),1)
        Write-Host ("OS: {0}  Build: {1}" -f $os.Caption, [Environment]::OSVersion.Version.Build)
        Write-Host ("Edition: {0}" -f (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID)
        try { $tpm = Get-Tpm; Write-Host ("TPM Present={0} Ready={1}" -f $tpm.TpmPresent,$tpm.TpmReady) } catch { Write-Host "TPM info N/A" }
        Write-Host ("System Disk: {0}  Style: {1}" -f $disk.Number, $disk.PartitionStyle)
        Write-Host ("Free on {0} : {1} GB" -f $os.SystemDrive, $freeGB)
      } catch { Write-Host "Pre-Check failed: $($_.Exception.Message)" }
      PauseIt
    }
    "2" {
      Header
      Write-Host "[EFI/BCD Repair Wizard]"
      Write-Host "Use WinRE CMD: diskpart -> select disk <n> -> select partition <EFI#> -> assign letter=Z"
      Write-Host "Then: bcdboot <WindowsDrive>:\Windows /l de-de /s Z: /f UEFI"
      PauseIt
    }
    "3" {
      Header
      Write-Host "[Set Upgrade Bypass via script]"
      $bypass = Join-Path $ScriptDir "PreUpgrade-W11-Bypass.ps1"
      if (!(Test-Path $bypass)) {
        Write-Host "Missing: $bypass"
      } else {
        # Set only the bypass keys (no ISO mount, no setup start)
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$bypass`""
        Write-Host "Bypass script launched."
      }
      PauseIt
    }
    "4" {
      Header
      Write-Host "[Start Setup with bypass]"
      $drive = Read-Host "Mounted ISO drive letter (e.g. D or E)"
      if ([string]::IsNullOrWhiteSpace($drive)) { $drive="D" }
      $setup = ("{0}:\setup.exe" -f $drive.TrimEnd(':'))
      if (Test-Path $setup) {
        $args  = "/product server /compat IgnoreWarning /auto upgrade /dynamicupdate disable"
        Write-Host "Launching: $setup $args"
        Start-Process -FilePath $setup -ArgumentList $args -Verb RunAs
      } else {
        Write-Host "setup.exe not found at $setup"
      }
      PauseIt
    }
    "5" {
      Header
      Write-Host "[Trim]"
      $mode = Read-Host "Mode: Balanced / Pro / Aggressive (default Pro)"; if ([string]::IsNullOrWhiteSpace($mode)) { $mode="Pro" }
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