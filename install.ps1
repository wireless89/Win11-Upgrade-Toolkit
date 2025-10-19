# install.ps1  (ASCII only)  -- always update version
# Downloads the toolkit to C:\ProgramData\Win11UpgradeToolkit and launches the launcher.
param(
  [string]$User   = "<USER>",                   # <<< GitHub-Nutzername einsetzen (ohne <>)
  [string]$Repo   = "Win11-Upgrade-Toolkit",
  [string]$Branch = "main",
  [switch]$NoLaunch                               # optional: nur herunterladen, nicht starten
)

$ErrorActionPreference = "SilentlyContinue"

# --- Elevation ---
function IsAdmin(){
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (IsAdmin)) {
  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $($MyInvocation.UnboundArguments)"
  exit
}

# --- TLS for GitHub ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Paths ---
$BaseDir   = "C:\ProgramData\Win11UpgradeToolkit"
$ScriptDir = Join-Path $BaseDir "scripts"
$DocDir    = Join-Path $BaseDir "docs"
$LogDir    = Join-Path $BaseDir "logs"
$RawBase   = "https://raw.githubusercontent.com/$User/$Repo/$Branch"

# ensure dirs
$null = New-Item -ItemType Directory -Path $BaseDir,$ScriptDir,$DocDir,$LogDir -Force

Write-Host "== Win11-Upgrade-Toolkit Installer (always update) =="
Write-Host "Repo : $User/$Repo [$Branch]"
Write-Host "Target: $BaseDir"
Write-Host ""

# --- Download helper: ALWAYS overwrite + cache-busting ---
function Get-File($url,$dest){
  try {
    $noc = "?nocache=$([guid]::NewGuid().ToString())"
    $tmp = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
    Invoke-WebRequest -UseBasicParsing -Uri ($url+$noc) -OutFile $tmp -TimeoutSec 90
    # move with overwrite
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    Move-Item $tmp $dest -Force
    Unblock-File -Path $dest -ErrorAction SilentlyContinue
    Write-Host ("Fetched: {0}" -f $url)
  } catch {
    Write-Host ("WARN : Download failed: {0} -> {1}" -f $url, $_.Exception.Message)
  }
}

# --- File map ---
$files = @(
  @{ url="$RawBase/Toolkit-Launcher.ps1";                 dst=(Join-Path $BaseDir   "Toolkit-Launcher.ps1") },
  @{ url="$RawBase/scripts/W11-Trim-Complete-V2.ps1";     dst=(Join-Path $ScriptDir "W11-Trim-Complete-V2.ps1") },
  @{ url="$RawBase/scripts/W11-Prep-AutoFix.ps1";         dst=(Join-Path $ScriptDir "W11-Prep-AutoFix.ps1") },
  @{ url="$RawBase/scripts/PreUpgrade-W11-Bypass.ps1";    dst=(Join-Path $ScriptDir "PreUpgrade-W11-Bypass.ps1") },
  @{ url="$RawBase/docs/Upgrade-Guide.md";                dst=(Join-Path $DocDir    "Upgrade-Guide.md") },
  @{ url="$RawBase/docs/Troubleshooting.md";              dst=(Join-Path $DocDir    "Troubleshooting.md") }
)

# --- Download all (always update) ---
foreach($f in $files){ Get-File $f.url $f.dst }

# --- Sanity ---
$launcher = Join-Path $BaseDir "Toolkit-Launcher.ps1"
if (!(Test-Path $launcher)) {
  Write-Host "ERROR: Launcher missing at $launcher. Check Repo/Branch/User."
  exit 1
}

# --- Launch (optional) ---
if (-not $NoLaunch){
  Write-Host "`nLaunching Toolkit Launcher..."
  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$launcher`""
} else {
  Write-Host "`nInstalled to $BaseDir"
}