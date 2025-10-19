# install.ps1  (ASCII only)
# Win11-Upgrade-Toolkit bootstrapper: downloads files from GitHub and launches the Toolkit-Launcher.
param(
  [string]$User    = "wireless89",            # TODO: your GitHub username
  [string]$Repo    = "Win11-Upgrade-Toolkit",
  [string]$Branch  = "main",
  [switch]$ForceUpdate,                   # re-download even if files exist
  [switch]$NoLaunch                       # don't auto-launch the toolkit
)

$ErrorActionPreference = "SilentlyContinue"
# 0) Elevation
function IsAdmin(){
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (IsAdmin)) {
  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $($MyInvocation.UnboundArguments)"
  exit
}

# 1) TLS 1.2 for GitHub
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 2) Paths
$BaseDir   = "C:\ProgramData\Win11UpgradeToolkit"
$ScriptDir = Join-Path $BaseDir "scripts"
$DocDir    = Join-Path $BaseDir "docs"
$RawBase   = "https://raw.githubusercontent.com/$User/$Repo/$Branch"
$null = New-Item -ItemType Directory -Path $BaseDir,$ScriptDir,$DocDir -Force

# 3) Helper: download with retries
function Get-File($url,$dest){
  if ((Test-Path $dest) -and (-not $ForceUpdate)) { return }
  for($i=1;$i -le 3;$i++){
    try{
      Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest -TimeoutSec 60
      Unblock-File -Path $dest -ErrorAction SilentlyContinue
      return
    } catch {
      Start-Sleep -Seconds (2*$i)
    }
  }
  throw "Download failed: $url"
}

Write-Host "== Win11-Upgrade-Toolkit Installer =="
Write-Host "Repo: $User/$Repo [$Branch]"
Write-Host "Target: $BaseDir"
Write-Host ""

# 4) File map (extend as you add files)
$files = @(
  @{ url="$RawBase/Toolkit-Launcher.ps1";                 dst=(Join-Path $BaseDir   "Toolkit-Launcher.ps1") },
  @{ url="$RawBase/Win11-Trim-Complete.ps1";     dst=(Join-Path $ScriptDir "W11-Trim-Complete-V2.ps1") },
  @{ url="$RawBase/W11-Prep-AutoFix.ps1";         dst=(Join-Path $ScriptDir "W11-Prep-AutoFix.ps1") },
  @{ url="$RawBase/PreUpgrade-W11-Bypass.ps1";    dst=(Join-Path $ScriptDir "PreUpgrade-W11-Bypass.ps1") },
//  @{ url="$RawBase/docs/Upgrade-Guide.md";                dst=(Join-Path $DocDir    "Upgrade-Guide.md") },
//  @{ url="$RawBase/docs/Troubleshooting.md";              dst=(Join-Path $DocDir    "Troubleshooting.md") }
)

# 5) Download files
foreach($f in $files){
  try {
    Write-Host ("Fetching: {0}" -f $f.url)
    Get-File $f.url $f.dst
  } catch {
    Write-Host ("WARN: {0}" -f $_.Exception.Message)
  }
}

# 6) Quick sanity
$launcher = Join-Path $BaseDir "Toolkit-Launcher.ps1"
if (!(Test-Path $launcher)) {
  Write-Host "ERROR: Toolkit-Launcher.ps1 missing. Check GitHub path/user/branch."
  exit 1
}

# 7) Launch
if (-not $NoLaunch){
  Write-Host "Launching Toolkit Launcher..."
  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$launcher`""
} else {
  Write-Host "Install finished. Launcher at: $launcher"
}