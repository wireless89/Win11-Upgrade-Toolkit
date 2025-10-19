# W11-Prep-AutoFix.ps1  (ASCII only)
# Goal: Automate Win10->Win11 groundwork on older hardware.
# What it does (automated):
#  - Make free space (clean caches, disable hibernate, DISM cleanup, delete SoftwareDistribution temp)
#  - Disable WinRE (reagentc /disable)
#  - Detect system disk/partitions; remove tiny OEM/old Recovery after C: if present
#  - Extend C: into adjacent unallocated space (after C:)
#  - Run mbr2gpt /validate and /convert if possible
#  - If conversion fails with "no room for EFI", print precise next steps (GUI move 100 MB at front)
#  - Writes a log to C:\W11Prep\autofix.log

param(
  [int]$DiskNumber = -1,
  [int]$TargetFreeGB = 35,
  [switch]$SkipCleanup,
  [switch]$TryConvertNow
)

$ErrorActionPreference = 'SilentlyContinue'
$root = 'C:\W11Prep'
if (!(Test-Path $root)) { New-Item -ItemType Directory -Path $root | Out-Null }
$log = Join-Path $root 'autofix.log'
function Log($m){ "$([DateTime]::Now.ToString('u'))  $m" | Out-File -FilePath $log -Append -Encoding ascii; Write-Host $m }

Log "=== W11-Prep-AutoFix start ==="

# 0) Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run as Administrator." -ForegroundColor Yellow
  exit 1
}

# 1) Detect system drive/disk
try { $os = Get-CimInstance Win32_OperatingSystem } catch {}
$sysDrive = $os.SystemDrive
try {
  $sysPart = Get-Partition -DriveLetter $sysDrive.TrimEnd(':','\')
  $sysDiskObj = ($sysPart | Get-Disk)
  if ($DiskNumber -lt 0) { $DiskNumber = $sysDiskObj.Number }
} catch {}
if ($DiskNumber -lt 0) { Log "ERROR: Could not detect system disk."; exit 1 }
Log "System disk: $DiskNumber  System drive: $sysDrive"

# 2) Free space (unless skipped)
function Get-FreeGB { return [math]::Round(((Get-PSDrive $sysDrive.TrimEnd('\')).Free/1GB),1) }
if (-not $SkipCleanup) {
  Log "Cleanup phase..."
  # a) Turn off hibernate
  try { powercfg /h off | Out-Null; Log "Hibernate off" } catch {}
  # b) Stop WU services and clear SoftwareDistribution\Download
  try {
    Stop-Service wuauserv -Force; Stop-Service bits -Force
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force
    Start-Service wuauserv; Start-Service bits
    Log "Cleared SoftwareDistribution\\Download"
  } catch { Log "SoftwareDistribution cleanup failed: $($_.Exception.Message)" }
  # c) Temp folders
  try { cmd /c "del /q/f/s %TEMP%\*" | Out-Null; Log "User temp cleaned" } catch {}
  try { cmd /c "del /q/f/s C:\Windows\Temp\*" | Out-Null; Log "Windows temp cleaned" } catch {}
  # d) DISM component cleanup
  try { Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null; Log "DISM cleanup done" } catch { Log "DISM cleanup error" }
}
$freeGB = Get-FreeGB
Log "Free space on $sysDrive : $freeGB GB"
if ($freeGB -lt $TargetFreeGB) { Log "WARN: Less than target free space ($TargetFreeGB GB). Continue anyway." }

# 3) Disable WinRE (so we can delete shrinky Recovery partitions if needed)
try {
  $reinfo = reagentc /info
  reagentc /disable | Out-Null
  Log "WinRE disabled"
} catch { Log "WinRE disable failed (may already be off)." }

# 4) Partition layout and quick hygiene on DiskNumber
$parts = Get-Partition -DiskNumber $DiskNumber | Sort-Object PartitionNumber
Log "Partitions on disk $DiskNumber:"
$parts | ForEach-Object { Log ("  Part {0}  Letter={1}  Size={2}  Type={3}" -f $_.PartitionNumber, $_.DriveLetter, $_.Size, $_.Type) }

# Remove tiny OEM/Recovery AFTER C: (adjacent), then extend C:
$sysPartObj = $parts | Where-Object { $_.DriveLetter -eq $sysDrive.TrimEnd(':','\') }
if ($sysPartObj) {
  $after = $parts | Where-Object { $_.PartitionNumber -gt $sysPartObj.PartitionNumber }
  $firstAfter = $after | Select-Object -First 1
  if ($firstAfter -and ($firstAfter.Type -like "*Recovery*" -or $firstAfter.Type -like "*OEM*") -and $firstAfter.Size -lt 800MB) {
    try {
      Log "Deleting tiny partition after C: (Part $($firstAfter.PartitionNumber), $($firstAfter.Type), $([math]::Round($firstAfter.Size/1MB)) MB)"
      Remove-Partition -DiskNumber $DiskNumber -PartitionNumber $firstAfter.PartitionNumber -Confirm:$false
    } catch { Log "Could not delete tiny partition: $($_.Exception.Message)" }
  }
  # Try to extend C: into immediate unallocated space AFTER it
  try {
    # Determine maximum size
    $vol = Get-Volume -DriveLetter $sysDrive.TrimEnd(':','\')
    $cur = $sysPartObj.Size
    # Try blind "max" extend; Resize-Partition without -Size uses all contiguous free space if we pass a big size.
    Resize-Partition -DriveLetter $sysDrive.TrimEnd(':','\') -Size ($cur + 500GB) -ErrorAction SilentlyContinue | Out-Null
    Log "Tried to extend C: into adjacent unallocated space."
  } catch { Log "Extend C: failed or not needed." }
} else {
  Log "ERROR: Could not resolve system partition object."
}

# 5) Try mbr2gpt validate/convert if requested
function Run-Mbr2Gpt {
  $build = [Environment]::OSVersion.Version.Build
  if ($build -lt 15063) { Log "Build too old for allowFullOS."; return 999 }
  $m = "$env:SystemRoot\System32\mbr2gpt.exe"
  if (!(Test-Path $m)) { Log "mbr2gpt.exe not found"; return 998 }
  Log "mbr2gpt /validate /disk:$DiskNumber /allowFullOS"
  $v = Start-Process -FilePath $m -ArgumentList "/validate /disk:$DiskNumber /allowFullOS" -PassThru -Wait -NoNewWindow
  if ($v.ExitCode -ne 0) { Log "VALIDATE FAILED (ExitCode $($v.ExitCode))"; return $v.ExitCode }
  Log "VALIDATE OK"
  Log "mbr2gpt /convert /disk:$DiskNumber /allowFullOS"
  $c = Start-Process -FilePath $m -ArgumentList "/convert /disk:$DiskNumber /allowFullOS" -PassThru -Wait -NoNewWindow
  Log "CONVERT ExitCode: $($c.ExitCode)"
  return $c.ExitCode
}

$exit = -1
if ($TryConvertNow) {
  $exit = Run-Mbr2Gpt
  if ($exit -eq 0) {
    Log "Conversion SUCCESS. Reboot incoming. Set firmware to UEFI mode, disable CSM."
    Start-Sleep -Seconds 5
    Restart-Computer
    exit
  }
  if ($exit -eq 8) {
    Log "mbr2gpt: Cannot find room for EFI System Partition."
    Log "ACTION REQUIRED:"
    Log "  1) Use AOMEI Partition Assistant STANDARD (free) to MOVE C: a little to the right"
    Log "     so that there is at least 100 MB Unallocated Space BEFORE C: (at the beginning)."
    Log "  2) Steps: Right-click C: -> Move/Resize -> set 'Unallocated Space Before' to 100 MB -> Apply -> Reboot if asked."
    Log "  3) After Windows boots, run this script again with -TryConvertNow to finish."
  } elseif ($exit -ne -1) {
    Log "mbr2gpt failed with ExitCode $exit. Check C:\Windows\setupact.log and setuperr.log"
  }
} else {
  Log "TryConvertNow not set. Skipping mbr2gpt for now."
}

# 6) Done
$freeGBNow = [math]::Round(((Get-PSDrive $sysDrive.TrimEnd('\')).Free/1GB),1)
Log "Free space now: $freeGBNow GB"
Log "=== AutoFix finished. Log: $log ==="
Write-Host "AutoFix finished. Log: $log"
