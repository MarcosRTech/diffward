# diffward installer for Windows (PowerShell 5.1+).
#
#   irm https://github.com/MarcosRTech/diffward/releases/latest/download/install.ps1 | iex
#
# Environment:
#   DIFFWARD_VERSION      tag to install, e.g. v0.2.0 (default: latest release)
#   DIFFWARD_INSTALL_DIR  where to put diffward.exe (default: %LOCALAPPDATA%\diffward\bin)
#   DIFFWARD_FORCE=1      reinstall even if that version is already installed

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "MarcosRTech/diffward"
$InstallDir = if ($env:DIFFWARD_INSTALL_DIR) { $env:DIFFWARD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "diffward\bin" }
$Steps = 4

function Write-Step($n, $text) { Write-Host "[$n/$Steps] " -NoNewline -ForegroundColor DarkGray; Write-Host $text }
function Write-Info($label, $text) { Write-Host ("      {0,-10} " -f $label) -NoNewline -ForegroundColor DarkGray; Write-Host $text }
# `throw`, not `exit`: under `irm ... | iex`, exit would close the user's PowerShell window.
function Stop-Install($message, $hint) {
  Write-Host ""
  if ($hint) { Write-Host "  $hint" }
  throw "diffward install failed: $message"
}
function Format-Size([double]$bytes) {
  $units = "B", "KB", "MB", "GB"; $i = 0
  while ($bytes -ge 1024 -and $i -lt 3) { $bytes /= 1024; $i++ }
  if ($i -eq 0) { "{0} {1}" -f [int]$bytes, $units[$i] } else { "{0:N1} {1}" -f $bytes, $units[$i] }
}

# The logo is kept ASCII in this file (PowerShell 5.1 may decode a downloaded
# script as Latin-1) and turned into box-drawing characters at runtime.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$logo = @'
@@@@@@} @@}@@@@@@@}@@@@@@@}@@}    @@} @@@@@} @@@@@@} @@@@@@}
@@{==@@}@@!@@{====]@@{====]@@!    @@!@@{==@@}@@{==@@}@@{==@@}
@@!  @@!@@!@@@@@}  @@@@@}  @@! @} @@!@@@@@@@!@@@@@@{]@@!  @@!
@@!  @@!@@!@@{==]  @@{==]  @@!@@@}@@!@@{==@@!@@{==@@}@@!  @@!
@@@@@@{]@@!@@!     @@!     [@@@{@@@{]@@!  @@!@@!  @@!@@@@@@{]
[=====] [=][=]     [=]      [==][==] [=]  [=][=]  [=][=====]
'@
$glyphs = @{ "@" = 0x2588; "{" = 0x2554; "}" = 0x2557; "[" = 0x255A; "]" = 0x255D; "=" = 0x2550; "!" = 0x2551 }
foreach ($k in $glyphs.Keys) { $logo = $logo.Replace($k, [string][char]$glyphs[$k]) }
Write-Host $logo -ForegroundColor Cyan
Write-Host ""
Write-Host "  Security scanner for pull requests " -NoNewline
Write-Host "- installer" -ForegroundColor DarkGray
Write-Host ""

# ---------------------------------------------------------------- 1. detect
Write-Step 1 "Detecting your system"
if (-not [Environment]::Is64BitOperatingSystem) { Stop-Install "32-bit Windows is not supported." }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
  # No native build yet; the x64 binary runs under Windows on ARM emulation.
  $Arch = "x64 (emulated on ARM64)"
} else { $Arch = "x64" }
$Asset = "diffward-windows-x64.exe"
$OsName = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
if (-not $OsName) { $OsName = "Windows" }

if ($env:DIFFWARD_VERSION) {
  $Version = if ($env:DIFFWARD_VERSION.StartsWith("v")) { $env:DIFFWARD_VERSION } else { "v$($env:DIFFWARD_VERSION)" }
  $Note = "pinned"
} else {
  try {
    $latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "diffward-installer" }
    $Version = $latest.tag_name
  } catch { Stop-Install "Could not find the latest release." "Check your connection, or set DIFFWARD_VERSION=v0.2.0." }
  $Note = "latest"
}
$Base = "https://github.com/$Repo/releases/download/$Version"
$Target = Join-Path $InstallDir "diffward.exe"
$Previous = if (Test-Path $Target) { (& $Target --version 2>$null) } else { "" }

Write-Info "System" "$OsName - $Arch"
Write-Info "Version" "$Version ($Note)"
if ($Previous) {
  Write-Info "Installed" $Previous
  if ("v$Previous" -eq $Version -and $env:DIFFWARD_FORCE -ne "1") {
    Write-Host ""
    Write-Host "  ok diffward $Previous is already installed and up to date." -ForegroundColor Green
    Write-Host "  DIFFWARD_FORCE=1 reinstalls it." -ForegroundColor DarkGray
    return
  }
}

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("diffward-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  # -------------------------------------------------------------- 2. download
  Write-Host ""
  Write-Step 2 "Downloading"
  Add-Type -AssemblyName System.Net.Http
  $client = New-Object System.Net.Http.HttpClient
  $client.DefaultRequestHeaders.UserAgent.ParseAdd("diffward-installer")
  $response = $client.GetAsync("$Base/$Asset", [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
  if (-not $response.IsSuccessStatusCode) {
    Stop-Install "$Asset is not published for $Version." "Available releases: https://github.com/$Repo/releases"
  }
  $total = [long]$response.Content.Headers.ContentLength
  Write-Info "Package" ("{0} ({1})" -f $Asset, (Format-Size $total))

  $out = Join-Path $Tmp $Asset
  $stream = $response.Content.ReadAsStreamAsync().Result
  $file = [IO.File]::Create($out)
  $buffer = New-Object byte[] 262144
  $done = [long]0
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $lastDraw = -1
  $width = 30
  # CI logs turn every `r redraw into a new line: print a line every 25% there instead.
  $interactive = -not [Console]::IsOutputRedirected -and -not $env:CI
  $nextMilestone = 25
  try {
    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $file.Write($buffer, 0, $read)
      $done += $read
      $pct = if ($total -gt 0) { [int][Math]::Floor($done * 100 / $total) } else { 0 }
      if ($interactive -and $pct -ne $lastDraw) {
        $lastDraw = $pct
        $filled = [int][Math]::Floor($pct * $width / 100)
        $speed = if ($watch.Elapsed.TotalSeconds -gt 0) { "  " + (Format-Size ($done / $watch.Elapsed.TotalSeconds)) + "/s" } else { "" }
        $bar = ("#" * $filled).PadRight($width, "-")
        Write-Host ("`r      [{0}] {1,3}%  {2} / {3}{4}   " -f $bar, $pct, (Format-Size $done), (Format-Size $total), $speed) -NoNewline
      } elseif (-not $interactive -and $pct -ge $nextMilestone -and $nextMilestone -lt 100) {
        Write-Info "" ("{0}% ({1} / {2})" -f $nextMilestone, (Format-Size $done), (Format-Size $total))
        $nextMilestone += 25
      }
    }
  } finally { $file.Close(); $stream.Close(); $client.Dispose() }
  if ($interactive) { Write-Host "" }
  if ($total -gt 0 -and $done -ne $total) { Stop-Install ("Incomplete download: got {0} of {1}." -f (Format-Size $done), (Format-Size $total)) }
  Write-Info "Done" ("{0} in {1:N0}s" -f (Format-Size $done), $watch.Elapsed.TotalSeconds)

  # -------------------------------------------------------------- 3. verify
  Write-Host ""
  Write-Step 3 "Verifying"
  $sums = (Invoke-WebRequest "$Base/SHA256SUMS" -UseBasicParsing).Content
  if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }
  $expected = ($sums -split "`n" | Where-Object { $_ -match "\s$([regex]::Escape($Asset))\s*$" } | ForEach-Object { ($_ -split "\s+")[0] }) | Select-Object -First 1
  if (-not $expected) { Stop-Install "No checksum for $Asset in SHA256SUMS." }
  $actual = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected.ToLower()) { Stop-Install "Checksum mismatch: the download is corrupted or was tampered with." "expected $expected, got $actual" }
  Write-Info "SHA-256" ("{0}...{1} ok" -f $actual.Substring(0, 8), $actual.Substring(56))

  # -------------------------------------------------------------- 4. install
  Write-Host ""
  Write-Step 4 "Installing"
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Move-Item -Force $out $Target
  $Installed = (& $Target --version)
  if (-not $Installed) { Stop-Install "The installed binary does not run on this system." }
  Write-Info "Location" $Target

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $onPath = ($userPath -split ";") -contains $InstallDir
  if (-not $onPath) {
    [Environment]::SetEnvironmentVariable("Path", (($userPath.TrimEnd(";"), $InstallDir) -join ";").TrimStart(";"), "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Info "PATH" "added $InstallDir to your user PATH (open a new terminal)"
  }
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "  ok diffward $Installed installed" -NoNewline -ForegroundColor Green
if ($Previous -and $Previous -ne $Installed) { Write-Host " (was $Previous)" -ForegroundColor DarkGray } else { Write-Host "" }
Write-Host ""
Write-Host "  Next steps"
foreach ($row in @(
  @("diffward --diff origin/main", "scan what your branch changes"),
  @("diffward", "scan the whole repository"),
  @("diffward baseline", "adopt on an existing project"),
  @("diffward --help", "all options"))) {
  Write-Host ("      {0,-32} " -f $row[0]) -NoNewline
  Write-Host $row[1] -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Docs: https://github.com/$Repo" -ForegroundColor DarkGray
Write-Host ""
