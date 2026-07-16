$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
$runtime = Join-Path $dist "runtime"
$licenses = Join-Path $dist "licenses"
$source = Join-Path $root "scripts\BmBlockedTray.cs"
$notificationVendor = Join-Path $root "vendor\notifications"
$toastToolkit = Join-Path $notificationVendor "Microsoft.Toolkit.Uwp.Notifications.dll"
$valueTuple = Join-Path $notificationVendor "System.ValueTuple.dll"
$systemRuntime = Get-ChildItem "$env:WINDIR\Microsoft.NET\assembly\GAC_MSIL\System.Runtime" -Recurse -Filter System.Runtime.dll -ErrorAction SilentlyContinue |
  Select-Object -First 1 -ExpandProperty FullName
$winMetadata = Join-Path $env:WINDIR "System32\WinMetadata"
$windowsFoundation = Join-Path $winMetadata "Windows.Foundation.winmd"
$windowsData = Join-Path $winMetadata "Windows.Data.winmd"
$windowsUi = Join-Path $winMetadata "Windows.UI.winmd"
$compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$authConfig = Join-Path $root "auth-config.json"
$archive = Join-Path $root "bm-blocked.zip"
$checksum = Join-Path $root "bm-blocked.zip.sha256"
$systemNodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$systemNode = if ($systemNodeCommand) { $systemNodeCommand.Source } else { $null }
$codexNode = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "OpenAI\Codex\runtimes") -Recurse -Filter node.exe -ErrorAction SilentlyContinue |
  Select-Object -First 1 -ExpandProperty FullName
$nodeSource = if ($systemNode) { $systemNode } else { $codexNode }

if (-not (Test-Path $compiler)) {
  throw "C# compiler not found: $compiler"
}

if (-not $nodeSource -or -not (Test-Path $nodeSource)) {
  throw "Node runtime not found. Install Node.js or run the build from Codex."
}

if (-not (Test-Path $authConfig)) {
  throw "auth-config.json not found. Copy the company authorization config before building."
}

if (-not (Test-Path $toastToolkit) -or -not (Test-Path $valueTuple)) {
  throw "Notification dependencies are missing in vendor\notifications."
}

if (-not $systemRuntime -or -not (Test-Path $systemRuntime)) {
  throw "System.Runtime.dll is required to compile Windows notifications."
}

$expectedDist = [IO.Path]::GetFullPath((Join-Path $root "dist"))
$actualDist = [IO.Path]::GetFullPath($dist)

if ($actualDist -ne $expectedDist -or [IO.Path]::GetDirectoryName($actualDist) -ne [IO.Path]::GetFullPath($root)) {
  throw "Unexpected dist path: $actualDist"
}

if (Test-Path $dist) {
  Remove-Item -LiteralPath $dist -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $dist, $runtime, $licenses | Out-Null

$exePath = Join-Path $dist "bm-blocked.exe"

& $compiler `
  /nologo `
  /codepage:65001 `
  /target:winexe `
  /platform:anycpu `
  /optimize+ `
  /out:$exePath `
  /reference:System.dll `
  /reference:System.Drawing.dll `
  /reference:System.IO.Compression.dll `
  /reference:System.IO.Compression.FileSystem.dll `
  /reference:System.Web.Extensions.dll `
  /reference:System.Windows.Forms.dll `
  /reference:$systemRuntime `
  /reference:$toastToolkit `
  /reference:$valueTuple `
  /reference:$windowsFoundation `
  /reference:$windowsData `
  /reference:$windowsUi `
  $source

if ($LASTEXITCODE -ne 0) {
  throw "C# build failed with exit code $LASTEXITCODE"
}

Copy-Item -Force (Join-Path $root "server.js") (Join-Path $dist "server.js")
Copy-Item -Force (Join-Path $root "index.html") (Join-Path $dist "index.html")
Copy-Item -Force $authConfig (Join-Path $dist "auth-config.json")
Copy-Item -Force (Join-Path $root "README.md") (Join-Path $dist "README.txt")
Copy-Item -Force $nodeSource (Join-Path $runtime "node.exe")
Copy-Item -Force $toastToolkit (Join-Path $dist "Microsoft.Toolkit.Uwp.Notifications.dll")
Copy-Item -Force $valueTuple (Join-Path $dist "System.ValueTuple.dll")
Copy-Item -Force (Join-Path $notificationVendor "Microsoft.Toolkit.Uwp.Notifications.LICENSE.md") $licenses
Copy-Item -Force (Join-Path $notificationVendor "System.ValueTuple.LICENSE.txt") $licenses

if (Test-Path $archive) {
  Remove-Item -LiteralPath $archive -Force
}

if (Test-Path $checksum) {
  Remove-Item -LiteralPath $checksum -Force
}

Compress-Archive -Path (Join-Path $dist "*") -DestinationPath $archive -CompressionLevel Optimal
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumLine = "$archiveHash  bm-blocked.zip`r`n"
[IO.File]::WriteAllText($checksum, $checksumLine, [Text.Encoding]::ASCII)

Write-Host "Done: $exePath"
Write-Host "Archive: $archive"
Write-Host "Checksum: $checksum"
