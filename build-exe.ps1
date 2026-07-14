$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
$runtime = Join-Path $dist "runtime"
$source = Join-Path $root "scripts\BmBlockedTray.cs"
$compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$authConfig = Join-Path $root "auth-config.json"
$archive = Join-Path $root "bm-blocked.zip"
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

$expectedDist = [IO.Path]::GetFullPath((Join-Path $root "dist"))
$actualDist = [IO.Path]::GetFullPath($dist)

if ($actualDist -ne $expectedDist -or [IO.Path]::GetDirectoryName($actualDist) -ne [IO.Path]::GetFullPath($root)) {
  throw "Unexpected dist path: $actualDist"
}

if (Test-Path $dist) {
  Remove-Item -LiteralPath $dist -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $dist, $runtime | Out-Null

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
  /reference:System.Windows.Forms.dll `
  $source

if ($LASTEXITCODE -ne 0) {
  throw "C# build failed with exit code $LASTEXITCODE"
}

Copy-Item -Force (Join-Path $root "server.js") (Join-Path $dist "server.js")
Copy-Item -Force (Join-Path $root "index.html") (Join-Path $dist "index.html")
Copy-Item -Force $authConfig (Join-Path $dist "auth-config.json")
Copy-Item -Force (Join-Path $root "README.md") (Join-Path $dist "README.txt")
Copy-Item -Force $nodeSource (Join-Path $runtime "node.exe")

if (Test-Path $archive) {
  Remove-Item -LiteralPath $archive -Force
}

Compress-Archive -Path (Join-Path $dist "*") -DestinationPath $archive -CompressionLevel Optimal

Write-Host "Done: $exePath"
Write-Host "Archive: $archive"
