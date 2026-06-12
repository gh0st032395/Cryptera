$ErrorActionPreference = "Stop"

$version = (Get-Content VERSION -Raw).Trim()
if (-not $version) {
  throw "VERSION file is empty"
}

$rootCargo = Get-Content Cargo.toml -Raw
$tauriCargo = Get-Content src-tauri/Cargo.toml -Raw
$tauriConfig = Get-Content src-tauri/tauri.conf.json -Raw

function Assert-Version([string]$content, [string]$name) {
  $m = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
  if (-not $m.Success) {
    throw "$name does not contain a package version"
  }
  if ($m.Groups[1].Value -ne $version) {
    throw "$name version does not match VERSION=$version"
  }
}

Assert-Version $rootCargo "Cargo.toml"
Assert-Version $tauriCargo "src-tauri/Cargo.toml"

$cfg = $tauriConfig | ConvertFrom-Json
if ($cfg.version -ne $version) {
  throw "src-tauri/tauri.conf.json version does not match VERSION=$version"
}

$pkg = Get-Content package.json -Raw | ConvertFrom-Json
if ($pkg.version -ne $version) {
  throw "package.json version does not match VERSION=$version"
}

Write-Host "Version check OK: $version"
