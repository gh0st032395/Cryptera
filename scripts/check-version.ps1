$ErrorActionPreference = "Stop"

$version = (Get-Content VERSION -Raw).Trim()
if (-not $version) {
  throw "VERSION file is empty"
}

$rootCargo = Get-Content Cargo.toml -Raw
$opsCargo = Get-Content ops/Cargo.toml -Raw
$cliCargo = Get-Content cli/Cargo.toml -Raw
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
Assert-Version $opsCargo "ops/Cargo.toml"
Assert-Version $cliCargo "cli/Cargo.toml"
Assert-Version $tauriCargo "src-tauri/Cargo.toml"

# The path dependencies pin the exact core/ops version; a bump has to reach
# them too or the workspace silently builds against a stale copy.
foreach ($pair in @(
    @{ name = "ops/Cargo.toml"; content = $opsCargo },
    @{ name = "cli/Cargo.toml"; content = $cliCargo },
    @{ name = "src-tauri/Cargo.toml"; content = $tauriCargo }
  )) {
  foreach ($m in [regex]::Matches($pair.content, 'version\s*=\s*"=([^"]+)"')) {
    if ($m.Groups[1].Value -ne $version) {
      throw "$($pair.name) pins a path dependency to $($m.Groups[1].Value), expected $version"
    }
  }
}

$cfg = $tauriConfig | ConvertFrom-Json
if ($cfg.version -ne $version) {
  throw "src-tauri/tauri.conf.json version does not match VERSION=$version"
}

$pkg = Get-Content package.json -Raw | ConvertFrom-Json
if ($pkg.version -ne $version) {
  throw "package.json version does not match VERSION=$version"
}

Write-Host "Version check OK: $version"
