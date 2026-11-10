#Requires -Version 7.0
<#
.SYNOPSIS
  Builds the LibrePatch Agent MSI (WiX v7) from a built, ideally already signed, librepatch-agent.exe.

.DESCRIPTION
  Needs PowerShell 7, the .NET SDK (8+), Go (only to compute the numeric MSI version) and git (optional).
  The WiX version is pinned in .config/dotnet-tools.json; the Util extension version is pinned below
  and checked against it by installer/windows/package_test.go.

  EULA: WiX v7 is released under the Open Source Maintenance Fee (OSMF) EULA. The build passes
  `--acceptEula wix7` explicitly; that is the project's recorded acceptance (docs/DECISIONS.md O6, D67).
  Read installer/windows/README.md before running this in a commercial pipeline.

  Signing is NOT done here and no certificate is ever read by this script. Release pipeline:
    1. signtool sign ... librepatch-agent.exe          (before this script)
    2. build.ps1 -AgentExe ... -SignScript .\sign.ps1   (the script receives the MSI path)
    or run signtool on the MSI afterwards. See README.md for a signtool example.

.PARAMETER AgentExe
  Path to the agent exe (windows/amd64). It is embedded unchanged, so sign it first.
.PARAMETER Version
  Release version: 1.2.3, v1.2.3, 1.2.3-rc.1. Default: the exact git tag (v*) on HEAD, else the latest
  tag plus "-dev", else internal/shared/version.
.PARAMETER BuildNumber
  Fourth MSI version field for pre-release builds (CI run number). Releases always get .0.
.PARAMETER Output
  Output .msi path. Default: installer/windows/out/librepatch-agent-<version>-x64.msi
.PARAMETER SignScript
  Optional script called as `& $SignScript <path-to-msi>` after the build and validation.
.PARAMETER SkipValidate
  Skip `wix msi validate` (the ICE checks).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$AgentExe,
  [string]$Version,
  [int]$BuildNumber = 0,
  [string]$Output,
  [string]$SignScript,
  [switch]$SkipValidate
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$UtilExtension = 'WixToolset.Util.wixext/7.0.0'   # keep in step with .config/dotnet-tools.json (tested)
$EulaId        = 'wix7'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$AgentExe = (Resolve-Path -LiteralPath $AgentExe).Path
$head = [byte[]](Get-Content -LiteralPath $AgentExe -AsByteStream -TotalCount 2)
if ($head.Count -lt 2 -or $head[0] -ne 0x4D -or $head[1] -ne 0x5A) { throw "$AgentExe is not a Windows executable (no MZ header)" }

function Invoke-Tool {
  param([string]$What, [scriptblock]$Cmd)
  & $Cmd
  if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE" }
}

Push-Location $root
try {
  # --- version -------------------------------------------------------------------------------
  if (-not $Version) {
    $Version = ''   # '' = the default of internal/shared/version
    try {
      $exact = (git describe --tags --exact-match --match 'v*' 2>$null)
      if ($LASTEXITCODE -eq 0 -and $exact) { $Version = "$exact".Trim() }
      else {
        $last = (git describe --tags --abbrev=0 --match 'v*' 2>$null)
        if ($LASTEXITCODE -eq 0 -and $last) { $Version = "$last".Trim() + '-dev' }
      }
    } catch { Write-Host "git is not available; using internal/shared/version" }
    $global:LASTEXITCODE = 0
  }
  $msiVersion = (go run ./installer/windows/msiversion -build $BuildNumber $Version)
  if ($LASTEXITCODE -ne 0) { throw "cannot derive an MSI version from '$Version'" }
  $msiVersion = $msiVersion.Trim()
  $fileVersion = if ($Version) { $Version.TrimStart('v') } else { 'default' }
  Write-Host "Version '$Version' -> MSI ProductVersion $msiVersion"

  if (-not $Output) { $Output = Join-Path $PSScriptRoot "out\librepatch-agent-$($fileVersion -replace '[^0-9A-Za-z.+-]','_')-x64.msi" }
  $Output = [System.IO.Path]::GetFullPath($Output)
  New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null

  # --- toolchain -------------------------------------------------------------------------------
  Invoke-Tool 'dotnet tool restore' { dotnet tool restore }
  Invoke-Tool 'wix extension add' { dotnet wix --acceptEula $EulaId extension add -g $UtilExtension }

  # --- product name: one source of truth (internal/shared/brand), handed to WiX as defines ---------
  $brand = @{}
  Push-Location (Join-Path $PSScriptRoot '..\..')
  try { go run ./internal/shared/brand/gen -wix | ForEach-Object { $k, $v = $_ -split '=', 2; $brand[$k] = $v } } finally { Pop-Location }
  foreach ($k in 'ProductName', 'AgentName', 'Company', 'Slug', 'ServiceName', 'SetupFolder') { if (-not $brand[$k]) { throw "internal/shared/brand did not provide $k" } }
  $brandDefines = foreach ($k in $brand.Keys) { '-d'; "$k=$($brand[$k])" }

  # --- build -----------------------------------------------------------------------------------
  Invoke-Tool 'wix build' {
    dotnet wix --acceptEula $EulaId build `
      -arch x64 `
      -ext ($UtilExtension.Split('/')[0]) `
      -d "Version=$msiVersion" `
      -d "AgentExe=$AgentExe" `
      @brandDefines `
      -o $Output `
      (Join-Path $PSScriptRoot 'Package.wxs')
  }

  # --- ICE validation (needs Windows Installer; warnings are printed, errors fail the build) ---------
  if (-not $SkipValidate) {
    Invoke-Tool 'wix msi validate' { dotnet wix --acceptEula $EulaId msi validate $Output }
  }

  # --- signing hook (the release pipeline supplies the script; nothing secret lives in the repo) -----
  if ($SignScript) {
    & $SignScript $Output
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw "sign script failed with exit code $LASTEXITCODE" }
  }

  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash.ToLowerInvariant()
  Write-Host "Built $Output"
  Write-Host "sha256 $hash"
  $Output
}
finally { Pop-Location }
