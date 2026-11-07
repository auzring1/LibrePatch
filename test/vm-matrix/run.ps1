<#
.SYNOPSIS
  Runs the software-deployment VM matrix on THIS Windows machine, which must already have
  the LibrePatch agent installed and enrolled against the server named by -Url.

.DESCRIPTION
  For every package in matrix.json: import it from winget-pkgs, deploy an install, check the
  detection file exists, deploy an uninstall, check the file is gone. Passing runs are appended
  to results.json in the format of internal/server/catalog/matrix_results.json; copy that file
  over matrix_results.json and rebuild to mark the packages "verified".

  Use a throwaway VM snapshot per OS (Windows 10 1809/22H2, Windows 11 23H2/24H2, Server 2019/2022/2025)
  and revert between rows. See test/vm-matrix/README.md.

.EXAMPLE
  .\run.ps1 -Url https://librepatch.lan -TotpFile C:\temp\totp.txt -Os win11-24h2
#>
param(
  [Parameter(Mandatory)] [string] $Url,
  [Parameter(Mandatory)] [string] $TotpFile,
  [Parameter(Mandatory)] [string] $Os,
  [string] $Email = "admin@example.com",
  [string] $Password = $env:LIBREPATCH_ADMIN_PASSWORD,
  [string] $Matrix = "$PSScriptRoot\matrix.json",
  [string] $Results = "$PSScriptRoot\results.json",
  [string] $Only = ""
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$tool = Join-Path $env:TEMP "deploycheck.exe"
Push-Location $root
try { go build -o $tool ./test/tools/deploycheck } finally { Pop-Location }
$rows = (Get-Content $Matrix -Raw | ConvertFrom-Json).packages
$failed = @()
foreach ($r in $rows) {
  if ($Only -and $r.identifier -ne $Only) { continue }
  $detect = [Environment]::ExpandEnvironmentVariables($r.detect_file)
  Write-Host "=== $($r.identifier) ($($r.scope)) on $Os"
  & $tool -url $Url -email $Email -password $Password -totp-file $TotpFile -scenario winget `
    -package $r.identifier -scope $r.scope -detect-file $detect -os $Os -json-out $Results
  if ($LASTEXITCODE -ne 0) { $failed += "$($r.identifier)/$($r.scope)" }
}
if ($failed.Count) { Write-Host "FAILED: $($failed -join ', ')"; exit 1 }
Write-Host "All rows passed; results in $Results"
