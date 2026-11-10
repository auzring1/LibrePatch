#Requires -Version 7.0
<#
.SYNOPSIS
  Authenticode helper for the release pipeline (.github/workflows/release.yml, docs/DECISIONS.md D79, D82).

.DESCRIPTION
  -Action Sign    signs files with signtool.exe. Used by the "signtool" provider (a code-signing certificate whose
                  private key lives in a cloud HSM / key service with a CSP or KSP, or a hardware token on a
                  self-hosted runner). The Azure Artifact Signing (formerly Trusted Signing) provider does not use
                  this: the workflow calls Azure's own action for it.
                  Everything provider-specific is passed in the environment, never in the repository:
                    LIBREPATCH_SIGNTOOL_ARGS   certificate selection arguments, e.g.
                                        /csp "<KSP name>" /kc "<key container>" /f "<public cert .cer>"
                                        (a repository variable; it holds names, not secrets)
                    plus whatever the KSP reads from the environment (secrets, set by the workflow step)
  -Action Verify  checks that each file has a valid, timestamped Authenticode signature and that the signer's
                  simple display name (the CN; this is exactly what the agent compares, see
                  internal/agent/jobs/platform_windows.go, CERT_NAME_SIMPLE_DISPLAY_TYPE) equals -Subject.
                  The same value must be pinned into the vendor release manifest (librepatch-release manifest
                  --authenticode-subject), otherwise agents will refuse the update.

  Not exercised in the authoring sandbox (Linux, no signtool, no certificate). Reviewed against the
  signtool documented syntax only.

.PARAMETER Files
  Files to sign or verify (.exe, .msi).
.PARAMETER Subject
  Expected signer CN (Verify) - mandatory for Verify.
.PARAMETER TimestampUrl
  RFC 3161 timestamp server (Sign). Default: the Microsoft Artifact Signing one.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Sign', 'Verify')][string]$Action,
  [Parameter(Mandatory)][string[]]$Files,
  [string]$Subject,
  [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-SignTool {
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $found = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
  if (-not $found) { throw 'signtool.exe not found (install the Windows SDK or use the runner image that has it)' }
  return $found.FullName
}

foreach ($f in $Files) {
  if (-not (Test-Path -LiteralPath $f)) { throw "file not found: $f" }
}

switch ($Action) {
  'Sign' {
    if (-not $env:LIBREPATCH_SIGNTOOL_ARGS) { throw 'LIBREPATCH_SIGNTOOL_ARGS is not set (certificate selection arguments for signtool)' }
    $signtool = Find-SignTool
    # Split the variable like a command line; it contains names and paths, not secrets.
    $selection = [System.Management.Automation.PSParser]::Tokenize($env:LIBREPATCH_SIGNTOOL_ARGS, [ref]$null) |
      Where-Object { $_.Type -in 'CommandArgument', 'String', 'CommandParameter' } | ForEach-Object { $_.Content }
    foreach ($f in $Files) {
      Write-Host "signing $f"
      & $signtool sign /fd SHA256 /tr $TimestampUrl /td SHA256 @selection $f
      if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE) for $f" }
    }
  }
  'Verify' {
    if (-not $Subject) { throw '-Subject is required for Verify' }
    foreach ($f in $Files) {
      $sig = Get-AuthenticodeSignature -LiteralPath $f
      if ($sig.Status -ne 'Valid') { throw "$f : Authenticode status is $($sig.Status): $($sig.StatusMessage)" }
      if (-not $sig.TimeStamperCertificate) { throw "$f : signature has no trusted timestamp (it would expire with the certificate)" }
      $cn = $sig.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
      if ($cn -ne $Subject) { throw "$f : signer is '$cn', expected '$Subject'" }
      Write-Host "OK $f signed by '$cn', thumbprint $($sig.SignerCertificate.Thumbprint), timestamp by '$($sig.TimeStamperCertificate.Subject)'"
    }
  }
}
