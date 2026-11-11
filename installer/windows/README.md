# LibrePatch Agent MSI

A thin WiX v7 wrapper around `librepatch-agent.exe install` / `uninstall` (O6, D67).
Usage for administrators (properties, GPO, Intune, RMM, exit codes): docs/RUNBOOK.md section 4.
Security notes and gaps: docs/THREAT-MODEL.md section 9d.b.

| File | Purpose |
|---|---|
| `Package.wxs` | The package: properties, launch conditions, staged exe, three custom actions, sequencing |
| `Validation.wxi` | Character deny lists for `SERVER`, `TOKEN`, `ALLOWEDJOBS` (included by `Package.wxs`) |
| `build.ps1` | Windows build: version, `wix build`, ICE validation, optional signing hook |
| `msiversion/` | Maps a git tag or `internal/shared/version` to the numeric `a.b.c.d` ProductVersion |
| `package_test.go` | Linux-runnable checks of the sources (`go test ./installer/...`) |
| `../../scripts/build-msi.sh` | `lint`: WiX compile and link of `Package.wxs` on Linux (cannot build the MSI) |
| `../../.config/dotnet-tools.json` | Pins the WiX tool (7.0.0) |

## Build (Windows, PowerShell 7, .NET SDK 8+, Go)

```powershell
go build -trimpath -ldflags "-s -w -X github.com/auzring1/librepatch/internal/shared/version.Version=1.0.0" -o librepatch-agent.exe ./cmd/librepatch-agent
# release pipeline: sign the exe BEFORE it goes into the MSI
#   signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 <your cert selection options> librepatch-agent.exe
./installer/windows/build.ps1 -AgentExe .\librepatch-agent.exe -Version 1.0.0
```

The version comes from `-Version`, else the exact `v*` git tag on HEAD, else the latest tag plus `-dev`, else
`internal/shared/version`. The MSI ProductVersion is `major.minor.patch.0` for releases and
`major.minor.patch.<BuildNumber>` for pre-releases. Windows Installer ignores the fourth field when it decides
about upgrades, so two builds of the same `a.b.c` are "the same version" (the package allows same-version
upgrades; bump the patch number for real releases). Limits: 255.255.65535.

### Signing

`build.ps1` never reads a certificate. Pass `-SignScript <script>` and the script is called with the MSI path after
the build and validation, or run `signtool` on the MSI afterwards:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.example/ /td SHA256 /sha1 <thumbprint-from-your-HSM-or-store> librepatch-agent-1.0.0-x64.msi
signtool verify /pa librepatch-agent-1.0.0-x64.msi
```

The certificate or the HSM/KMS signing service belongs to the protected release environment (T-REL-3), not to this repository.

## WiX 7 and the EULA

`.config/dotnet-tools.json` pins the `wix` .NET tool to 7.0.0 (`dotnet tool restore`); `build.ps1` and
`scripts/build-msi.sh` pin the Util extension to the same version (`WixToolset.Util.wixext/7.0.0`, a test checks both).
WiX v7 binaries are released under the **Open Source Maintenance Fee (OSMF) EULA**
(`requireLicenseAcceptance` in the NuGet package; the text is in `~/.nuget/packages/wix/7.0.0/OSMFEULA.txt`).
Verified by reading that text: the fee applies to users who use WiX in revenue-generating activities with annual gross
revenue of US$10,000 or more, unless they pay the maintainers for support; the source stays under MS-RL and you may compile it yourself.
Accepting is a legal act of the project owner. This repository records it in the build scripts as `--acceptEula wix7`
(a per-invocation flag; no acceptance file is written; `wix eula accept wix7` is the interactive alternative that writes
`~/.wix/wix7-osmf-eula.txt`). Remove the flag if the owner has not decided. These command-line forms were confirmed against the
7.0.0 tool here; the docs sites (wixtoolset.org, docs.firegiant.com) were not reachable from the sandbox, so nothing else
about v7 behavior was read from the official documentation.

## What was and was not verified (authoring sandbox, Linux)

Verified: `dotnet tool restore` of wix 7.0.0; WiX compile and link of `Package.wxs` (schema, references, sequencing) via
`scripts/build-msi.sh lint`; `go test ./installer/...`.
Not verified: producing the MSI (the WiX binder needs `msi.dll`; the compiler on Linux also rejects relative directory
names, which is why `LinuxLint` swaps the directory declaration), ICE validation, and every runtime behavior. The CI job `msi`
(`.github/workflows/windows.yml`) is the verification path.
