# VM test matrix

The catalog marks a winget package **verified** only when it has passed this matrix
(`internal/server/catalog/matrix_results.json`). Everything else is *unverified* and
needs an explicit, audited confirmation to deploy (docs/ARCHITECTURE.md §7.9).

## What it checks

For each row in `matrix.json` on a clean Windows install with the agent enrolled:

1. import the package from winget-pkgs (metadata only),
2. deploy an **install** (machine or per-user scope) and wait for the job to succeed,
3. check the detection file exists,
4. deploy an **uninstall** (command derived from the machine's own registry entry),
5. check the file is gone.

## Target images

Windows 10 1809 and 22H2, Windows 11 23H2 and 24H2, Windows Server 2019, 2022 and 2025.
Use one snapshot per image and revert before every run. Rows that apply to user scope need
a signed-in standard user so the helper can start in their session.

## Running

Install the agent against a server you control, then on the VM:

```powershell
# totp.txt = the administrator's TOTP secret (shown once at setup)
$env:LIBREPATCH_ADMIN_PASSWORD = "..."
.\test\vm-matrix\run.ps1 -Url https://librepatch.lan -TotpFile C:\temp\totp.txt -Os win11-24h2
```

`results.json` gains one entry per passing row. Merge the entries from all images into
`internal/server/catalog/matrix_results.json`; a package counts as verified for a scope as
soon as one image passes (the OS is recorded so you can require more later).

## Status

This harness has **not yet been run on real VMs**; `matrix_results.json` is empty, so every
winget package is currently unverified. The `deploy` job in `.github/workflows/windows.yml`
runs the 7-Zip row on a GitHub runner as an informational check.
