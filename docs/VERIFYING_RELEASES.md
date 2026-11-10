# Verifying a LibrePatch release

This page is for customers and auditors: how to check that the files you downloaded are the ones the LibrePatch
release pipeline built, and what each check does and does not prove. The maintainers' side (keys, certificates, how
a release is cut) is in `docs/RUNBOOK.md`, section 9; the design is `docs/DECISIONS.md` D79-D84.

> **Status.** The pipeline (`.github/workflows/release.yml`) is written and its offline parts are tested, but **no
> release has been signed yet**: the vendor release key (open decision O7) and the code-signing certificate (O5) do
> not exist. Until the project announces both, there is nothing to verify against. The commands below are the ones
> the pipeline is built to satisfy; the parts that need GitHub, Sigstore or Windows have not been run end to end.
> Placeholders you must replace once published: the vendor public key (`<VENDOR_PUBKEY_HEX>`) and the Authenticode
> signer name (`<SIGNER_CN>`). Take both from the project's announcement and from your own records of earlier
> releases, **never from the release you are verifying**.

## What a release contains

| File | What it is |
|---|---|
| `librepatch-agent_<v>_windows_amd64.exe` | The agent. Authenticode-signed. |
| `librepatch-agent_<v>_windows_x64.msi` | The agent MSI (GPO, Intune, RMM). Carries the signed exe; itself Authenticode-signed. |
| `librepatch-agent_<v>_windows_amd64.lprel` | The **vendor release bundle**: manifest (hash, size, version, signer) + Ed25519 signature. This is what agents check when they update themselves. |
| `librepatch-server_<v>_linux_amd64` | The server binary (also inside the container image). |
| `librepatch-release_<v>_linux_amd64` | The release-signing tool (manifest, sign, verify). |
| `librepatch-web_<v>.tar.gz` | The web console bundle that is embedded in the server. |
| `*.cdx.json` | CycloneDX 1.5 SBOMs: one per binary, one for the web bundle, one for the container image. |
| `unsigned-SHA256SUMS` | Digests of the build **before** signing. Anyone can reproduce these (see the last section). |
| `BUILD-INFO.txt` | The inputs of the build: commit, `SOURCE_DATE_EPOCH`, toolchain versions, linker flags, compiled-in keys and signer names. |
| `SHA256SUMS` | Digests of every file above, after signing. |
| `SHA256SUMS.sigstore.json` | Cosign (Sigstore) keyless signature over `SHA256SUMS`. |
| `<artifact>.sbom.sigstore.json` | Cosign attestation that `<artifact>.cdx.json` is the SBOM of `<artifact>`. |

The container image is `ghcr.io/auzring1/librepatch-server@sha256:<digest>`; the digest is in `image-ref.txt`.

## All at once

```sh
scripts/verify-release.sh --dir ./release-v1.2.3 --repo auzring1/librepatch --tag v1.2.3 \
    --pub <VENDOR_PUBKEY_HEX> --authenticode-subject '<SIGNER_CN>'
```

Needs `sha256sum`, `jq`, [cosign](https://docs.sigstore.dev/) and the GitHub CLI `gh` (logged in). It prints one
PASS/WARN/FAIL line per check and exits 1 on any failure. The steps it performs are the sections below, so you can
also run them by hand. The script checks the vendor bundle with the `librepatch-release` binary from the same release
directory (after its digest has been verified); to be strict, build that tool yourself:
`go build ./cmd/librepatch-release` from the tagged source and pass `--release-tool`.

## 1. Checksums

```sh
sha256sum -c SHA256SUMS
```

This only proves the files match the list. The list is trustworthy only after step 2.

## 2. Who signed the checksums (cosign, keyless)

Releases are signed without a long-lived key: the GitHub Actions run proves its identity to Sigstore (OIDC), Sigstore
issues a short-lived certificate naming the workflow, and the signature is recorded in the public Rekor log.

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/auzring1/librepatch/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

What this proves: the file was signed by the `release.yml` workflow of `auzring1/librepatch` at tag `v1.2.3`. What it does
not prove: that the code at that tag is good (read the source or rely on step 7), or that a maintainer who can push
tags is honest. Protect yourself against a re-pointed tag by comparing the commit in `BUILD-INFO.txt` with what you
reviewed.

## 3. Build provenance (SLSA)

```sh
gh attestation verify librepatch-server_1.2.3_linux_amd64 \
  --repo auzring1/librepatch --signer-workflow auzring1/librepatch/.github/workflows/release.yml
```

Do this for each file you intend to run. The attestation says which workflow run, commit and runner built the file.
(`slsa-verifier` can also check these attestations; the GitHub CLI is the documented path.)

## 4. SBOMs

```sh
for f in *.cdx.json; do jq -e '.bomFormat=="CycloneDX" and .specVersion=="1.5"' "$f" >/dev/null && echo "$f ok"; done

cosign verify-blob-attestation --bundle librepatch-server_1.2.3_linux_amd64.sbom.sigstore.json --type cyclonedx \
  --certificate-identity "https://github.com/auzring1/librepatch/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  librepatch-server_1.2.3_linux_amd64
```

How to read them:

- Go SBOMs list the modules the linker actually compiled into that binary (read from the binary's embedded build
  information), plus the Go standard library at the toolchain's version. Each module has a `purl` and, from
  `go.sum`, a hash. That hash is the Go module "dirhash" (`h1:`) decoded to hex, a SHA-256 over the module's file
  digests, **not** the digest of a download archive; the property `librepatch:hash-kind` says so.
- The dependency graph is flat (every module hangs off the product); the module-level graph is not recorded.
- The web SBOM lists the production closure of `web/package-lock.json` with the SHA-512 `integrity` digests npm uses
  and the license each package declares. Development tools are excluded because they are not shipped.
- SBOMs are deterministic (the timestamp is the commit time), so they take part in the reproducibility check.
- Licenses are not listed for Go modules; see `THIRD_PARTY_NOTICES.md`.

## 5. The container image

```sh
IMG=ghcr.io/auzring1/librepatch-server@sha256:<digest from image-ref.txt>
cosign verify "$IMG" \
  --certificate-identity "https://github.com/auzring1/librepatch/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation "$IMG" --type cyclonedx \
  --certificate-identity "https://github.com/auzring1/librepatch/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$IMG" --repo auzring1/librepatch
```

Always run the image **by digest**, never by tag (a tag can be moved; the signature belongs to the digest).
`deploy/docker-compose.yml` uses `librepatch/server:${LIBREPATCH_VERSION}` for local builds; for a verified deployment, pull the
digest above and point `image:` at it. The base images in `deploy/Dockerfile.server` are pinned by digest.

## 6. Authenticode (the Windows files)

The agent exe and the MSI carry an Authenticode signature with an RFC 3161 timestamp. On Windows:

```powershell
Get-AuthenticodeSignature .\librepatch-agent_1.2.3_windows_amd64.exe |
  Format-List Status, @{n='Signer CN';e={$_.SignerCertificate.GetNameInfo('SimpleName',$false)}}, TimeStamperCertificate
signtool verify /pa /v .\librepatch-agent_1.2.3_windows_x64.msi
```

`Status` must be `Valid`, the signer CN must equal `<SIGNER_CN>` exactly as announced, and a timestamp must be present.
This is the same name the agent compares when it updates itself (the simple display name, i.e. the certificate CN).
The pipeline verifies it before the file is published (`scripts/authenticode.ps1 -Action Verify`). The signature is
not part of the cosign/SHA256 story in a way you can reproduce: Authenticode adds a certificate blob and a timestamp
to the file, so the signed file's SHA-256 differs from the one in `unsigned-SHA256SUMS` (section 8).

## 7. How the agent verifies its own updates

You do not have to trust the LibrePatch server you run for agent updates to be safe. The agent installs a new version
only if **all** of these hold (docs/DECISIONS.md D68, D83; `internal/shared/release`, `internal/agent/jobs/selfupdate.go`):

1. The **vendor release bundle** (`.lprel`) carries an Ed25519 signature that verifies under a vendor public key compiled
   into the agent. A build with no key refuses every update. The signature is domain-separated
   (`librepatch/release/v1\0`) and the manifest is parsed strictly.
2. The manifest names this platform, a version that is newer (or an explicitly allowed rollback), and the binary's
   SHA-256 and size; the downloaded file is hashed while downloading and again from a locked handle.
3. The binary has a valid **Authenticode** signature whose signer CN equals the manifest's pinned subject, **and** that
   subject is one of the signer names compiled into the agent. The second half matters: it means a stolen release key
   alone cannot pin an attacker's own certificate.
4. The staged binary reports the promised version before the service is pointed at it; the new version must connect
   within 10 minutes or the old one is restored.

To check a bundle yourself with a key you trust:

```sh
librepatch-release verify --bundle librepatch-agent_1.2.3_windows_amd64.lprel \
    --exe librepatch-agent_1.2.3_windows_amd64.exe --pub vendor.pub    # vendor.pub holds <VENDOR_PUBKEY_HEX>
```

The vendor public key(s) are also in the tagged source at `release/release-public-keys.txt` and in `BUILD-INFO.txt`;
those tell you what the release *claims*. Compare with the fingerprint the project announced out of band.

## 8. Reproducing a build

The Go binaries, the web bundle and the SBOMs are built reproducibly: the same commit built twice, in different
directories, with different time zones, umasks and build caches, gives byte-identical files (`scripts/verify-reproducible.sh`
checks exactly that). To reproduce a release:

```sh
git clone https://github.com/auzring1/librepatch && cd current && git checkout v1.2.3
cat BUILD-INFO.txt                      # from the release: Go version, Node major, keys, signer names
export GOTOOLCHAIN=go1.27.1             # the version BUILD-INFO.txt names
scripts/build-release.sh --version 1.2.3 \
    --release-pubkeys <the release_public_keys line of BUILD-INFO.txt> \
    --authenticode-subjects '<the authenticode_subjects line>' --out /tmp/rebuild
diff /tmp/rebuild/unsigned-SHA256SUMS ./unsigned-SHA256SUMS    # must print nothing
```

Requirements: Linux, bash, git, Go at exactly the version in `go.mod`'s `toolchain` line, Node 22.x with npm (the
lockfile is installed with `npm ci --ignore-scripts`), GNU tar and gzip. `--require-authenticode` defaults to `true`.

What is **not** covered, honestly:

- The **signed** agent exe and the MSI are not reproducible byte for byte: Authenticode adds a signature and a timestamp.
  `unsigned-SHA256SUMS` lists the digest of the exe *before* signing. Comparing it with the signed file needs the PE
  "Authenticode digest" (the hash that excludes the certificate table); the repository does not ship a tool for that yet.
  The MSI is built on Windows with WiX and is not part of the reproducibility check.
- The **container image** is built with BuildKit's `rewrite-timestamp`, and the server binary inside is built with the same flags
  as the standalone one (the release workflow fails if they differ), but whole-image digest reproducibility has not been verified.
- Reproducibility was checked on one Linux amd64 host; other tar/gzip builds could compress differently.

## What none of this proves

A valid chain says the files came from the pipeline of this repository at that tag. It does not say the source is free of
bugs or that no maintainer account was compromised. It narrows the places an attacker has to be: GitHub's protected
`release` environment, the code-signing service and the release-key KMS must all be subverted to ship a malicious update,
and a malicious *server* cannot do it at all.
