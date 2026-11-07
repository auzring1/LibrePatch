#!/usr/bin/env bash
# Rehearses the release pipeline locally with THROW-AWAY keys. Output goes to dist-release/dryrun/ (git-ignored).
#
#   scripts/release-dryrun.sh [--version 0.0.0-dryrun] [--with-repro] [--with-image] [--clean]
#
# Exercised here, for real:
#   build-release.sh (reproducible build, web bundle, SBOMs)  ->  release-checksums.sh  ->  throw-away Ed25519 key
#   -> librepatch-release manifest / tosign -> the KMS contract (release-kms.sh with the dryrun provider AND with the
#   aws provider against a fake `aws` command) -> attach (refuses a wrong key) -> verify (and a tampered binary
#   is refused) -> one-step `sign` produces the identical bundle -> verify-release.sh on the assembled directory
#   -> check-actions-pinned.sh and workflow YAML parse.
# Optional: --with-repro (builds twice in different directories and compares; about 3 minutes),
#           --with-image (OCI image build; needs a running Docker daemon).
# NOT exercised (needs infrastructure this script cannot fake): Authenticode (signtool / Azure Artifact Signing),
# the real KMS, cosign keyless signing (needs a GitHub OIDC token), GitHub attestations, the MSI (needs Windows + WiX),
# registry push. The agent exe is copied unchanged where the pipeline would Authenticode-sign it.
#
# Nothing here is a real release: the keys are generated into dist-release/dryrun/keys/ and the compiled-in public
# key is the throw-away one, so these agents would not trust a real release and vice versa.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

version=0.0.0-dryrun with_repro=0 with_image=0 clean=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=${2:?}; shift 2 ;;
    --with-repro) with_repro=1; shift ;;
    --with-image) with_image=1; shift ;;
    --clean) clean=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

D=$ROOT/dist-release/dryrun
if [ -e "$D" ]; then
  [ "$clean" = 1 ] || { echo "$D exists; pass --clean to remove it" >&2; exit 2; }
  rm -rf "$D"
fi
mkdir -p "$D/keys" "$D/bin"
step() { printf '\n== %s\n' "$*"; }
exercised=() skipped=()
pass() { exercised+=("$1"); echo "ok: $1"; }

# --- 1. throw-away key -------------------------------------------------------------------------------
step "throw-away vendor release key"
go build -o "$D/bin/librepatch-release" ./cmd/librepatch-release
rel=$D/bin/librepatch-release
"$rel" keygen --out "$D/keys/release.key" >/dev/null
pub=$(tr -d '[:space:]' <"$D/keys/release.pub")
"$rel" keygen --out "$D/keys/other.key" >/dev/null     # a second key, used for negative tests
pass "key generation (Ed25519, private key mode 0600 in $D/keys, never committed)"

# --- 2. reproducible build --------------------------------------------------------------------------
step "build-release.sh"
dirty=()
if [ -n "$(git status --porcelain)" ]; then
  echo "note: the working tree is dirty; building with --allow-dirty (a real release never does)"
  dirty=(--allow-dirty)
fi
scripts/build-release.sh --version "$version" --release-pubkeys "$pub" --authenticode-subjects "LibrePatch Dry Run" --out "$D/out" ${dirty[@]+"${dirty[@]}"} >"$D/build.log" 2>&1 || { tail -30 "$D/build.log"; exit 1; }
tail -n +1 "$D/out/unsigned-SHA256SUMS" | sed 's/^/   /'
pass "reproducible build: agent (windows/amd64), server, librepatch-release, web bundle, SBOMs"
v=${version#v}
agent=$D/out/librepatch-agent_${v}_windows_amd64.exe

# --- 3. SBOM validation --------------------------------------------------------------------------------
step "SBOM shape"
go build -o "$D/bin/librepatch-sbom" ./cmd/librepatch-sbom
"$D/bin/librepatch-sbom" check "$D"/out/*.cdx.json >/dev/null
pass "all $(ls "$D"/out/*.cdx.json | wc -l) SBOMs are well-formed CycloneDX 1.5"

# --- 4. "Authenticode" placeholder + vendor manifest through the KMS contract ----------------------------
step "vendor release manifest through the KMS contract"
signed=$D/signed
mkdir -p "$signed"
cp "$agent" "$signed/"
echo "   (Authenticode and the MSI are NOT done here: the agent is copied unchanged)"
sde=$(git log -1 --format=%ct)
w=$D/manifest
mkdir -p "$w"
"$rel" manifest --exe "$signed/$(basename "$agent")" --version "$v" --os windows --arch amd64 \
  --authenticode-subject "LibrePatch Dry Run" --released-at "$sde" --out "$w/manifest.json" >/dev/null
"$rel" tosign --manifest "$w/manifest.json" --out "$w/tosign.bin" >/dev/null

# 4a. dryrun provider
LIBREPATCH_DRYRUN_KEY=$D/keys/release.key LIBREPATCH_RELEASE_BIN=$rel scripts/release-kms.sh dryrun sign --in "$w/tosign.bin" --out "$w/sig-dryrun.bin" >/dev/null
pass "release-kms.sh dryrun provider signed the manifest bytes"

# 4b. aws provider against a fake `aws` (checks our argument handling, base64 and SPKI parsing; NOT AWS)
cat >"$D/bin/aws" <<'FAKE'
#!/usr/bin/env bash
# Minimal fake of `aws kms sign|get-public-key` for rehearsal. It signs with the throw-away key.
set -euo pipefail
[ "$1 $2" = "kms sign" ] || [ "$1 $2" = "kms get-public-key" ] || { echo "fake aws: unsupported: $*" >&2; exit 2; }
sub=$2; shift 2
msg="" alg="" mtype=""
while [ $# -gt 0 ]; do
  case "$1" in
    --message) msg=${2#fileb://}; shift 2 ;;
    --signing-algorithm) alg=$2; shift 2 ;;
    --message-type) mtype=$2; shift 2 ;;
    --key-id|--output) shift 2 ;;
    *) shift ;;
  esac
done
if [ "$sub" = sign ]; then
  [ "$alg" = ED25519_SHA_512 ] && [ "$mtype" = RAW ] || { echo "fake aws: wrong algorithm/message type" >&2; exit 2; }
  "$LIBREPATCH_RELEASE_BIN" sign-bytes --key "$FAKE_KEY" --in "$msg" --out "$FAKE_TMP/sig" >/dev/null
  printf '{"KeyId":"fake","SigningAlgorithm":"ED25519_SHA_512","Signature":"%s"}\n' "$(base64 -w0 <"$FAKE_TMP/sig")"
else
  spki="302a300506032b6570032100$(tr -d '[:space:]' <"${FAKE_KEY%.key}.pub")"
  printf '{"KeyId":"fake","PublicKey":"%s"}\n' "$(printf '%b' "$(printf '%s' "$spki" | sed 's/../\\x&/g')" | base64 -w0)"
fi
FAKE
chmod +x "$D/bin/aws"
mkdir -p "$D/faketmp"
PATH="$D/bin:$PATH" FAKE_KEY=$D/keys/release.key FAKE_TMP=$D/faketmp LIBREPATCH_RELEASE_BIN=$rel LIBREPATCH_RELEASE_KMS_KEY_ID=alias/fake \
  scripts/release-kms.sh aws sign --in "$w/tosign.bin" --out "$w/sig-aws.bin" >/dev/null
cmp "$w/sig-dryrun.bin" "$w/sig-aws.bin"
fakepub=$(PATH="$D/bin:$PATH" FAKE_KEY=$D/keys/release.key LIBREPATCH_RELEASE_KMS_KEY_ID=alias/fake scripts/release-kms.sh aws pubkey)
[ "$fakepub" = "$pub" ] || { echo "aws pubkey parsing returned $fakepub, want $pub" >&2; exit 1; }
pass "release-kms.sh aws provider (against a fake aws CLI): same Ed25519 signature, SPKI parsed to the compiled-in key"

# 4c. attach / verify / negative tests
"$rel" attach --manifest "$w/manifest.json" --signature "$w/sig-aws.bin" --pub "$pub" --out "$w/librepatch-agent_${v}_windows_amd64.lprel" >/dev/null
if "$rel" attach --manifest "$w/manifest.json" --signature "$w/sig-aws.bin" --pub "$D/keys/other.pub" --out "$w/wrong.lprel" >/dev/null 2>&1; then
  echo "attach accepted a signature from the wrong key" >&2; exit 1
fi
pass "attach refuses a signature that does not verify under the given key"
# The release build compiles the allowed Authenticode signer into the tools (and agent/server): a manifest pinning
# any other signer is refused even though its signature would be valid (a stolen release key is not enough, D83).
built=$D/out/librepatch-release_${v}_linux_amd64
chmod +x "$built"
if "$built" manifest --exe "$signed/$(basename "$agent")" --version "$v" --authenticode-subject "Evil Corp" --out "$w/evil.json" >/dev/null 2>&1; then
  echo "the release build accepted a manifest pinning a foreign signer" >&2; exit 1
fi
"$built" manifest --exe "$signed/$(basename "$agent")" --version "$v" --authenticode-subject "LibrePatch Dry Run" --out "$w/good.json" >/dev/null
pass "a manifest pinning a signer that is not compiled in is refused by the release build"
echo "$pub" >"$w/pub.hex"
"$rel" verify --bundle "$w/librepatch-agent_${v}_windows_amd64.lprel" --exe "$signed/$(basename "$agent")" --pub "$w/pub.hex" >/dev/null
cp "$signed/$(basename "$agent")" "$w/tampered.exe"
printf 'X' >>"$w/tampered.exe"
if "$rel" verify --bundle "$w/librepatch-agent_${v}_windows_amd64.lprel" --exe "$w/tampered.exe" --pub "$w/pub.hex" >/dev/null 2>&1; then
  echo "verify accepted a tampered binary" >&2; exit 1
fi
pass "self-update manifest round trip: manifest -> tosign -> KMS signature -> attach -> verify; a tampered binary is refused"
"$rel" sign --key "$D/keys/release.key" --exe "$signed/$(basename "$agent")" --version "$v" --os windows --arch amd64 \
  --authenticode-subject "LibrePatch Dry Run" --released-at "$sde" --out "$w/direct.lprel" >/dev/null
cmp "$w/direct.lprel" "$w/librepatch-agent_${v}_windows_amd64.lprel"
pass "the external-signer path and one-step 'sign' produce byte-identical bundles"

# --- 5. final directory + verify-release ------------------------------------------------------------
step "assemble and verify the release directory"
final=$D/final
mkdir -p "$final"
cp "$D"/out/* "$final/"
cp "$signed"/* "$final/"
cp "$w/librepatch-agent_${v}_windows_amd64.lprel" "$final/"
scripts/release-checksums.sh "$final" >/dev/null
scripts/verify-release.sh --dir "$final" --skip-cosign --skip-attestations --pub "$pub" | sed 's/^/   /'
pass "verify-release.sh: SHA256SUMS, vendor bundle, SBOM shape"
# Same sanity check the workflow runs: apart from the (here unchanged) agent, nothing differs from the build.
(cd "$final" && grep -v "  librepatch-agent_${v}_windows_amd64.exe\$" unsigned-SHA256SUMS | sha256sum -c - >/dev/null)
pass "everything except the signed agent still equals the reproducible build"

# --- 6. static checks of the pipeline definition ---------------------------------------------------------
step "pipeline definition"
scripts/check-actions-pinned.sh
pass "all GitHub Actions are pinned to full commit SHAs"
if command -v python3 >/dev/null && python3 -I -c 'import yaml' 2>/dev/null; then
  python3 -I -c 'import sys, yaml
for f in sys.argv[1:]:
    yaml.safe_load(open(f))' .github/workflows/*.yml
  pass "workflow YAML parses"
else
  skipped+=("workflow YAML parse (python3 yaml not installed)")
fi
for s in scripts/*.sh; do bash -n "$s"; done
pass "bash -n on every script"
if command -v shellcheck >/dev/null; then
  shellcheck -S warning scripts/build-release.sh scripts/build-image.sh scripts/verify-reproducible.sh scripts/release-dryrun.sh scripts/verify-release.sh scripts/release-kms.sh scripts/check-actions-pinned.sh scripts/release-checksums.sh
  pass "shellcheck"
else
  skipped+=("shellcheck (not installed)")
fi

# --- 7. optional ----------------------------------------------------------------------------------------
if [ "$with_repro" = 1 ]; then
  step "verify-reproducible.sh (two builds, different paths)"
  scripts/verify-reproducible.sh --version "$v"
  pass "two independent builds are byte-identical"
else
  skipped+=("verify-reproducible.sh (slow; pass --with-repro)")
fi
if [ "$with_image" = 1 ]; then
  step "container image (OCI archive)"
  if docker info >/dev/null 2>&1; then
    LIBREPATCH_RELEASE_PUBKEYS=$pub scripts/build-image.sh --version "$v" --commit "$(git rev-parse --short=12 HEAD)" --source-date-epoch "$sde" \
      --require-authenticode true --authenticode-subjects "LibrePatch Dry Run" --oci-out "$D/server-image.oci.tar" --digest-file "$D/image-digest.txt"
    pass "image builds from deploy/Dockerfile.server; digest $(cat "$D/image-digest.txt")"
  else
    skipped+=("image build (no Docker daemon)")
  fi
else
  skipped+=("image build (pass --with-image; needs a Docker daemon)")
fi
skipped+=("Authenticode signing and verification (needs signtool + a certificate or Azure Artifact Signing)"
          "MSI build (needs Windows + WiX)"
          "real KMS signing (needs AWS KMS / Key Vault + OIDC)"
          "cosign keyless signing, SBOM attestations, GitHub build provenance (need a GitHub OIDC token)"
          "registry push")

printf '\n==== dry run summary ====\nExercised:\n'
printf '  + %s\n' "${exercised[@]}"
printf 'Not exercised:\n'
printf '  - %s\n' "${skipped[@]}"
echo "Output: $D"
