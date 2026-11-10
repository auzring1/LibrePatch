#!/usr/bin/env bash
# The KMS signing contract for the vendor release manifest (docs/DECISIONS.md D68, D81; docs/RUNBOOK.md).
#
#   scripts/release-kms.sh <provider> sign   --in tosign.bin --out sig.bin
#   scripts/release-kms.sh <provider> pubkey [--out public.hex]
#
# Contract
#   input   tosign.bin from `librepatch-release tosign`: "librepatch/release/v1\0" + the manifest bytes.
#   output  sig.bin: the raw 64-byte Ed25519 (RFC 8032, PureEdDSA, no pre-hash) signature over those exact bytes.
#   The private key never leaves the KMS/HSM. The caller (release.yml) authenticates to the cloud with OIDC
#   (no stored cloud credentials), then runs `librepatch-release attach` and `librepatch-release verify` against the
#   public key committed in release/release-public-keys.txt, so a wrong key or a bad signature fails the release.
#
# Providers (set LIBREPATCH_KMS_PROVIDER in the repository variables; you need exactly one)
#   aws     AWS KMS asymmetric key, key spec ECC_NIST_EDWARDS25519, algorithm ED25519_SHA_512 (message type RAW,
#           max 4096 bytes: a manifest is well under 1 KiB). Env: LIBREPATCH_RELEASE_KMS_KEY_ID (key id, ARN or alias);
#           region/credentials come from the environment (aws-actions/configure-aws-credentials with a role).
#   azure   Azure Key Vault / Managed HSM key. Env: LIBREPATCH_AKV_VAULT, LIBREPATCH_AKV_KEY [, LIBREPATCH_AKV_KEY_VERSION]; az must be
#           logged in (azure/login with OIDC). CAVEAT: this hook assumes the vault can hold an Ed25519 (OKP) key and
#           sign with algorithm EdDSA. We could not confirm that Azure offers this (as of writing it does not for
#           Key Vault, to our knowledge); if the service refuses, use the aws provider or another KMS/HSM. Unverified.
#   dryrun  throw-away key file (LIBREPATCH_DRYRUN_KEY) signed with `librepatch-release sign-bytes` (LIBREPATCH_RELEASE_BIN). NEVER for
#           a real release; the workflow uses it only when dry_run is true.
#
# Adding a provider (GCP KMS, a PKCS#11 HSM, Vault transit ...) means one more function pair below with the same
# contract; nothing else in the pipeline changes.
set -euo pipefail

die() { echo "release-kms: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: release-kms.sh <aws|azure|dryrun> <sign|pubkey> [--in F] [--out F]"
provider=$1 action=$2; shift 2
in="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --in) in=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done

b64url_decode() { # stdin: base64url without padding -> raw bytes
  local s
  s=$(tr '_-' '/+' | tr -d '\n')
  while [ $(( ${#s} % 4 )) -ne 0 ]; do s="${s}="; done
  printf '%s' "$s" | base64 -d
}
hex() { od -An -v -tx1 | tr -d ' \n'; }

check_sig() { # file
  [ "$(wc -c <"$1")" -eq 64 ] || die "the KMS did not return a 64-byte Ed25519 signature"
}

need() { command -v "$1" >/dev/null || die "$1 is required for provider $provider"; }

# ---- aws ----------------------------------------------------------------------------------------
aws_sign() {
  need aws; need jq
  : "${LIBREPATCH_RELEASE_KMS_KEY_ID:?set LIBREPATCH_RELEASE_KMS_KEY_ID}"
  [ "$(wc -c <"$in")" -le 4096 ] || die "message is over the 4096-byte AWS KMS RAW limit"
  aws kms sign --key-id "$LIBREPATCH_RELEASE_KMS_KEY_ID" --message "fileb://$in" --message-type RAW \
      --signing-algorithm ED25519_SHA_512 --output json | jq -er .Signature | base64 -d >"$out"
}
aws_pubkey() {
  need aws; need jq
  : "${LIBREPATCH_RELEASE_KMS_KEY_ID:?set LIBREPATCH_RELEASE_KMS_KEY_ID}"
  local spki
  spki=$(aws kms get-public-key --key-id "$LIBREPATCH_RELEASE_KMS_KEY_ID" --output json | jq -er .PublicKey | base64 -d | hex)
  # SubjectPublicKeyInfo of an Ed25519 key: fixed 12-byte header, then the 32-byte key.
  [[ $spki =~ ^302a300506032b6570032100([0-9a-f]{64})$ ]] || die "the KMS key is not an Ed25519 key (SPKI: ${spki:0:40}...)"
  echo "${BASH_REMATCH[1]}"
}

# ---- azure --------------------------------------------------------------------------------------
akv_args() {
  : "${LIBREPATCH_AKV_VAULT:?set LIBREPATCH_AKV_VAULT}"; : "${LIBREPATCH_AKV_KEY:?set LIBREPATCH_AKV_KEY}"
  akv=(--vault-name "$LIBREPATCH_AKV_VAULT" --name "$LIBREPATCH_AKV_KEY")
  if [ -n "${LIBREPATCH_AKV_KEY_VERSION:-}" ]; then akv+=(--version "$LIBREPATCH_AKV_KEY_VERSION"); fi
}
azure_sign() {
  need az; need jq
  akv_args
  # Key Vault sign takes the value to sign base64-encoded; for EdDSA this would be the message itself.
  az keyvault key sign "${akv[@]}" --algorithm EdDSA --digest "$(base64 -w0 <"$in")" --query signature -o tsv | b64url_decode >"$out"
}
azure_pubkey() {
  need az; need jq
  akv_args
  local crv x
  crv=$(az keyvault key show "${akv[@]}" --query key.crv -o tsv)
  [ "$crv" = "Ed25519" ] || die "the Key Vault key curve is '$crv', not Ed25519"
  x=$(az keyvault key show "${akv[@]}" --query key.x -o tsv | b64url_decode | hex)
  [[ $x =~ ^[0-9a-f]{64}$ ]] || die "unexpected public key length"
  echo "$x"
}

# ---- dryrun -------------------------------------------------------------------------------------
dryrun_sign() {
  : "${LIBREPATCH_DRYRUN_KEY:?set LIBREPATCH_DRYRUN_KEY}"; : "${LIBREPATCH_RELEASE_BIN:?set LIBREPATCH_RELEASE_BIN}"
  "$LIBREPATCH_RELEASE_BIN" sign-bytes --key "$LIBREPATCH_DRYRUN_KEY" --in "$in" --out "$out"
}
dryrun_pubkey() {
  : "${LIBREPATCH_DRYRUN_KEY:?set LIBREPATCH_DRYRUN_KEY}"
  tr -d '[:space:]' <"${LIBREPATCH_DRYRUN_KEY%.key}.pub"; echo
}

case "$provider:$action" in
  aws:sign|azure:sign|dryrun:sign)
    [ -n "$in" ] && [ -n "$out" ] || die "sign needs --in and --out"
    [ -s "$in" ] || die "$in is missing or empty"
    head -c "$(printf 'librepatch/release/v1\0' | wc -c)" "$in" | cmp -s - <(printf 'librepatch/release/v1\0') || die "$in does not start with the release domain prefix (make it with: librepatch-release tosign)"
    tmp=$(mktemp)
    out_final=$out; out=$tmp
    "${provider}_sign"
    check_sig "$tmp"
    mv "$tmp" "$out_final"
    echo "release-kms: $provider produced a 64-byte signature in $out_final"
    ;;
  aws:pubkey|azure:pubkey|dryrun:pubkey)
    pk=$("${provider}_pubkey")
    if [ -n "$out" ]; then echo "$pk" >"$out"; else echo "$pk"; fi
    ;;
  *) die "unknown provider/action '$provider:$action'" ;;
esac
