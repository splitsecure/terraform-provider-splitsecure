#!/usr/bin/env bash
#
# Sign the SHA256SUMS file of a draft release with GPG, attach the
# detached signature to the release as a .sig asset, and flip the
# release from draft to published. Mirrors what goreleaser would do
# in --skip=sign mode but performed locally so the signing key never
# leaves the operator's machine.
#
# Usage:
#   ./scripts/sign-release.sh TAG GPG_FINGERPRINT
#
# TAG:              tag of the draft release (e.g. v0.1.2). Required --
#                   the script refuses to guess so a typo can't sign
#                   and publish the wrong release.
# GPG_FINGERPRINT:  40-char fingerprint of the RSA signing key
#                   (`gpg --list-secret-keys --keyid-format=long`).
#                   Required and explicit so the wrong default key
#                   can't quietly sign a release.
#
# Environment:
#   GH_REPO          owner/name override; otherwise the current
#                    directory's repo is used.
#
# Prereqs:
#   - gh authenticated against the splitsecure org
#   - gpg with the release-signing key available
#   - jq
#
# To generate a fresh release-signing key:
#   gpg --full-generate-key
#     -> (1) RSA and RSA  -> 4096  -> 0 (no expiry, or 2y if you prefer)
#     -> Real name + email matching the org
#   gpg --list-secret-keys --keyid-format=long
#   export GPG_FINGERPRINT=<long-fingerprint>
#   gpg --armor --export "$GPG_FINGERPRINT" > release-pubkey.asc
#   # upload release-pubkey.asc to the registry under Signing Keys

set -euo pipefail

if [ "$#" -ne 2 ] || [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
  echo "usage: $0 TAG GPG_FINGERPRINT" >&2
  echo "       e.g. $0 v0.1.2 0513D58E93D94AA701F8412F08F3C5834B8EAF90" >&2
  exit 2
fi

repo="${GH_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
tag="$1"
fingerprint="$2"

is_draft="$(gh release view "$tag" --repo "$repo" --json isDraft -q .isDraft)"
if [ "$is_draft" != "true" ]; then
  echo "release $tag is not a draft (already published?)" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

cd "$workdir"
gh release download "$tag" --repo "$repo" --pattern '*_SHA256SUMS'

count="$(ls *_SHA256SUMS 2>/dev/null | wc -l | tr -d '[:space:]')"
if [ "$count" -ne 1 ]; then
  echo "expected exactly one *_SHA256SUMS file in release, found $count" >&2
  exit 1
fi
shafile="$(ls *_SHA256SUMS)"

echo "signing $shafile with $fingerprint"

gpg --batch --yes \
    --local-user "$fingerprint" \
    --output "${shafile}.sig" \
    --detach-sign \
    "$shafile"

# Verify the signature parses against the public keyring before
# uploading so we don't ship something the registry will reject.
gpg --verify "${shafile}.sig" "$shafile"

echo "uploading ${shafile}.sig"
gh release upload "$tag" --repo "$repo" --clobber "${shafile}.sig"

echo "publishing $tag"
gh release edit "$tag" --repo "$repo" --draft=false

echo "release $tag is live"
