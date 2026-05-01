#!/usr/bin/env bash
set -euo pipefail

# Syncs an allowlisted subset of proto definitions from the source repository.
#
# Usage:
#   ./scripts/sync-protos.sh /path/to/source/apis/proto

SRC="${1:-}"
DST="$(cd "$(dirname "$0")/.." && pwd)/proto"

if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
  echo "usage: $0 /path/to/source/apis/proto" >&2
  exit 1
fi

ALLOWLIST=(
  # ConvenienceStore SAML2 RPC + resources
  splitsecure/conveniencestore/v1/list_saml2_resources.proto
  splitsecure/conveniencestore/v1/saml2_resource.proto
  splitsecure/conveniencestore/v1/tombstone.proto

  # ConvenienceStore Generate/Get RPCs used for Create + Delete + Read
  splitsecure/conveniencestore/v1/generate_create_saml2_idp_proposal_request.proto
  splitsecure/conveniencestore/v1/generate_create_saml2_idp_proposal_response.proto
  splitsecure/conveniencestore/v1/generate_create_saml2_sp_proposal_request.proto
  splitsecure/conveniencestore/v1/generate_create_saml2_sp_proposal_response.proto
  splitsecure/conveniencestore/v1/generate_delete_saml2_idp_proposal_request.proto
  splitsecure/conveniencestore/v1/generate_delete_saml2_idp_proposal_response.proto
  splitsecure/conveniencestore/v1/generate_delete_saml2_sp_proposal_request.proto
  splitsecure/conveniencestore/v1/generate_delete_saml2_sp_proposal_response.proto
  splitsecure/conveniencestore/v1/get_saml2_resource.proto
  splitsecure/conveniencestore/v1/get_proposal_resource.proto

  # Enclave invoke types (needed by EnclaveRoundtripService)
  splitsecure/enclave/v1/enclave.proto

  # SAML2 inner types (for decoding authenticated bytes)
  splitsecure/enclaveservices/saml2/v1/idp_state.proto
  splitsecure/enclaveservices/saml2/v2/authenticated_idp_state_and_key.proto
  splitsecure/enclaveservices/saml2/v2/authenticated_saml2_service_provider.proto
  splitsecure/enclaveservices/saml2/v2/saml2_service_provider.proto

  # Transitive deps
  splitsecure/enclaveservices/threshold/v1/threshold_key.proto
  splitsecure/hybridkeyset/v1/hybridkeyset.proto
  splitsecure/keys/v1/aes.proto
  splitsecure/keys/v1/diffie_hellman_spec.proto
  splitsecure/keys/v1/key_encapsulation_spec.proto
  splitsecure/keys/v1/signature_spec.proto
  splitsecure/keys/v1/spec.proto
  splitsecure/keys/v1/symmetric_encryption_spec.proto
  splitsecure/notifications/v1/notification_policy.proto
  splitsecure/saml2metadatafetcherservice/v1/metadata.proto
  splitsecure/teamresource/v1/team_resource.proto
)

# Clean synced protos (preserve provider-owned files)
find "$DST/splitsecure" -name '*.proto' \
  ! -name 'provider_custom_*' \
  ! -path '*/requestsigning/v1/signed_request.proto' \
  -delete 2>/dev/null || true
find "$DST/splitsecure" -type d -empty -delete 2>/dev/null || true

for f in "${ALLOWLIST[@]}"; do
  mkdir -p "$DST/$(dirname "$f")"
  cp "$SRC/$f" "$DST/$f"
done

echo "synced ${#ALLOWLIST[@]} proto files from $SRC"
