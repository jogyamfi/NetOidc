#!/usr/bin/env bash
# Runs OpenID Foundation conformance test plans against the NetOidc conformance host.
#
#   ./run-conformance.sh <profile> [plan:config ...]
#
# Profiles and their default plans are listed in PLANS below. Requires Docker, Python 3
# (httpx, pyparsing), git and the .NET SDK. Environment:
#   SUITE_DIR     conformance-suite checkout (cloned when missing; default ./.suite)
#   SUITE_TAG     suite release to run (default release-v5.3.1)
#   OP_URL        issuer as seen from the suite container (default https://host.docker.internal:8990)
#   RESULTS_DIR   where exported results and the OP log go (default ./results)
#   CONFIGURATION build configuration of the host (default Release)
#   ALIAS         suite alias (part of callback URLs); concurrent runs need distinct aliases (default netoidc)
#   KEEP_SUITE=1  leave the suite containers running afterwards
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${1:?usage: run-conformance.sh <profile> [plan:config ...]}"
shift
SUITE_DIR="${SUITE_DIR:-$HERE/.suite}"
SUITE_TAG="${SUITE_TAG:-release-v5.3.1}"
OP_URL="${OP_URL:-https://host.docker.internal:8990}"
RESULTS_DIR="${RESULTS_DIR:-$HERE/results}"
ALIAS="${ALIAS:-netoidc}"
CONFIGURATION="${CONFIGURATION:-Release}"
SUITE_URL="https://localhost.emobix.co.uk:8443"
PYTHON="${PYTHON:-$(command -v python3 || command -v python)}"

# Plans per profile: "<plan name with variants>:<configuration file written by the host>".
FAPI2_VARIANTS="[openid=openid_connect][fapi_profile=plain_fapi]"
declare -A PLANS=(
  [oidcc]="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]:oidcc-static.json
oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]:oidcc-static.json
oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]:oidcc-static.json
oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]:oidcc-static.json
oidcc-config-certification-test-plan:oidcc-static.json
oidcc-dynamic-certification-test-plan[response_type=code]:oidcc-dynamic.json
oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]:oidcc-logout-rp.json
oidcc-frontchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]:oidcc-logout-frontchannel.json
oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]:oidcc-logout-backchannel.json"
  [fapi2]="fapi2-security-profile-final-test-plan${FAPI2_VARIANTS}[client_auth_type=private_key_jwt][sender_constrain=dpop]:fapi2-pkjwt.json
fapi2-security-profile-final-test-plan${FAPI2_VARIANTS}[client_auth_type=private_key_jwt][sender_constrain=mtls]:fapi2-pkjwt.json
fapi2-security-profile-final-test-plan${FAPI2_VARIANTS}[client_auth_type=mtls][sender_constrain=mtls]:fapi2-mtls.json"
  [fapi2-ms]="fapi2-message-signing-final-test-plan[openid=openid_connect][fapi_profile=plain_fapi][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm]:fapi2-ms-pkjwt.json"
  [fapi1]="fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response]:fapi1-pkjwt.json
fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm]:fapi1-mtls.json"
  [fapi-ciba]="fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=poll][fapi_ciba_profile=plain_fapi][client_registration=static_client]:fapi-ciba-poll.json
fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=ping][fapi_ciba_profile=plain_fapi][client_registration=static_client]:fapi-ciba-ping.json"
)

# ── Suite ────────────────────────────────────────────────────────────────────
if [ ! -d "$SUITE_DIR/.git" ]; then
  git -c core.longpaths=true clone --depth 1 --branch "$SUITE_TAG" https://gitlab.com/openid/conformance-suite.git "$SUITE_DIR"
fi
(cd "$SUITE_DIR" && IMAGE_TAG="$SUITE_TAG" docker compose -f docker-compose-prebuilt.yml -p netoidc-conformance up -d)
for _ in $(seq 1 60); do
  curl -sfk "$SUITE_URL/api/runner/available" >/dev/null && break
  sleep 5
done

# ── NetOidc conformance host ─────────────────────────────────────────────────
# It writes the plan configurations (with the clients' generated keys) into the suite's scripts directory.
mkdir -p "$RESULTS_DIR"
dotnet build "$HERE" -c "$CONFIGURATION" --nologo -v q
ASPNETCORE_ENVIRONMENT=Production dotnet run --project "$HERE" -c "$CONFIGURATION" --no-build -- \
  --Conformance:Profile="$PROFILE" --Conformance:Issuer="$OP_URL" --Conformance:Alias="$ALIAS" \
  --Conformance:SuiteConfigDir="$SUITE_DIR/scripts" > "$RESULTS_DIR/op-$PROFILE.log" 2>&1 &
OP_PID=$!
cleanup() {
  kill "$OP_PID" 2>/dev/null || true
  if [ "${KEEP_SUITE:-0}" != "1" ]; then
    (cd "$SUITE_DIR" && docker compose -f docker-compose-prebuilt.yml -p netoidc-conformance down)
  fi
}
trap cleanup EXIT
LOCAL_OP="https://localhost:${OP_URL##*:}"
for _ in $(seq 1 60); do
  curl -sfk "$LOCAL_OP/.well-known/openid-configuration" >/dev/null && break
  kill -0 "$OP_PID" 2>/dev/null || break
  sleep 1
done
if ! curl -sfk "$LOCAL_OP/.well-known/openid-configuration" >/dev/null; then
  echo "The conformance host did not start; last lines of its log:" >&2
  tail -20 "$RESULTS_DIR/op-$PROFILE.log" >&2
  exit 1
fi

# ── Plans ────────────────────────────────────────────────────────────────────
if [ $# -gt 0 ]; then
  SELECTED=$(printf '%s\n' "$@")
else
  SELECTED="${PLANS[$PROFILE]:?unknown profile $PROFILE}"
fi

ARGS=()
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  ARGS+=("${entry%%:*}" "${entry##*:}")
done <<< "$SELECTED"

# Known, explained deviations per profile (docs/CONFORMANCE.md). The suite also fails a run when a
# listed item does not occur, so they apply only to a full profile run.
EXPECTED=()
if [ $# -eq 0 ] && [ -f "$HERE/expected-failures-$PROFILE.json" ]; then
  EXPECTED=(--expected-failures-file "$HERE/expected-failures-$PROFILE.json")
fi

cd "$SUITE_DIR/scripts"
CONFORMANCE_SERVER="$SUITE_URL/" CONFORMANCE_DEV_MODE=1 PYTHONIOENCODING=utf-8 \
  "$PYTHON" run-test-plan.py --export-dir "$RESULTS_DIR" "${EXPECTED[@]}" "${ARGS[@]}"
