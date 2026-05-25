#!/usr/bin/env bash
# smoke-test-opamp-attestation.sh
# Validates OpAMP Message Attestation (X.509 payload trust verification)
# end-to-end against a real opampsupervisor process.
#
# The script:
#   1. Builds the signing OpAMP test server from source.
#   2. Starts the server (which generates ca.pem and begins listening).
#   3. Writes a supervisor YAML config that points at ca.pem and the
#      server, with capabilities.requires_payload_trust_verification: true.
#   4. Starts the supervisor.
#   5. Polls the server log for SMOKE_TEST_PASS or SMOKE_TEST_FAIL.
#   6. Prints both logs; exits 0 on PASS or 1 on FAIL.
#
# Usage:
#   ./scripts/smoke-test-opamp-attestation.sh [SUPERVISOR_BIN] [AGENT_BIN]
#
#   SUPERVISOR_BIN  path to the opampsupervisor binary.
#                   Default: ./bin/opampsupervisor_$(go env GOOS)_$(go env GOARCH)
#   AGENT_BIN       path to the agent (collector) executable.
#                   Default: ./bin/otelcontribcol_$(go env GOOS)_$(go env GOARCH)
#                   The supervisor needs SOME executable at this path
#                   to pass config validation; the smoke test exits as
#                   soon as the supervisor verifies the signed envelope
#                   and reports a RemoteConfigStatus back, so the agent
#                   does not need to be a fully-functional collector.
#
# Environment overrides:
#   SMOKE_TEST_PORT     OpAMP server port (default: 14320)
#   SMOKE_TEST_TIMEOUT  seconds to wait for the PASS/FAIL sentinel
#                       (default: 60)
#
# Requirements:
#   - go (to build the test server)
#   - A built opampsupervisor binary
#   - A file (any executable) at AGENT_BIN; the supervisor's config
#     validation requires it to exist
#
# Exit codes:
#   0  Smoke test passed (supervisor accepted the signed envelope).
#   1  Failure or timeout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PORT="${SMOKE_TEST_PORT:-14320}"
TIMEOUT_SECS="${SMOKE_TEST_TIMEOUT:-60}"

# Resolve default binary paths from GOOS/GOARCH.
source ~/.gimme/envs/go1.26.1.env 2>/dev/null || true
GOOS="$(go env GOOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]')"
GOARCH="$(go env GOARCH 2>/dev/null || uname -m)"
GOARCH="${GOARCH/x86_64/amd64}"
GOARCH="${GOARCH/aarch64/arm64}"
EXT=""
[[ "$GOOS" == "windows" ]] && EXT=".exe"

SUPERVISOR_BIN="${1:-${REPO_ROOT}/bin/opampsupervisor_${GOOS}_${GOARCH}${EXT}}"
AGENT_BIN="${2:-${REPO_ROOT}/bin/otelcontribcol_${GOOS}_${GOARCH}${EXT}}"

if [[ ! -x "$SUPERVISOR_BIN" ]]; then
  echo "ERROR: supervisor binary not found or not executable: ${SUPERVISOR_BIN}" >&2
  echo "       Build it first (e.g.: cd cmd/opampsupervisor && go build -o ../../bin/opampsupervisor_${GOOS}_${GOARCH}${EXT} .)" >&2
  exit 1
fi
if [[ ! -e "$AGENT_BIN" ]]; then
  echo "ERROR: agent executable not found: ${AGENT_BIN}" >&2
  echo "       Build it first (e.g.: make otelcontribcol)" >&2
  exit 1
fi

# Temp workspace + cleanup.
TMPDIR="$(mktemp -d)"
CA_PEM="${TMPDIR}/ca.pem"
STORAGE_DIR="${TMPDIR}/supervisor-storage"
SERVER_LOG="${TMPDIR}/server.log"
SUPERVISOR_LOG="${TMPDIR}/supervisor.log"
SUPERVISOR_CFG="${TMPDIR}/supervisor.yaml"
SERVER_BIN="${TMPDIR}/smoke-test-opamp-attestation-server"

SERVER_PID=""
SUPERVISOR_PID=""

cleanup() {
  local rc=$?
  [[ -n "$SUPERVISOR_PID" ]] && kill "$SUPERVISOR_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID"     ]] && kill "$SERVER_PID"     2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "${TMPDIR}"
  exit $rc
}
trap cleanup EXIT INT TERM

# Step 1: Build the signing OpAMP test server.
echo "==> Building smoke-test-opamp-attestation-server..."
(
  cd "${SCRIPT_DIR}/smoke-test-opamp-attestation-server"
  go build -o "${SERVER_BIN}" .
)
echo "    Built: ${SERVER_BIN}"

# Step 2: Start the signing test server.
echo "==> Starting signing OpAMP server on port ${PORT}..."
"${SERVER_BIN}" \
  --port "${PORT}" \
  --ca-out "${CA_PEM}" \
  > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

# Wait up to 10s for ca.pem to appear (signals the server is ready).
for _ in $(seq 1 50); do
  [[ -f "${CA_PEM}" ]] && break
  sleep 0.2
done
if [[ ! -f "${CA_PEM}" ]]; then
  echo "ERROR: signing server did not produce ${CA_PEM} within 10s" >&2
  echo "--- Server log ---" >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi
echo "    Server ready; CA cert at ${CA_PEM}"

# Step 3: Write supervisor config.
mkdir -p "${STORAGE_DIR}"
cat > "${SUPERVISOR_CFG}" << EOF
server:
  endpoint: ws://127.0.0.1:${PORT}/v1/opamp

capabilities:
  reports_effective_config: true
  reports_health: true
  accepts_remote_config: true
  reports_remote_config: true
  requires_payload_trust_verification: true

signing:
  ca_cert_file: ${CA_PEM}

storage:
  directory: ${STORAGE_DIR}

agent:
  executable: ${AGENT_BIN}
EOF
echo "    Supervisor config written to ${SUPERVISOR_CFG}"

# Step 4: Start the supervisor.
echo "==> Starting supervisor..."
"${SUPERVISOR_BIN}" --config "${SUPERVISOR_CFG}" \
  > "${SUPERVISOR_LOG}" 2>&1 &
SUPERVISOR_PID=$!
echo "    Supervisor PID=${SUPERVISOR_PID}"

# Step 5: Poll for the PASS/FAIL sentinel from the server.
echo "==> Waiting for test result (timeout ${TIMEOUT_SECS}s)..."
RESULT=1
for _ in $(seq 1 $((TIMEOUT_SECS * 5))); do
  if grep -q "SMOKE_TEST_PASS" "${SERVER_LOG}" 2>/dev/null; then
    RESULT=0
    break
  fi
  if grep -q "SMOKE_TEST_FAIL" "${SERVER_LOG}" 2>/dev/null; then
    RESULT=1
    break
  fi
  # Exit early if either process died unexpectedly.
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: signing server exited unexpectedly" >&2
    break
  fi
  if ! kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
    echo "ERROR: supervisor exited unexpectedly" >&2
    break
  fi
  sleep 0.2
done

# Step 6: Print logs and report.
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Signing OpAMP server log"
echo "════════════════════════════════════════════════════════"
cat "${SERVER_LOG}"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Supervisor log (last 80 lines)"
echo "════════════════════════════════════════════════════════"
tail -80 "${SUPERVISOR_LOG}"

echo ""
if [[ "${RESULT}" -eq 0 ]]; then
  echo "PASS: supervisor verified the SignedServerToAgent envelope end-to-end."
else
  echo "FAIL: see logs above for details."
fi

exit "${RESULT}"
