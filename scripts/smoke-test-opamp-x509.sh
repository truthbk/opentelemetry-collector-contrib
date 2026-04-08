#!/usr/bin/env bash
# smoke-test-opamp-x509.sh
# Validates X.509 remote config signing in the OpAMP supervisor end-to-end.
#
# The script:
#   1. Builds the signing test server from source.
#   2. Starts the server (which generates ca.pem and begins listening).
#   3. Writes a supervisor config pointing at ca.pem and the server.
#   4. Starts the supervisor.
#   5. Polls the server log for SMOKE_TEST_PASS or SMOKE_TEST_FAIL sentinels.
#   6. Prints both logs, exits 0 on PASS or 1 on FAIL.
#
# Usage:
#   ./scripts/smoke-test-opamp-x509.sh [SUPERVISOR_BIN]
#
#   SUPERVISOR_BIN  path to the opampsupervisor binary
#                   (default: ./bin/opampsupervisor_$(go env GOOS)_$(go env GOARCH))
#
# Requirements:
#   - go (to build the test server)
#   - A built supervisor binary (build with: make build-supervisor)
#
# Exit codes:
#   0  All assertions passed (signed config accepted, unsigned config rejected).
#   1  One or more assertions failed or timeout exceeded.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Configuration ─────────────────────────────────────────────────────────────
PORT="${SMOKE_TEST_PORT:-14320}"
TIMEOUT_SECS="${SMOKE_TEST_TIMEOUT:-60}"

# Determine default supervisor binary path.
if [[ -n "${1:-}" ]]; then
  SUPERVISOR_BIN="$1"
else
  source ~/.gimme/envs/go1.26.1.env 2>/dev/null || true
  GOOS="$(go env GOOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]')"
  GOARCH="$(go env GOARCH 2>/dev/null || uname -m)"
  GOARCH="${GOARCH/x86_64/amd64}"
  GOARCH="${GOARCH/aarch64/arm64}"
  EXT=""
  [[ "$GOOS" == "windows" ]] && EXT=".exe"
  SUPERVISOR_BIN="${REPO_ROOT}/bin/opampsupervisor_${GOOS}_${GOARCH}${EXT}"
fi

if [[ ! -x "$SUPERVISOR_BIN" ]]; then
  echo "ERROR: supervisor binary not found or not executable: ${SUPERVISOR_BIN}" >&2
  echo "       Build it first (e.g.: make build-supervisor)" >&2
  exit 1
fi

# ── Temp directories & cleanup ────────────────────────────────────────────────
TMPDIR="$(mktemp -d)"
CA_PEM="${TMPDIR}/ca.pem"
STORAGE_DIR="${TMPDIR}/supervisor-storage"
SERVER_LOG="${TMPDIR}/server.log"
SUPERVISOR_LOG="${TMPDIR}/supervisor.log"
SUPERVISOR_CFG="${TMPDIR}/supervisor.yaml"
SERVER_BIN="${TMPDIR}/smoke-test-opamp-x509-server"

SERVER_PID=""
SUPERVISOR_PID=""

cleanup() {
  local rc=$?
  [[ -n "$SERVER_PID"     ]] && kill "$SERVER_PID"     2>/dev/null || true
  [[ -n "$SUPERVISOR_PID" ]] && kill "$SUPERVISOR_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "${TMPDIR}"
  exit $rc
}
trap cleanup EXIT INT TERM

# ── Step 1: Build the signing test server ─────────────────────────────────────
echo "==> Building smoke-test-opamp-x509-server..."
(
  source ~/.gimme/envs/go1.26.1.env 2>/dev/null || true
  go build -o "${SERVER_BIN}" \
    "${REPO_ROOT}/scripts/smoke-test-opamp-x509-server/..."
)
echo "    Built: ${SERVER_BIN}"

# ── Step 2: Start the signing test server ─────────────────────────────────────
echo "==> Starting signing test server on port ${PORT}..."
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
  echo "ERROR: signing server did not produce ca.pem within 10s" >&2
  echo "--- Server log ---" >&2
  cat "${SERVER_LOG}" >&2
  exit 1
fi
echo "    Server ready; CA cert at ${CA_PEM}"

# ── Step 3: Write supervisor config ───────────────────────────────────────────
mkdir -p "${STORAGE_DIR}"
cat > "${SUPERVISOR_CFG}" << EOF
server:
  endpoint: ws://127.0.0.1:${PORT}/v1/opamp

capabilities:
  reports_effective_config: true
  reports_health: true
  accepts_remote_config: true
  reports_remote_config: true
  verifies_remote_config_signature: true

signing:
  ca_cert_file: ${CA_PEM}

storage:
  directory: ${STORAGE_DIR}

agent:
  executable: ${SUPERVISOR_BIN}
EOF
echo "    Supervisor config written to ${SUPERVISOR_CFG}"

# ── Step 4: Start the supervisor ──────────────────────────────────────────────
echo "==> Starting supervisor..."
"${SUPERVISOR_BIN}" --config "${SUPERVISOR_CFG}" \
  > "${SUPERVISOR_LOG}" 2>&1 &
SUPERVISOR_PID=$!
echo "    Supervisor PID=${SUPERVISOR_PID}"

# ── Step 5: Poll for SMOKE_TEST_PASS / SMOKE_TEST_FAIL ───────────────────────
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
  # Also exit early if either process died unexpectedly.
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: signing server exited unexpectedly" >&2
    break
  fi
  sleep 0.2
done

# ── Step 6: Print logs and report ─────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Signing server log"
echo "════════════════════════════════════════════════════════"
cat "${SERVER_LOG}"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Supervisor log (last 60 lines)"
echo "════════════════════════════════════════════════════════"
tail -60 "${SUPERVISOR_LOG}"

echo ""
if [[ "${RESULT}" -eq 0 ]]; then
  echo "✅  SMOKE TEST PASSED: signed config accepted, unsigned config rejected."
else
  echo "❌  SMOKE TEST FAILED. Check the logs above for details."
fi

exit "${RESULT}"
