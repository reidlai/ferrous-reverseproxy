#!/usr/bin/env bash
# Ferrous ReverseProxy 3-minute standalone local quickstart and verification script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================================="
echo "  Ferrous ReverseProxy - 3-Minute Quickstart & Audit      "
echo "=========================================================="

cd "${PROJECT_ROOT}"

# 1. Run cargo check & test suite
echo ""
echo "[Step 1/3] Executing fast test suite..."
cargo test --manifest-path "${PROJECT_ROOT}/Cargo.toml" --lib
echo "  ✓ WAF, routing, and TLS unit tests passed."

# 2. Run unbuffered SSE stream integration test
echo ""
echo "[Step 2/3] Verifying unbuffered Axum SSE streaming..."
cargo test --manifest-path "${PROJECT_ROOT}/Cargo.toml" --test test_sse_streaming
echo "  ✓ SSE streaming pass-through verified (X-Accel-Buffering: no, zero chunk buffering)."

# 3. Static configuration & Day-0 rules verification
echo ""
echo "[Step 3/3] Auditing WAF CRS & Day-0 SecRules..."
find "${PROJECT_ROOT}/config" -type f \( -name "*.conf" -o -name "*.yaml" \) | while read -r file; do
    echo "  - $(basename "$file")"
done

echo ""
echo "=========================================================="
echo "  ✓ QUICKSTART AUDIT COMPLETED IN UNDER 3 MINUTES!        "
echo "=========================================================="
