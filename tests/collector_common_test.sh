#!/usr/bin/env bash
# Offline regression suite; needs only Bash, Python 3, jq, gzip, file and SHA256.
set -euo pipefail
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$TEST_DIR/test_collector_common.py"
