#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
semgrep --config p/owasp-top-ten --metrics=off --json > reports/semgrep.json || true
echo "Semgrep results at reports/semgrep.json"
