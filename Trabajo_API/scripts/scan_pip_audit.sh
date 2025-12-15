#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
pip-audit -r requirements.txt -f json -o reports/pip_audit.json || true
echo "pip-audit results at reports/pip_audit.json"
