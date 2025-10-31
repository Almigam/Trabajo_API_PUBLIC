#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
bandit -r app -f html -o reports/bandit_report.html || true
echo "Bandit report at reports/bandit_report.html"
