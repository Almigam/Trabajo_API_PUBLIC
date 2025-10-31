#!/usr/bin/env bash
set -euo pipefail
TARGET_URL="${1:-http://localhost:8000}"

docker run --rm -t   -u zap   -v "$(pwd)"/reports:/zap/wrk   -w /zap   ghcr.io/zaproxy/zaproxy:stable zap-baseline.py   -t "$TARGET_URL" -r zap_baseline_report.html || true

echo "ZAP baseline completed. See reports/zap_baseline_report.html"
