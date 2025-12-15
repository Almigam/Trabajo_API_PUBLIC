#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
trivy fs --scanners vuln,secret,misconfig --format table --output reports/trivy_fs.txt . || true
echo "Trivy FS scan completed. See reports/trivy_fs.txt"
