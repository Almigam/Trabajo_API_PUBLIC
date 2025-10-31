#!/usr/bin/env bash
set -euo pipefail
IMAGE="${1:-secure-api:dev}"
mkdir -p reports
trivy image --scanners vuln,secret,misconfig --format table --output reports/trivy_image.txt "$IMAGE" || true
echo "Trivy image scan completed. See reports/trivy_image.txt"
