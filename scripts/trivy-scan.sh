#!/bin/bash
# ============================================================
# Trivy Dependency Scan Script
# File: scripts/trivy-scan.sh
# Called by pre-commit on git push
# ============================================================

# Check if Docker is available
if ! command -v docker &>/dev/null; then
  echo "⚠️  Docker not found — skipping Trivy scan"
  echo "   Install Docker to enable dependency scanning"
  exit 0
fi

# Check if Docker is running
if ! docker info &>/dev/null 2>&1; then
  echo "⚠️  Docker is not running — skipping Trivy scan"
  exit 0
fi

echo "🛡️  Running Trivy dependency scan..."

# Run Trivy
docker run --rm \
  -v "$(pwd):/src" \
  aquasec/trivy:latest \
  fs \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  --quiet \
  /src

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ No HIGH/CRITICAL vulnerabilities found"
else
  echo "❌ HIGH/CRITICAL vulnerabilities found — push blocked"
  echo "   Fix vulnerabilities or request an exception:"
  echo "   hardikdoshi@devrepublic.nl"
fi

exit $EXIT_CODE
