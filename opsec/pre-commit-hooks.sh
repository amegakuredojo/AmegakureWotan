#!/bin/bash
# Pre-commit hook to scan for secrets using gitleaks

# Check if gitleaks is installed
if ! command -v gitleaks &> /dev/null; then
    echo "Warning: gitleaks is not installed. Skipping secrets scan."
    exit 0
fi

echo "Running gitleaks detect..."
gitleaks detect --verbose --redact
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "Error: Gitleaks detected potential secrets in your commit. Commit aborted."
    exit 1
fi

echo "Gitleaks check passed."
exit 0
