#!/bin/bash
# Git Credential Helper to decrypt and retrieve credentials from a secure GPG file.
# Supported JSON keys: 'github_username'/'email' and 'github_token'/'token'.

CREDS_GPG="/home/lugh/.karasugakure/opsec/credentials.json.gpg"

action="$1"
if [[ "$action" != "get" ]]; then
    exit 0
fi

# Read Git's stdin payload (protocol, host, etc.)
while read -r line; do
    if [[ -z "$line" ]]; then
        break
    fi
done

if [[ -f "$CREDS_GPG" ]]; then
    # Decrypt GPG file securely using gpg in batch/quiet mode
    CREDS_JSON=$(gpg --decrypt --batch --quiet "$CREDS_GPG" 2>/dev/null)
    if [[ $? -eq 0 && ! -z "$CREDS_JSON" ]]; then
        # Parse username and token from the GPG JSON file using Python 3
        USER_PASS=$(python3 -c "
import json, sys
try:
    data = json.loads('''$CREDS_JSON''')
    user = data.get('github_username', data.get('email', ''))
    token = data.get('github_token', data.get('token', ''))
    if user and token:
        print(f'username={user}\npassword={token}')
except Exception:
    sys.exit(1)
" 2>/dev/null)
        if [[ $? -eq 0 && ! -z "$USER_PASS" ]]; then
            echo "$USER_PASS"
            exit 0
        fi
    fi
fi

exit 1
