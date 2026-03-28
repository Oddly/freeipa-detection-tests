#!/usr/bin/env bash
# Test: FreeIPA Password Reset by Another User
# Admin resets another user's password via the IPA API.
source /tests/lib.sh

log "  Admin resetting testuser2's password..."
kinit_admin
echo -e "NewPassw0rd!\nNewPassw0rd!" | ipa passwd testuser2 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"passwd"}},{"match":{"event.outcome":"success"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Password Reset by Another User"
