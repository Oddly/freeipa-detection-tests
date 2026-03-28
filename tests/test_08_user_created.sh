#!/usr/bin/env bash
# Test: FreeIPA New User Account Created
source /tests/lib.sh

log "  Creating a new user via IPA API..."
kinit_admin
ipa user-add alerttestuser --first Alert --last TestUser --password <<< "$(printf '%s\n%s\n' 'Passw0rd!' 'Passw0rd!')" 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"user_add"}},{"match":{"event.outcome":"success"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA New User Account Created"
