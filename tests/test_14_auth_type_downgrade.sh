#!/usr/bin/env bash
# Test: FreeIPA User Authentication Type Modified
source /tests/lib.sh

log "  Changing testuser8 auth type to password..."
kinit_admin
ipa user-mod testuser8 --user-auth-type=password 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"user_mod"}},{"wildcard":{"freeipa.api.parameters":"*user_auth_type*"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA User Authentication Type Modified"

# Cleanup - reset to default
ipa user-mod testuser8 --user-auth-type= 2>/dev/null || true
