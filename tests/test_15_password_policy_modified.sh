#!/usr/bin/env bash
# Test: FreeIPA Password Policy Modified
source /tests/lib.sh

log "  Modifying global password policy..."
kinit_admin
# Lower the min length (we'll restore it after)
ipa pwpolicy-mod --minlength=4 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"pwpolicy_mod"}},{"match":{"event.outcome":"success"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Password Policy Modified"

# Cleanup - restore
ipa pwpolicy-mod --minlength=8 2>/dev/null || true
