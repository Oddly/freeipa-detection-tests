#!/usr/bin/env bash
# Test: FreeIPA HBAC Rule Created, Modified, or Disabled
source /tests/lib.sh

log "  Creating test HBAC rule..."
kinit_admin
ipa hbacrule-add test_hbac_rule 2>/dev/null || true
ipa hbacrule-add-user test_hbac_rule --users=testuser6 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"hbacrule_add"}},{"match":{"event.outcome":"success"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA HBAC Rule Created, Modified, or Disabled"

# Cleanup
ipa hbacrule-del test_hbac_rule 2>/dev/null || true
