#!/usr/bin/env bash
# Test: FreeIPA Sudo Rule Created or Expanded
source /tests/lib.sh

log "  Creating test sudo rule..."
kinit_admin
ipa sudorule-add test_sudo_rule 2>/dev/null || true
ipa sudorule-add-user test_sudo_rule --users=testuser5 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"sudorule_add"}},{"match":{"event.outcome":"success"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Sudo Rule Created or Expanded"

# Cleanup
ipa sudorule-del test_sudo_rule 2>/dev/null || true
