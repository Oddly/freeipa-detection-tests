#!/usr/bin/env bash
# Test: FreeIPA RBAC Role or Privilege Modification
source /tests/lib.sh

log "  Creating test role and adding member..."
kinit_admin
ipa role-add testrole --desc "Test role for detection" 2>/dev/null || true
ipa role-add-member testrole --users=testuser4 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"role_add_member"}},{"match":{"event.outcome":"success"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA RBAC Role or Privilege Modification"

# Cleanup
ipa role-del testrole 2>/dev/null || true
