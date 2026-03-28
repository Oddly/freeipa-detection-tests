#!/usr/bin/env bash
# Test: FreeIPA Admin Group Member Added
source /tests/lib.sh

log "  Adding testuser3 to admins group..."
kinit_admin
ipa group-add-member admins --users=testuser3 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"group_add_member"}},{"wildcard":{"freeipa.api.parameters":"*admins*"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Admin Group Member Added"

# Cleanup
ipa group-remove-member admins --users=testuser3 2>/dev/null || true
