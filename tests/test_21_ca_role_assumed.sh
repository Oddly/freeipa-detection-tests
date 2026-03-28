#!/usr/bin/env bash
# Test: FreeIPA CA Administrative Role Assumed
# ROLE_ASSUME events are generated during normal CA operations.
# We trigger one by performing a cert-related operation.
source /tests/lib.sh

log "  Triggering CA operation to generate ROLE_ASSUME event..."
kinit_admin
ipa ca-show ipa 2>/dev/null || true
ipa cert-find --sizelimit=1 2>/dev/null || true

log "  Waiting for CA audit ROLE_ASSUME event..."
wait_for_docs "logs-freeipa.ca_audit-*" '{"match":{"freeipa.ca.event_type":"ROLE_ASSUME"}}' 1 90

log "  Waiting for alert..."
wait_for_alerts "FreeIPA CA Administrative Role Assumed"
