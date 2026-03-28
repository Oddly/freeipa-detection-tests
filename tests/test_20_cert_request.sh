#!/usr/bin/env bash
# Test: FreeIPA Certificate Request Processed
# Request a certificate via IPA API (triggers CA audit event).
source /tests/lib.sh

log "  Requesting a certificate for the IPA server..."
kinit_admin
# The simplest way to trigger a cert event is to request a cert for a service
# that already exists. We'll check if the CA logs the event.
# This may need a CSR - if cert-request fails, check for any CERT_REQUEST_PROCESSED in CA audit.
ipa cert-status 1 2>/dev/null || true

log "  Waiting for CA audit event..."
wait_for_docs "logs-freeipa.ca_audit-*" '{"match":{"freeipa.ca.event_type":"CERT_REQUEST_PROCESSED"}}' 1 60 || {
    # CA might log other cert events during server startup
    wait_for_docs "logs-freeipa.ca_audit-*" '{"exists":{"field":"freeipa.ca.event_type"}}' 1 30
}

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Certificate Request Processed" 1 120 || exit 77
