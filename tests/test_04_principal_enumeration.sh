#!/usr/bin/env bash
# Test: FreeIPA Kerberos Principal Enumeration
# Generates CLIENT_NOT_FOUND by requesting tickets for non-existent principals.
source /tests/lib.sh

log "  Probing 15 non-existent principals..."
for i in $(seq 1 15); do
    echo "x" | kinit "nonexistent_user_$i@EXAMPLE.TEST" 2>/dev/null || true
done

log "  Waiting for KDC events..."
wait_for_docs "logs-freeipa.kdc-*" '{"match":{"freeipa.kdc.error_code":"CLIENT_NOT_FOUND"}}' 10

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Kerberos Principal Enumeration"
