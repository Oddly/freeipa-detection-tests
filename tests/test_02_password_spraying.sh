#!/usr/bin/env bash
# Test: FreeIPA Kerberos Password Spraying Attempt
# Generates PREAUTH_FAILED across 16+ distinct principals from one source.
source /tests/lib.sh

log "  Spraying wrong password across 18 test users..."
for i in $(seq 1 18); do
    echo "SprayPassword1" | kinit "testuser$i@EXAMPLE.TEST" 2>/dev/null || true
done

log "  Waiting for KDC events to be indexed..."
wait_for_docs "logs-freeipa.kdc-*" '{"bool":{"must":[{"match":{"freeipa.kdc.error_code":"PREAUTH_FAILED"}}]}}' 16

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Kerberos Password Spraying Attempt"
