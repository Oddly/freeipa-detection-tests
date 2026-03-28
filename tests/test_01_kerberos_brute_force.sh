#!/usr/bin/env bash
# Test: FreeIPA Kerberos Brute Force Attempt
# Generates 30 PREAUTH_FAILED for a single principal from one source.
source /tests/lib.sh

log "  Generating 30 failed kinit attempts for testuser1..."
for i in $(seq 1 30); do
    echo "wrongpassword$i" | kinit testuser1@EXAMPLE.TEST 2>/dev/null || true
done

log "  Waiting for KDC events to be indexed..."
wait_for_docs "logs-freeipa.kdc-*" '{"bool":{"must":[{"match":{"freeipa.kdc.error_code":"PREAUTH_FAILED"}},{"match":{"freeipa.kdc.client_principal":"testuser1@EXAMPLE.TEST"}}]}}' 25

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Kerberos Brute Force Attempt"
