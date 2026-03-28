#!/usr/bin/env bash
# Test: FreeIPA Kerberos Account Lockout Storm
# Trigger lockout for 4+ distinct principals.
source /tests/lib.sh

log "  Triggering account lockouts for multiple users..."
# We need enough failures to trigger lockout for each user.
# Default FreeIPA lockout is 6 failures.
for user_i in $(seq 10 14); do
    for attempt in $(seq 1 8); do
        echo "wrongpw" | kinit "testuser$user_i@EXAMPLE.TEST" 2>/dev/null || true
    done
done

log "  Waiting for LOCKED_OUT events..."
wait_for_docs "logs-freeipa.kdc-*" '{"match":{"freeipa.kdc.error_code":"LOCKED_OUT"}}' 3

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Kerberos Account Lockout Storm"

# Cleanup - unlock users
kinit_admin
for user_i in $(seq 10 14); do
    ipa user-unlock "testuser$user_i" 2>/dev/null || true
done
