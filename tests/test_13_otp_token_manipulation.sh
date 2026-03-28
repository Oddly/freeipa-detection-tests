#!/usr/bin/env bash
# Test: FreeIPA OTP Token Created, Modified, or Deleted
source /tests/lib.sh

log "  Creating OTP token for testuser7..."
kinit_admin
token_id=$(ipa otptoken-add --owner=testuser7 --type=totp 2>/dev/null | grep "Unique ID" | awk '{print $NF}') || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"match":{"event.action":"otptoken_add"}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA OTP Token Created, Modified, or Deleted"

# Cleanup
[ -n "$token_id" ] && ipa otptoken-del "$token_id" 2>/dev/null || true
