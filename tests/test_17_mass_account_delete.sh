#!/usr/bin/env bash
# Test: FreeIPA Mass Account Disable or Deletion
source /tests/lib.sh

log "  Creating and deleting 6 temporary users..."
kinit_admin
for i in $(seq 1 6); do
    ipa user-add "tmpdelete$i" --first Tmp --last "Del$i" --password <<< "$(printf '%s\n%s\n' 'Passw0rd!' 'Passw0rd!')" 2>/dev/null || true
done
for i in $(seq 1 6); do
    ipa user-del "tmpdelete$i" 2>/dev/null || true
done

log "  Waiting for API events..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"bool":{"must":[{"match":{"event.action":"user_del"}},{"match":{"event.outcome":"success"}}]}}' 5

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Mass Account Disable or Deletion"
