#!/usr/bin/env bash
# Test: FreeIPA LDAP Bind Brute Force Attempt
# Generates 25 failed LDAP simple binds from one source.
source /tests/lib.sh

log "  Generating 25 failed LDAP simple bind attempts..."
for i in $(seq 1 25); do
    ldap_bind "uid=testuser1,cn=users,cn=accounts,dc=example,dc=test" "wrong$i" || true
done

log "  Waiting for directory access events..."
wait_for_docs "logs-freeipa.directory_access-*" '{"bool":{"must":[{"match":{"freeipa.directory.operation":"BIND"}},{"match":{"freeipa.directory.bind_method":"SIMPLE"}}]}}' 20

log "  Waiting for alert..."
wait_for_alerts "FreeIPA LDAP Bind Brute Force Attempt"
