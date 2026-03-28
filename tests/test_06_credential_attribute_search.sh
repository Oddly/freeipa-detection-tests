#!/usr/bin/env bash
# Test: FreeIPA LDAP Search for Credential Attributes
# Searches for password hash attributes via LDAP.
source /tests/lib.sh

log "  Searching for credential attributes via LDAP..."
ldap_search_auth -b "cn=users,cn=accounts,dc=example,dc=test" "(userPassword=*)" dn 2>/dev/null || true
ldap_search_auth -b "cn=users,cn=accounts,dc=example,dc=test" "(krbPrincipalKey=*)" dn 2>/dev/null || true
ldap_search_auth -b "dc=example,dc=test" "(ipaNTHash=*)" dn 2>/dev/null || true

log "  Waiting for directory access events..."
wait_for_docs "logs-freeipa.directory_access-*" '{"bool":{"must":[{"match":{"freeipa.directory.operation":"SRCH"}},{"wildcard":{"freeipa.directory.filter":"*userPassword*"}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA LDAP Search for Credential Attributes"
