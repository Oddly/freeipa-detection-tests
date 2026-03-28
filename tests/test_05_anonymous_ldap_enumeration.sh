#!/usr/bin/env bash
# Test: FreeIPA Anonymous LDAP Directory Enumeration
# Performs anonymous LDAP search returning many entries.
source /tests/lib.sh

log "  Performing anonymous LDAP subtree search..."
ldap_search -b "cn=users,cn=accounts,dc=example,dc=test" "(objectclass=*)" dn 2>/dev/null || true
ldap_search -b "cn=groups,cn=accounts,dc=example,dc=test" "(objectclass=*)" dn 2>/dev/null || true
ldap_search -b "dc=example,dc=test" "(objectclass=*)" dn 2>/dev/null || true

log "  Waiting for directory access events..."
wait_for_docs "logs-freeipa.directory_access-*" '{"bool":{"must":[{"match":{"freeipa.directory.operation":"SRCH"}}]}}' 3

log "  Waiting for alert..."
wait_for_alerts "FreeIPA Anonymous LDAP Directory Enumeration"
