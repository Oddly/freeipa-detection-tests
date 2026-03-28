#!/usr/bin/env bash
# Test: FreeIPA LDAP Mass Data Exfiltration
# Performs a subtree search returning many entries (not as replication manager).
source /tests/lib.sh

log "  Performing large authenticated LDAP subtree search..."
ldap_search_auth -b "dc=example,dc=test" -s sub "(objectclass=*)" dn 2>/dev/null || true

log "  Waiting for directory access event with high entry count..."
wait_for_docs "logs-freeipa.directory_access-*" '{"bool":{"must":[{"match":{"freeipa.directory.operation":"SRCH"}},{"range":{"freeipa.directory.entries_returned":{"gte":100}}}]}}' 1

log "  Waiting for alert..."
wait_for_alerts "FreeIPA LDAP Mass Data Exfiltration"
