#!/usr/bin/env bash
# Test: FreeIPA Integration Health
# Verifies all 5 data streams are receiving data with correct field mappings.
# Run this BEFORE the detection rule tests to confirm the integration works.
source /tests/lib.sh

PASS=0
FAIL=0

check_stream() {
    local stream="$1" required_field="$2" min_docs="${3:-1}"
    local count
    count=$(curl -sf "$ES_URL/logs-freeipa.$stream-*/_count" \
        -H 'Content-Type: application/json' \
        -d "{\"query\":{\"exists\":{\"field\":\"$required_field\"}}}" \
        2>/dev/null | jq -r '.count // 0')

    if [ "$count" -ge "$min_docs" ]; then
        PASS=$((PASS + 1))
        log "  PASS  $stream: $count docs with $required_field"
    else
        FAIL=$((FAIL + 1))
        log "  FAIL  $stream: $count docs with $required_field (expected >= $min_docs)"
    fi
}

log "=== Integration Health Check ==="

# Verify each data stream has data with key parsed fields
check_stream "kdc"              "freeipa.kdc.client_principal"
check_stream "kdc"              "freeipa.kdc.error_code"
check_stream "kdc"              "source.ip"
check_stream "directory_access" "freeipa.directory.operation"
check_stream "directory_access" "freeipa.directory.connection_id"
check_stream "directory_errors"  "log.level"
check_stream "ca_audit"         "freeipa.ca.event_type"
check_stream "ca_audit"         "user.name"
check_stream "ipa_api"          "event.action"
check_stream "ipa_api"          "freeipa.api.command"

# Verify ECS fields are populated
check_stream "kdc"              "event.category"
check_stream "directory_access" "event.dataset"
check_stream "ipa_api"          "event.outcome"

log ""
log "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
