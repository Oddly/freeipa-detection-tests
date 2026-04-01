#!/usr/bin/env bash
# Shared test library functions.

ES_URL="${ES_URL:-http://elasticsearch:9200}"
KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
IPA_SERVER="${IPA_SERVER:-ipa.example.test}"
IPA_ADMIN_PASSWORD="${IPA_ADMIN_PASSWORD:?Set IPA_ADMIN_PASSWORD}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

wait_for_url() {
    local url="$1" name="$2" timeout="${3:-60}"
    local elapsed=0
    while ! curl -sf "$url" > /dev/null 2>&1; do
        sleep 2
        elapsed=$((elapsed + 2))
        if [ $elapsed -ge $timeout ]; then
            log "ERROR: $name not ready after ${timeout}s"
            return 1
        fi
    done
    log "  $name is ready"
}

# Get a fresh admin ticket
kinit_admin() {
    echo "$IPA_ADMIN_PASSWORD" | kinit admin@EXAMPLE.TEST 2>/dev/null
}

# Wait for documents matching a query to appear in an index
wait_for_docs() {
    local index="$1" query="$2" min_count="${3:-1}" timeout="${4:-90}"
    local elapsed=0
    while true; do
        count=$(curl -sf "$ES_URL/$index/_count" \
            -H 'Content-Type: application/json' \
            -d "{\"query\": $query}" 2>/dev/null | jq -r '.count // 0')
        if [ "$count" -ge "$min_count" ]; then
            return 0
        fi
        sleep 3
        elapsed=$((elapsed + 3))
        if [ $elapsed -ge $timeout ]; then
            log "  Timeout waiting for $min_count docs in $index (got $count)"
            return 1
        fi
    done
}

# Wait for alerts from a specific rule to appear
wait_for_alerts() {
    local rule_name="$1" min_count="${2:-1}" timeout="${3:-180}"
    local elapsed=0
    while true; do
        count=$(curl -sf "$KIBANA_URL/api/detection_engine/signals/search" \
            -H 'Content-Type: application/json' \
            -H 'kbn-xsrf: true' \
            -d "{
                \"query\": {
                    \"bool\": {
                        \"must\": [
                            {\"match\": {\"kibana.alert.rule.name\": \"$rule_name\"}}
                        ]
                    }
                },
                \"size\": 0,
                \"track_total_hits\": true
            }" 2>/dev/null | jq -r '.hits.total.value // 0')
        if [ "$count" -ge "$min_count" ]; then
            log "  Alert found: '$rule_name' ($count alerts)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        if [ $elapsed -ge $timeout ]; then
            log "  No alert for '$rule_name' after ${timeout}s"
            return 1
        fi
    done
}

# Run an IPA command with admin credentials
ipa_cmd() {
    kinit_admin
    ipa "$@"
}

# Perform an LDAP search
ldap_search() {
    ldapsearch -x -H "ldap://$IPA_SERVER" "$@"
}

# Perform an authenticated LDAP search via GSSAPI
ldap_search_auth() {
    kinit_admin
    ldapsearch -Y GSSAPI -H "ldap://$IPA_SERVER" "$@"
}

# Perform LDAP simple bind (for testing bind failures)
ldap_bind() {
    local dn="$1" password="$2"
    ldapsearch -x -H "ldap://$IPA_SERVER" -D "$dn" -w "$password" -b "" -s base 2>&1
}
