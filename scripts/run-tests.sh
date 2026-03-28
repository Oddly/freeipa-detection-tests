#!/usr/bin/env bash
# Main test runner: sets up the environment, runs all tests, reports results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source /tests/lib.sh

PASS=0
FAIL=0
SKIP=0
RESULTS=()

log "=== FreeIPA Detection Rules Test Suite ==="

# Phase 1: Wait for all services
log "Phase 1: Waiting for services..."
wait_for_url "$ES_URL" "Elasticsearch" 120
wait_for_url "$KIBANA_URL/api/status" "Kibana" 120

# Phase 2: Install ingest pipelines and index templates
log "Phase 2: Installing ingest pipelines and index templates..."
for pipeline_file in /pipelines/*.yml; do
    pipeline_name="freeipa-$(basename "$pipeline_file" .yml)"
    log "  Installing pipeline: $pipeline_name"
    # Convert YAML to JSON for the ES API
    python3 -c "
import yaml, json, sys
with open('$pipeline_file') as f:
    d = yaml.safe_load(f)
print(json.dumps(d))
" | curl -sf -X PUT "$ES_URL/_ingest/pipeline/$pipeline_name" \
      -H 'Content-Type: application/json' \
      -d @- > /dev/null
done

# Create index templates for each data stream
for ds in kdc directory_access directory_errors ca_audit ipa_api; do
    log "  Creating index template for logs-freeipa.$ds"
    curl -sf -X PUT "$ES_URL/_index_template/logs-freeipa.$ds" \
      -H 'Content-Type: application/json' \
      -d "{
        \"index_patterns\": [\"logs-freeipa.$ds-*\"],
        \"data_stream\": {},
        \"priority\": 200,
        \"template\": {
          \"settings\": {
            \"default_pipeline\": \"freeipa-$ds\"
          }
        }
      }" > /dev/null
done

# Phase 3: Enroll test runner as IPA client
log "Phase 3: Enrolling test runner as IPA client..."
echo "$IPA_ADMIN_PASSWORD" | kinit admin@EXAMPLE.TEST 2>/dev/null || {
    # Configure krb5 manually if ipa-client-install isn't feasible
    cat > /etc/krb5.conf <<KRBEOF
[libdefaults]
  default_realm = EXAMPLE.TEST
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false

[realms]
  EXAMPLE.TEST = {
    kdc = ipa.example.test
    admin_server = ipa.example.test
  }

[domain_realm]
  .example.test = EXAMPLE.TEST
  example.test = EXAMPLE.TEST
KRBEOF
    echo "$IPA_ADMIN_PASSWORD" | kinit admin@EXAMPLE.TEST
}
log "  Kerberos ticket obtained for admin"

# Phase 4: Create test users and groups in FreeIPA
log "Phase 4: Creating test users and groups..."
for i in $(seq 1 20); do
    ipa user-add "testuser$i" --first "Test" --last "User$i" --password <<< "$(printf '%s\n%s\n' 'Passw0rd!' 'Passw0rd!')" 2>/dev/null || true
done
ipa group-add testgroup 2>/dev/null || true
ipa group-add-member testgroup --users=testuser1 2>/dev/null || true
log "  Created 20 test users and 1 test group"

# Phase 5: Import and enable detection rules
log "Phase 5: Importing detection rules..."
import_count=0
while IFS= read -r rule_json; do
    result=$(curl -sf -X POST "$KIBANA_URL/api/detection_engine/rules" \
        -H 'Content-Type: application/json' \
        -H 'kbn-xsrf: true' \
        -d "$rule_json" 2>&1) || true
    if echo "$result" | grep -q '"rule_id"'; then
        import_count=$((import_count + 1))
    fi
done < /rules/freeipa_rules.ndjson
log "  Imported $import_count detection rules"

# Enable all FreeIPA rules
curl -sf -X POST "$KIBANA_URL/api/detection_engine/rules/_bulk_action" \
    -H 'Content-Type: application/json' \
    -H 'kbn-xsrf: true' \
    -d '{
        "action": "enable",
        "query": "alert.attributes.tags:\"Data Source: FreeIPA\""
    }' > /dev/null
log "  Enabled all FreeIPA detection rules"

# Phase 6: Run test cases
log "Phase 6: Running test cases..."
log ""

for test_file in /tests/test_*.sh; do
    test_name=$(basename "$test_file" .sh | sed 's/^test_//')
    log "--- Running: $test_name ---"

    if bash "$test_file"; then
        PASS=$((PASS + 1))
        RESULTS+=("PASS  $test_name")
        log "  PASS"
    else
        exit_code=$?
        if [ $exit_code -eq 77 ]; then
            SKIP=$((SKIP + 1))
            RESULTS+=("SKIP  $test_name")
            log "  SKIP"
        else
            FAIL=$((FAIL + 1))
            RESULTS+=("FAIL  $test_name")
            log "  FAIL"
        fi
    fi
    log ""
done

# Phase 7: Report
log "=== Results ==="
for r in "${RESULTS[@]}"; do
    log "  $r"
done
log ""
log "Total: $((PASS + FAIL + SKIP))  Pass: $PASS  Fail: $FAIL  Skip: $SKIP"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
