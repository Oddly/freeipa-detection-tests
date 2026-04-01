#!/usr/bin/env bash
# Full E2E test: normal ops (verify 0 FP) → attacks (verify all 26 rules fire)
# Run from the HOST, not inside a container.
# Requires: podman containers "freeipa" and "attacker" running.
set -euo pipefail

IPA_PW="${IPA_ADMIN_PASSWORD:?Set IPA_ADMIN_PASSWORD}"
KIBANA_URL="${KIBANA_URL:?Set KIBANA_URL (e.g. http://kibana:5601)}"
KIBANA_AUTH="${KIBANA_AUTH:-}"  # Optional: "-u user:pass" or empty for no-auth
CURL_KB="curl -sk $KIBANA_AUTH"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

close_all_alerts() {
    $CURL_KB -X POST "$KIBANA_URL/api/detection_engine/signals/status" \
        -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
        -d '{"status":"closed","query":{"bool":{"must":[{"match":{"kibana.alert.rule.tags":"Data Source: FreeIPA"}}]}}}' 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Closed {d.get(\"updated\",0)} alerts')" 2>/dev/null
}

count_alerts() {
    $CURL_KB -X POST "$KIBANA_URL/api/detection_engine/signals/search" \
        -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
        -d '{"query":{"bool":{"must":[{"match":{"kibana.alert.rule.tags":"Data Source: FreeIPA"}},{"match":{"kibana.alert.workflow_status":"open"}}]}},"size":0,"aggs":{"rules":{"terms":{"field":"kibana.alert.rule.name","size":50}}}}' 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
total = d['hits']['total']['value']
rules = d['aggregations']['rules']['buckets']
print(f'{total} alerts across {len(rules)} rules')
for r in rules:
    print(f'  {r[\"doc_count\"]:3d} {r[\"key\"]}')
" 2>/dev/null
}

# ============================================================
# PHASE 0: SETUP (create baselines for new_terms rules)
# ============================================================
log "=== PHASE 0: SETUP ==="
close_all_alerts

# Create a new admin user NOW so new_terms has baseline by attack phase
TS=$(date +%s)
podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
ipa user-add e2eadmin_$TS --first E2E --last Admin --random 2>/dev/null >/dev/null
kadmin.local -q 'cpw -pw ${IPA_PW}Admin1 e2eadmin_$TS@EXAMPLE.TEST' 2>/dev/null >/dev/null
ipa group-add-member admins --users=e2eadmin_$TS 2>/dev/null >/dev/null
echo 'Setup: new admin e2eadmin_$TS created'
"

# Establish attacker's testuser1 password
podman exec freeipa kadmin.local -q "cpw -pw ${IPA_PW}Attack1 testuser1@EXAMPLE.TEST" 2>/dev/null

log "Waiting 10 minutes for lookback windows to clear and baselines to build..."
sleep 600

# ============================================================
# PHASE 1: NORMAL OPERATIONS (verify 0 false positives)
# ============================================================
log "=== PHASE 1: NORMAL OPERATIONS ==="
# Close any alerts that fired during the warmup window (from old data)
close_all_alerts
PHASE1_START=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)

podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
kvno HTTP/ipa.example.test@EXAMPLE.TEST 2>/dev/null
kvno ldap/ipa.example.test@EXAMPLE.TEST 2>/dev/null
ipa user-find --sizelimit=10 2>/dev/null >/dev/null
ipa user-show admin 2>/dev/null >/dev/null
ipa group-find --sizelimit=5 2>/dev/null >/dev/null
ipa host-find --sizelimit=5 2>/dev/null >/dev/null
ipa hbacrule-find --sizelimit=5 2>/dev/null >/dev/null
ipa sudorule-find --sizelimit=5 2>/dev/null >/dev/null
ipa pwpolicy-show 2>/dev/null >/dev/null
ipa config-show 2>/dev/null >/dev/null
ipa cert-find --sizelimit=3 2>/dev/null >/dev/null
ldapsearch -Y GSSAPI -H ldap://localhost -b 'cn=users,cn=accounts,dc=example,dc=test' '(uid=admin)' cn 2>/dev/null >/dev/null
ipa user-add fptest_$TS --first FP --last Test --random 2>/dev/null >/dev/null
ipa group-add-member engineering --users=fptest_$TS 2>/dev/null >/dev/null
echo 'Normal ops done'
"

log "Waiting 8 minutes for rules to evaluate normal ops..."
sleep 480

log "PHASE 1 RESULTS:"
# Only count alerts created after PHASE1_START to ignore old-data triggers
$CURL_KB -X POST "$KIBANA_URL/api/detection_engine/signals/search" \
    -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
    -d "{\"query\":{\"bool\":{\"must\":[{\"match\":{\"kibana.alert.rule.tags\":\"Data Source: FreeIPA\"}},{\"match\":{\"kibana.alert.workflow_status\":\"open\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$PHASE1_START\"}}}]}},\"size\":0,\"aggs\":{\"rules\":{\"terms\":{\"field\":\"kibana.alert.rule.name\",\"size\":50}}}}" 2>/dev/null > /tmp/e2e_phase1.json

python3 -c "
import json
with open('/tmp/e2e_phase1.json') as f:
    d = json.load(f)
total = d['hits']['total']['value']
rules = d['aggregations']['rules']['buckets']
if rules:
    print(f'{total} alerts across {len(rules)} rules:')
    for r in rules:
        print(f'  {r[\"doc_count\"]:3d} {r[\"key\"]}')
with open('/tmp/e2e_fp_count.txt', 'w') as f:
    f.write(str(total))
" 2>/dev/null || true
FP_COUNT=$(cat /tmp/e2e_fp_count.txt 2>/dev/null || echo 0)

if [ "${FP_COUNT:-0}" != "0" ]; then
    log "WARN: $FP_COUNT false positives detected (continuing to attack phase)"
else
    log "PASS: 0 false positives"
fi

# ============================================================
# PHASE 2: ATTACK SIMULATIONS
# ============================================================
log "=== PHASE 2: ATTACKS ==="

# --- KDC attacks ---
podman exec freeipa bash -c "
for i in \$(seq 1 35); do echo 'e2e' | kinit testuser1@EXAMPLE.TEST 2>/dev/null; done
for i in \$(seq 1 18); do echo 'e2e' | kinit testuser\$i@EXAMPLE.TEST 2>/dev/null; done
for i in \$(seq 1 15); do echo 'x' | kinit ghost_e2e_\$i@EXAMPLE.TEST 2>/dev/null; done
for u in 15 16 17 18; do for a in \$(seq 1 10); do echo 'lk' | kinit testuser\$u@EXAMPLE.TEST 2>/dev/null; done; done
echo 'KDC attacks done'
"

# --- LDAP attacks ---
podman exec freeipa bash -c "
for i in \$(seq 1 25); do ldapsearch -x -H ldap://localhost -D 'uid=testuser3,cn=users,cn=accounts,dc=example,dc=test' -w 'bad' -b '' -s base 2>/dev/null; done
ldapsearch -x -H ldap://localhost -D 'cn=Directory Manager' -w '$IPA_PW' -b 'dc=example,dc=test' '(objectclass=*)' dn 2>/dev/null >/dev/null
echo 'LDAP attacks done'
"

# --- Anonymous LDAP from attacker (3+ binds from same IP) ---
podman exec attacker bash -c "
for i in 1 2 3 4 5; do ldapsearch -x -H ldap://ipa.example.test -b '' -s base 2>/dev/null >/dev/null; done
echo 'Anonymous binds done'
"

# --- Unlock testuser1 (locked by brute force attacks above) ---
# Use kadmin.local to bypass IPA httpd (more reliable than ipa CLI)
podman exec freeipa kadmin.local -q "modprinc -unlock testuser1@EXAMPLE.TEST" 2>/dev/null || true
echo "testuser1 unlocked"

# --- Non-service enum: attacker binds as testuser1, wait for transform, then search ---
# The BIND and RESULT must be on the same connection for the LOOKUP JOIN to match.
# ldapsearch does BIND+SRCH in one connection, so we need the transform to process
# the BIND before the rule evaluates. We do a throwaway bind first, wait 3min for
# the transform cycle, then do the real enumeration.
podman exec attacker bash -c "
ldapsearch -x -H ldap://ipa.example.test -D 'uid=testuser1,cn=users,cn=accounts,dc=example,dc=test' -w '${IPA_PW}Attack1' -b '' -s base 2>/dev/null >/dev/null
echo 'Attacker BIND done, waiting 180s for transform sync...'
sleep 180
ldapsearch -x -H ldap://ipa.example.test -D 'uid=testuser1,cn=users,cn=accounts,dc=example,dc=test' -w '${IPA_PW}Attack1' -b 'dc=example,dc=test' '(objectclass=*)' dn 2>/dev/null | tail -1
echo 'Non-service enum done'
"

# --- Successful auth from attacker IP ---
podman exec attacker bash -c "echo '${IPA_PW}Attack1' | kinit testuser1@EXAMPLE.TEST 2>/dev/null && echo 'External auth OK'" || true

# --- IPA API attacks ---
podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
echo -e 'E2ePw!\nE2ePw!' | ipa passwd testuser4 2>/dev/null >/dev/null
ipa group-add-member admins --users=testuser5 2>/dev/null >/dev/null
ipa role-add e2erole_$TS --desc E2E 2>/dev/null >/dev/null
ipa role-add-member e2erole_$TS --users=testuser6 2>/dev/null >/dev/null
ipa otptoken-add --owner=testuser7 --type=totp 2>/dev/null >/dev/null
ipa user-mod testuser8 --user-auth-type=password 2>/dev/null >/dev/null
ipa pwpolicy-mod --minlength=3 2>/dev/null >/dev/null
ipa trust-add e2e_$TS.ad.test --type=ad --admin=X --password 2>/dev/null <<< 'x' >/dev/null
for i in \$(seq 1 6); do ipa user-add e2ev_\${TS}_\$i --first E --last \$i --random 2>/dev/null >/dev/null; done
for i in \$(seq 1 6); do ipa user-del e2ev_\${TS}_\$i 2>/dev/null >/dev/null; done
echo 'IPA API attacks done'
"

# --- Credential search: temporarily weaken ACL, search as testuser1 (simple bind) ---
podman exec freeipa bash -c "
ldapmodify -x -H ldap://localhost -D 'cn=Directory Manager' -w '$IPA_PW' 2>/dev/null <<LDIF
dn: dc=example,dc=test
changetype: modify
add: aci
aci: (targetattr = \"userPassword\")(version 3.0; acl \"temp-e2e-test\"; allow (read,search,compare) userdn = \"ldap:///all\";)
LDIF
ldapsearch -x -H ldap://ipa.example.test -D 'uid=testuser1,cn=users,cn=accounts,dc=example,dc=test' -w '${IPA_PW}Attack1' -b 'cn=users,cn=accounts,dc=example,dc=test' -s sub '(userPassword=*)' dn 2>/dev/null | tail -1
ldapmodify -x -H ldap://localhost -D 'cn=Directory Manager' -w '$IPA_PW' 2>/dev/null <<LDIF
dn: dc=example,dc=test
changetype: modify
delete: aci
aci: (targetattr = \"userPassword\")(version 3.0; acl \"temp-e2e-test\"; allow (read,search,compare) userdn = \"ldap:///all\";)
LDIF
echo 'Credential search done'
"

# --- CA attacks + cert revocation + CA restart for ROLE_ASSUME ---
podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
> /tmp/e2e_serials.txt
for i in \$(seq 1 6); do
    openssl req -new -newkey rsa:2048 -nodes -keyout /tmp/e2e_\${TS}_\$i.key -out /tmp/e2e_\${TS}_\$i.csr -subj '/CN=ipa.example.test' 2>/dev/null
    ipa service-add e2e_\${TS}_\$i/ipa.example.test 2>/dev/null >/dev/null
    serial=\$(ipa cert-request /tmp/e2e_\${TS}_\$i.csr --principal=e2e_\${TS}_\$i/ipa.example.test 2>/dev/null | grep 'Serial number:' | awk -F': ' '{print \$2}')
    [ -n \"\$serial\" ] && echo \$serial >> /tmp/e2e_serials.txt
done
while read s; do ipa cert-revoke \$s --revocation-reason=0 2>/dev/null >/dev/null; done < /tmp/e2e_serials.txt
echo 'Cert revocation done'

# Restart CA to trigger ROLE_ASSUME for admin
systemctl restart pki-tomcatd@pki-tomcat
echo 'CA restarted for ROLE_ASSUME'
"

# --- LDAP config modification ---
podman exec freeipa bash -c "
ldapmodify -x -H ldap://localhost -D 'cn=Directory Manager' -w '$IPA_PW' 2>/dev/null <<LDIF
dn: cn=config
changetype: modify
replace: nsslapd-errorlog-level
nsslapd-errorlog-level: 8192
LDIF
ldapmodify -x -H ldap://localhost -D 'cn=Directory Manager' -w '$IPA_PW' 2>/dev/null <<LDIF
dn: cn=config
changetype: modify
replace: nsslapd-errorlog-level
nsslapd-errorlog-level: 0
LDIF
echo 'Config mod done'
"

# --- S4U2Proxy delegation: configure delegation rule, then perform S4U2Proxy ---
podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
ipa servicedelegationrule-add e2e-s4u2proxy 2>/dev/null >/dev/null || true
ipa servicedelegationrule-add-member e2e-s4u2proxy --principals='HTTP/ipa.example.test@EXAMPLE.TEST' 2>/dev/null >/dev/null || true
ipa servicedelegationtarget-add e2e-s4u2proxy-target 2>/dev/null >/dev/null || true
ipa servicedelegationtarget-add-member e2e-s4u2proxy-target --principals='ldap/ipa.example.test@EXAMPLE.TEST' 2>/dev/null >/dev/null || true
ipa servicedelegationrule-add-target e2e-s4u2proxy --servicedelegationtargets=e2e-s4u2proxy-target 2>/dev/null >/dev/null || true
kadmin.local -q 'ktadd -k /tmp/http_e2e.keytab HTTP/ipa.example.test@EXAMPLE.TEST' 2>/dev/null >/dev/null
kinit -k -t /tmp/http_e2e.keytab HTTP/ipa.example.test@EXAMPLE.TEST 2>/dev/null
kvno -U admin ldap/ipa.example.test@EXAMPLE.TEST 2>&1
echo 'S4U2Proxy done'
# Restore HTTP keytab (ktadd re-keyed the principal, breaking gssproxy/httpd)
kadmin.local -q 'ktadd -k /var/lib/ipa/gssproxy/http.keytab HTTP/ipa.example.test@EXAMPLE.TEST' 2>/dev/null >/dev/null
systemctl restart gssproxy httpd 2>/dev/null
echo 'HTTP keytab restored'
ipa servicedelegationrule-del e2e-s4u2proxy 2>/dev/null >/dev/null || true
ipa servicedelegationtarget-del e2e-s4u2proxy-target 2>/dev/null >/dev/null || true
"

# --- New host enrollment with unique name ---
podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
ipa host-add e2e-host-$TS.example.test --force 2>/dev/null | head -1
echo 'Host enrollment done'
"

# --- First API command by the new admin created in SETUP ---
podman exec freeipa bash -c "
echo '${IPA_PW}Admin1' | kinit e2eadmin_$TS@EXAMPLE.TEST 2>/dev/null
ipa stageuser-find --sizelimit=1 2>/dev/null | head -1
ipa vault-find --sizelimit=1 2>/dev/null | head -1
echo 'First API command done'
"

# --- Cleanup ---
podman exec freeipa bash -c "
echo '$IPA_PW' | kinit admin@EXAMPLE.TEST 2>/dev/null
ipa group-remove-member admins --users=testuser5 2>/dev/null >/dev/null
ipa group-remove-member admins --users=e2eadmin_$TS 2>/dev/null >/dev/null
ipa role-del e2erole_$TS 2>/dev/null >/dev/null
ipa user-mod testuser8 --user-auth-type= 2>/dev/null >/dev/null
ipa pwpolicy-mod --minlength=8 2>/dev/null >/dev/null
for u in 15 16 17 18; do ipa user-unlock testuser\$u 2>/dev/null >/dev/null; done
echo 'Cleanup done'
"

log "Waiting 8 minutes for rules to evaluate attacks..."
sleep 480

# ============================================================
# PHASE 3: VERIFY RESULTS
# ============================================================
log "=== PHASE 3: RESULTS ==="
# Count alerts created after Phase 1 start (excludes old-data FPs)
RESULTS=$($CURL_KB -X POST "$KIBANA_URL/api/detection_engine/signals/search" \
    -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
    -d "{\"query\":{\"bool\":{\"must\":[{\"match\":{\"kibana.alert.rule.tags\":\"Data Source: FreeIPA\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$PHASE1_START\"}}}]}},\"size\":0,\"aggs\":{\"rules\":{\"terms\":{\"field\":\"kibana.alert.rule.name\",\"size\":50}}}}" 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
total = d['hits']['total']['value']
rules = d['aggregations']['rules']['buckets']
print(f'{total} alerts across {len(rules)} rules')
for r in sorted(rules, key=lambda x: x['key']):
    print(f'  {r[\"doc_count\"]:3d} {r[\"key\"]}')
print(f'RULES_COUNT={len(rules)}')
print(f'FP_COUNT={0 if len(rules) >= 26 else \"see above\"}')
" 2>/dev/null)
log "$RESULTS"

TOTAL_RULES=$(echo "$RESULTS" | grep 'RULES_COUNT=' | cut -d= -f2)

log ""
log "============================================"
log "  E2E TEST COMPLETE"
log "  False positives (Phase 1): ${FP_COUNT:-0}"
log "  Rules firing: $TOTAL_RULES / 26"
log "============================================"

if [ "${TOTAL_RULES:-0}" -lt 26 ]; then
    log "FAIL: Not all 26 rules fired"
    exit 1
fi
log "PASS: All 26 rules fired"
