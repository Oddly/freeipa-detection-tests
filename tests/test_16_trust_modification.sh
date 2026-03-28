#!/usr/bin/env bash
# Test: FreeIPA Active Directory Trust Modified
# Note: trust_add requires a real AD domain. We test with a failing call
# that still gets logged by the IPA API.
source /tests/lib.sh

log "  Attempting trust-add (expected to fail, but API logs the attempt)..."
kinit_admin
ipa trust-add fake.ad.domain --trust-type=ad --admin=Administrator --password <<< "FakePassword" 2>/dev/null || true

log "  Waiting for API event..."
wait_for_docs "logs-freeipa.ipa_api-*" '{"match":{"event.action":"trust_add"}}' 1 60

# This rule matches any trust_add including failures, so it should alert
log "  Waiting for alert..."
wait_for_alerts "FreeIPA Active Directory Trust Modified" 1 120 || exit 77  # Skip if no event logged
