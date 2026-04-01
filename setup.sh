#!/usr/bin/env bash
# One-command setup for FreeIPA detection rule testing.
#
# Usage:
#   ./setup.sh --fleet-url https://fleet:8220 --token <enrollment-token> [--agent-version 9.3.2]
#
# Prerequisites:
#   - Podman installed
#   - FreeIPA integration installed in your Fleet (via Kibana > Integrations)
#   - An agent policy with the FreeIPA integration added
#   - The enrollment token for that policy
#
# This script will:
#   1. Start a FreeIPA server in Podman
#   2. Install and enroll Elastic Agent
#   4. Create test users for attack simulations
#   5. Import detection rules into Kibana
#   6. Print next steps

set -euo pipefail

FLEET_URL=""
TOKEN=""
AGENT_VERSION="9.3.2"
KIBANA_URL=""
IPA_PASSWORD="${IPA_ADMIN_PASSWORD:-}"
INSECURE="--insecure"

usage() {
    echo "Usage: $0 --fleet-url <URL> --token <TOKEN> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --fleet-url URL       Fleet Server URL (e.g. https://fleet:8220)"
    echo "  --token TOKEN         Fleet enrollment token"
    echo ""
    echo "Optional:"
    echo "  --agent-version VER   Elastic Agent version (default: 9.3.2)"
    echo "  --kibana-url URL      Kibana URL for rule import (e.g. https://kibana:5601)"
    echo "  --kibana-user USER    Kibana username (default: elastic)"
    echo "  --kibana-pass PASS    Kibana password"
    echo "  --ca-cert PATH        CA certificate for Fleet TLS (disables --insecure)"
    echo "  --ipa-password PASS   FreeIPA admin password (required)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --fleet-url)    FLEET_URL="$2"; shift 2 ;;
        --token)        TOKEN="$2"; shift 2 ;;
        --agent-version) AGENT_VERSION="$2"; shift 2 ;;
        --kibana-url)   KIBANA_URL="$2"; shift 2 ;;
        --kibana-user)  KIBANA_USER="$2"; shift 2 ;;
        --kibana-pass)  KIBANA_PASS="$2"; shift 2 ;;
        --ca-cert)      CA_CERT="$2"; INSECURE="--certificate-authorities=$2"; shift 2 ;;
        --ipa-password) IPA_PASSWORD="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

[ -z "$FLEET_URL" ] && echo "Error: --fleet-url is required" && usage
[ -z "$TOKEN" ] && echo "Error: --token is required" && usage

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Step 1: Starting FreeIPA server ==="
echo "This takes 3-5 minutes on first run."
IPA_ADMIN_PASSWORD="$IPA_PASSWORD" podman compose -f "$SCRIPT_DIR/podman-compose.yml" up -d

echo "Waiting for FreeIPA to become healthy..."
for i in $(seq 1 60); do
    status=$(podman inspect --format='{{.State.Health.Status}}' freeipa 2>/dev/null || echo "starting")
    if [ "$status" = "healthy" ]; then
        echo "FreeIPA is healthy."
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "Error: FreeIPA did not become healthy in 30 minutes."
        echo "Check logs: podman logs freeipa"
        exit 1
    fi
    sleep 30
done

echo ""

echo ""
echo "=== Step 2: Installing Elastic Agent ==="
podman exec freeipa bash -c "
curl -sL https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${AGENT_VERSION}-linux-x86_64.tar.gz | tar xz -C /opt/
/opt/elastic-agent-${AGENT_VERSION}-linux-x86_64/elastic-agent install --non-interactive \
    --url='$FLEET_URL' \
    --enrollment-token='$TOKEN' \
    $INSECURE
"

echo ""
echo "=== Step 3: Creating test users ==="
podman cp "$SCRIPT_DIR/scripts/create-test-users.sh" freeipa:/tmp/create-test-users.sh
IPA_ADMIN_PASSWORD="$IPA_PASSWORD" podman exec -e IPA_ADMIN_PASSWORD="$IPA_PASSWORD" freeipa bash /tmp/create-test-users.sh
"

echo ""
echo "=== Step 4: Importing detection rules ==="
if [ -n "$KIBANA_URL" ]; then
    AUTH=""
    if [ -n "${KIBANA_USER:-}" ] && [ -n "${KIBANA_PASS:-}" ]; then
        AUTH="-u $KIBANA_USER:$KIBANA_PASS"
    fi
    imported=0
    while IFS= read -r rule_json; do
        result=$(curl -sf $AUTH -k -X POST "$KIBANA_URL/api/detection_engine/rules" \
            -H 'Content-Type: application/json' \
            -H 'kbn-xsrf: true' \
            -d "$rule_json" 2>&1) || true
        if echo "$result" | grep -q '"rule_id"'; then
            imported=$((imported + 1))
        fi
    done < "$SCRIPT_DIR/rules/freeipa_rules.ndjson"
    echo "Imported $imported detection rules."

    # Enable all FreeIPA rules
    curl -sf $AUTH -k -X POST "$KIBANA_URL/api/detection_engine/rules/_bulk_action" \
        -H 'Content-Type: application/json' \
        -H 'kbn-xsrf: true' \
        -d '{"action": "enable", "query": "alert.attributes.tags:\"Data Source: FreeIPA\""}' >/dev/null 2>&1
    echo "Enabled all FreeIPA detection rules."
else
    echo "Skipped (no --kibana-url provided)."
    echo "Import manually: curl -X POST <KIBANA>/api/detection_engine/rules -H 'kbn-xsrf: true' -d @rules/freeipa_rules.ndjson"
fi

echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "FreeIPA server:  ipa.example.test (inside Podman)"
echo "Admin password:  $IPA_PASSWORD"
echo "Realm:           EXAMPLE.TEST"
echo ""
echo "Wait ~2 minutes for data to start flowing, then run attack simulations:"
echo ""
echo "  # Run all attacks:"
echo "  for t in tests/test_*.sh; do podman exec freeipa bash \$t; done"
echo ""
echo "  # Run a single attack:"
echo "  podman exec freeipa bash tests/test_01_kerberos_brute_force.sh"
echo ""
echo "  # Check alerts in Kibana:"
echo "  # Security > Alerts > filter by 'Data Source: FreeIPA'"
echo ""
