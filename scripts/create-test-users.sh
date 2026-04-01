#!/usr/bin/env bash
# Create test users with known passwords that don't require first-use change.
# Uses kadmin.local to bypass FreeIPA's password policy.
#
# Run inside the FreeIPA container: podman exec freeipa bash /scripts/create-test-users.sh

set -euo pipefail
IPA_PASSWORD="${IPA_ADMIN_PASSWORD:?Set IPA_ADMIN_PASSWORD}"

echo "$IPA_PASSWORD" | kinit admin@EXAMPLE.TEST 2>/dev/null

echo "Creating 20 test users with known passwords..."
for i in $(seq 1 20); do
    ipa user-add "testuser$i" --first "Test" --last "User$i" --random 2>/dev/null >/dev/null || true
    kadmin.local -q "cpw -pw TestUser${i}Pass! testuser$i@EXAMPLE.TEST" 2>/dev/null >/dev/null
done

echo "Creating 500 bulk users for LDAP exfil threshold..."
for i in $(seq 100 599); do
    ipa user-add "bulkuser$i" --first "Bulk" --last "User$i" --random 2>/dev/null >/dev/null || true
done

echo "Creating test services for certificate tests..."
for i in $(seq 1 8); do
    ipa service-add "test$i/ipa.example.test" 2>/dev/null >/dev/null || true
done

echo "Installing ipa-server-trust-ad for trust tests..."
dnf install -y ipa-server-trust-ad 2>/dev/null >/dev/null || true

echo "Done. Test user passwords: TestUser<N>Pass! (e.g. TestUser1Pass!)"
