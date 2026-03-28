#!/usr/bin/env bash
# Test: FreeIPA Bulk Certificate Revocation
# This test is skipped by default because revoking real certificates
# in a fresh FreeIPA environment is destructive and complex to set up.
# It requires issuing multiple certificates first, then revoking them.
source /tests/lib.sh

log "  SKIP: Bulk cert revocation requires pre-issued certificates"
log "  To test manually: issue 6+ certs with ipa cert-request, then revoke them"
exit 77
