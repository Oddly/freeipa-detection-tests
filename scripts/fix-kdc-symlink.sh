#!/usr/bin/env bash
# Fix the krb5kdc.log symlink issue for Elastic Agent filestream.
#
# FreeIPA containers symlink /var/log/krb5kdc.log -> /data/var/log/krb5kdc.log.
# The Elastic Agent's filestream input can read through the symlink, but after
# initial enrollment it may have already registered the file at offset=EOF.
# This script clears the filestream registry so the agent re-discovers the file.
#
# Run this AFTER FreeIPA finishes installing and the agent has enrolled.

set -euo pipefail

echo "[fix-kdc-symlink] Clearing filestream registry to force re-discovery..."
rm -rf /opt/Elastic/Agent/data/elastic-agent-*/run/filestream-default/registry/filebeat/* 2>/dev/null || true

echo "[fix-kdc-symlink] Restarting elastic-agent..."
systemctl restart elastic-agent

echo "[fix-kdc-symlink] Done. Agent will re-read all log files from the beginning."
