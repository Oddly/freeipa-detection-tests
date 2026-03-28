# FreeIPA Detection Rules Test Suite

Functional test suite for 16 ES|QL detection rules targeting FreeIPA identity management servers. Spins up a FreeIPA server in Podman, generates attack simulations, and verifies Elastic Security detection rules fire correctly.

## Prerequisites

- **Podman** 4.0+ (Docker will not work — FreeIPA requires systemd)
- **Elastic Agent** enrolled in a Fleet policy with the FreeIPA integration
- **Elastic Security** with the 16 FreeIPA detection rules imported and enabled

The test environment connects to an external Elasticsearch/Kibana cluster. It does not run its own stack.

## Quick Start

```bash
# 1. Start the FreeIPA server (~5 minutes on first run)
podman compose -f podman-compose.yml up -d freeipa

# 2. Wait for FreeIPA to finish installing
podman logs -f freeipa  # watch for "FreeIPA server configured."

# 3. Install Elastic Agent inside the container
podman exec freeipa bash -c '
curl -sL https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-<VERSION>-linux-x86_64.tar.gz | tar xz -C /opt/
/opt/elastic-agent-<VERSION>-linux-x86_64/elastic-agent install --non-interactive \
    --url=<FLEET_URL> \
    --enrollment-token=<TOKEN> \
    --insecure
'

# 4. Fix the KDC log symlink (required for container deployments)
podman exec freeipa bash /scripts/fix-kdc-symlink.sh

# 5. Import detection rules into Kibana
# Use the rules/freeipa_rules.ndjson file via the detection engine API

# 6. Run attack simulations
podman exec freeipa bash /tests/test_01_kerberos_brute_force.sh
```

## Targeting a Different Elasticsearch Cluster

The Elastic Agent inside the Podman container connects to your cluster via Fleet enrollment. To change the target cluster:

1. Set up Fleet Server on your target cluster
2. Create an agent policy with the FreeIPA integration installed
3. Get the enrollment token from **Fleet > Enrollment tokens**
4. Enroll the agent with your cluster's Fleet URL and token:

```bash
podman exec freeipa elastic-agent install --non-interactive \
    --url=https://your-fleet-server:8220 \
    --enrollment-token=<YOUR_TOKEN> \
    --insecure  # or --certificate-authorities=/path/to/ca.pem
```

The FreeIPA integration must be available in your cluster's package registry. If using the unreleased integration, set up a custom EPR (see below).

## Custom Elastic Package Registry

To serve unreleased integrations (like FreeIPA) alongside upstream packages:

```bash
# Run the EPR with proxy mode
docker run -d --name epr \
    -p 8080:8080 \
    -e EPR_FEATURE_PROXY_MODE=true \
    -e EPR_PROXY_TO=https://epr.elastic.co \
    -v /path/to/packages:/packages/package-registry:ro \
    --user 0 \
    docker.elastic.co/package-registry/package-registry:main

# Point Kibana at the custom EPR (kibana.yml)
xpack.fleet.registryUrl: "http://epr-host:8080"
```

Build the FreeIPA package with `elastic-package build` and place the output directory (e.g., `freeipa/0.1.2/`) under the mounted packages path.

## Project Structure

```
podman-compose.yml          Podman services (FreeIPA only, no ES/Kibana)
Dockerfile.test-runner      Rocky 9 with freeipa-client and ldap tools
Makefile                    make up / make test / make clean
filebeat/filebeat.yml       Filebeat config (alternative to Elastic Agent)
pipelines/                  Ingest pipelines from the FreeIPA integration
rules/freeipa_rules.ndjson  All 16 detection rules in Kibana import format
scripts/
  run-tests.sh              Main test orchestrator
  fix-kdc-symlink.sh        Workaround for container KDC log symlink
tests/
  lib.sh                    Shared functions (kinit, ldapsearch, alert check)
  test_01_*.sh - test_22_*.sh   One script per detection rule
```

## Detection Rules Tested

| Rule | Tactic | Data Stream |
|------|--------|-------------|
| Kerberos Brute Force | Credential Access | kdc |
| Kerberos Password Spraying | Credential Access | kdc |
| Kerberos Principal Enumeration | Reconnaissance | kdc |
| Kerberos Account Lockout Storm | Impact | kdc |
| LDAP Bind Brute Force | Credential Access | directory_access |
| LDAP Mass Data Exfiltration | Collection | directory_access |
| Password Reset by Another User | Credential Access | ipa_api |
| Admin Group Member Added | Persistence | ipa_api |
| RBAC Role/Privilege Modification | Privilege Escalation | ipa_api |
| OTP Token Manipulation | Credential Access | ipa_api |
| User Auth Type Downgrade | Defense Evasion | ipa_api |
| Password Policy Modified | Defense Evasion | ipa_api |
| AD Trust Modified | Defense Evasion | ipa_api |
| Mass Account Disable/Delete | Impact | ipa_api |
| Bulk Certificate Revocation | Defense Evasion | ca_audit |
| CA Role Assumed | Privilege Escalation | ca_audit |

## Known Issues

- **KDC log symlink**: FreeIPA containers symlink `/var/log/krb5kdc.log` to `/data/var/log/krb5kdc.log`. The Elastic Agent filestream input needs `prospector.scanner.symlinks: true` (fixed in integration v0.1.2+) or the `fix-kdc-symlink.sh` workaround.
- **IPA API requires debug=True**: The `ipa_api` data stream only works when `/etc/ipa/default.conf` has `debug = True`. Without it, the 8 API-based rules will not fire.
- **Docker not supported**: FreeIPA requires systemd which Docker cannot provide. Use Podman.
- **LDAP Mass Exfiltration threshold**: The rule fires at 500+ entries returned. Small test instances with fewer than 500 LDAP objects will need additional users created (the test scripts create 500+ users).
- **Trust Modification**: Requires `ipa-server-trust-ad` package installed. The `ipa trust-add` command will fail without a real AD domain but still generates an API log entry that triggers the rule.
- **Bulk Certificate Revocation**: Requires issuing 6+ certificates first. The test scripts create test services and issue certificates before revoking them.
