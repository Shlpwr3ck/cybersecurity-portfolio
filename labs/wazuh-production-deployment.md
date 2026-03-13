# Wazuh SIEM — Production Home Lab Deployment

**Status:** Active
**Date:** March 2026
**Agents:** 7 endpoints

---

## Overview

Deployed and tuned a production Wazuh SIEM stack on a home lab running 7 monitored endpoints. This covers the full deployment lifecycle — installation, agent configuration, custom rule writing, dashboard development, and authentication hardening.

---

## Infrastructure

| Component | Host | Role |
|---|---|---|
| Wazuh Manager | dead-reckoning | Alert engine, log analysis, rule evaluation |
| Wazuh Indexer | dead-reckoning | OpenSearch — stores and indexes all events |
| Wazuh Dashboard | dead-reckoning | Web UI + OpenSearch Dashboards |
| Agents | 6 additional hosts | Linux, macOS endpoints |

---

## Deployment

### Stack Installation

Installed via the official Wazuh single-node script. Key post-install hardening:

```bash
# Extend indexer startup timeout (OpenSearch is slow on boot)
sudo mkdir -p /etc/systemd/system/wazuh-indexer.service.d/
sudo tee /etc/systemd/system/wazuh-indexer.service.d/timeout.conf << 'EOF'
[Service]
TimeoutStartSec=300
EOF
sudo systemctl daemon-reload
```

### Agent Deployment

Agents deployed on Linux endpoints via the Wazuh API enrollment method. macOS agent installed manually via .pkg installer.

---

## Agent Configuration (agent.conf)

Wazuh supports centralized agent configuration via `agent.conf` — pushed from manager to all agents. Out of the box this file is empty; agents run bare defaults.

Key sections added to `/var/ossec/etc/shared/default/agent.conf`:

### File Integrity Monitoring

```xml
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/usr/bin,/bin,/sbin</directories>
  <!-- Home dir: restrict to sensitive file types only -->
  <directories check_all="yes" report_changes="yes" realtime="yes"
    restrict=".sh|.py|.conf|.key|.pem|.env">/home/user</directories>

  <!-- Reduce noise: ignore transient/cache paths -->
  <ignore>/home/user/.cache</ignore>
  <ignore>/home/user/.mozilla</ignore>
  <ignore type="sregex">.log$|.swp$|.tmp$</ignore>
</syscheck>
```

### Log Collection

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>
```

### Scheduled Commands

```xml
<localfile>
  <log_format>command</log_format>
  <command>ss -tlnp</command>
  <frequency>300</frequency>
</localfile>
```

---

## Custom Alert Tuning (local_rules.xml)

Initial deployment surfaced 8.75 million alerts — nearly all from one NVR camera host repeatedly hitting a disk-full rule. Real security events were buried.

Custom rules written to downgrade high-volume false positives:

```xml
<!-- Suppress NVR disk-full noise (rule 531 fires millions of times) -->
<rule id="100001" level="2">
  <if_sid>531</if_sid>
  <hostname>frigate</hostname>
  <description>Frigate NVR disk-full — suppressed</description>
</rule>

<!-- Downgrade routine Docker lifecycle events -->
<rule id="100002" level="3">
  <if_sid>87924</if_sid>
  <match>die|kill</match>
  <description>Docker container stopped/killed — routine</description>
</rule>

<!-- Downgrade agent queue warnings -->
<rule id="100003" level="3">
  <if_sid>7010</if_sid>
  <description>Agent queue full — informational</description>
</rule>
```

**Result:** Alert volume dropped from millions to hundreds per day; real SSH failures, FIM changes, and auth events became visible.

---

## OpenSearch User Hardening

Replaced the default `admin` account with a named admin user.

```bash
# Generate bcrypt hash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YourPassword', bcrypt.gensalt(12)).decode())"
```

Added to `/etc/wazuh-indexer/opensearch-security/internal_users.yml`:

```yaml
newadmin:
  hash: "$2y$12$..."
  reserved: false
  backend_roles:
    - "admin"
  description: "Custom admin user"
```

Applied via:
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -icl -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem
```

---

## Indexer Connector Authentication Fix

The Wazuh manager → indexer connector uses basic auth stored in a keystore. Several issues found and resolved:

**Problems:**
- Keystore had no credentials after password rotation
- ossec.conf referenced wrong cert filenames (`filebeat.pem` vs `wazuh-server.pem`)
- Client certificate entries caused 401 — `wazuh-server.pem` is not an OpenSearch admin cert
- Host configured as `0.0.0.0` instead of `127.0.0.1`

**Fix — ossec.conf indexer section:**

```xml
<indexer>
  <enabled>yes</enabled>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/filebeat/certs/root-ca.pem</ca>
    </certificate_authorities>
    <!-- No client cert — use keystore basic auth instead -->
  </ssl>
</indexer>
```

**Fix — keystore:**
```bash
sudo /var/ossec/bin/wazuh-keystore -f indexer -k username -v "yourusername"
sudo /var/ossec/bin/wazuh-keystore -f indexer -k password -v "yourpassword"
```

---

## Custom Dashboard — OpenSearch Saved Objects API

Built an 11-panel security overview dashboard via the OpenSearch Dashboards API (no UI clicking required).

Panels created:
- Total alerts (metric)
- Critical/high/medium/low severity counters (4 metrics)
- Alerts over time (timeline)
- Severity distribution (donut)
- Top agents by alert volume
- Top rule groups
- Top rules triggered
- Top source IPs

Key lesson: `rule.level` is indexed as a `keyword` type, not numeric — use `terms` aggregation, not `range`.

```bash
curl -s -k -u "user:pass" -X POST \
  "https://localhost/api/saved_objects/dashboard" \
  -H "Content-Type: application/json" \
  -H "osd-xsrf: true" \
  -d '{ "attributes": { "title": "Security Overview", "panelsJSON": "..." } }'
```

---

## Wazuh API RBAC Fix

The Wazuh API uses its own SQLite RBAC database (`/var/ossec/api/configuration/security/rbac.db`) — separate from OpenSearch auth. Passwords are scrypt-hashed.

After password rotation, the Dashboard lost API connectivity. Fixed by resetting the `wazuh-wui` account directly in the database and updating `wazuh.yml`:

```yaml
# /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: "yourpassword"
      run_as: true
```

---

## Lessons Learned

| Issue | Root Cause | Fix |
|---|---|---|
| 8.75M false positives | NVR disk-full rule firing continuously | Custom `<if_sid>` rule at level 2 |
| Indexer connector 401 | Client cert not admin-authorized in OpenSearch | Remove `<certificate>`/`<key>` from ossec.conf; use keystore auth |
| Dashboard "Invalid credentials" | API RBAC DB separate from OpenSearch auth | Reset `wazuh-wui` in rbac.db, update wazuh.yml |
| OpenSearch boot timeout | JVM cold start exceeds systemd 90s timeout | Extend `TimeoutStartSec=300` |
| FIM false positives | Browser cache and temp files triggering FIM | `<ignore>` rules and `restrict=` patterns |

---

## Skills Demonstrated

- Wazuh Manager, Indexer, Dashboard administration
- OpenSearch security model (two separate auth systems)
- Custom XML rule writing
- OpenSearch Saved Objects API (dashboard as code)
- FIM configuration and tuning
- Centralized agent configuration management
- Keystore and certificate management
