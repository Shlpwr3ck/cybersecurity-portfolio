# Wazuh OpenSearch Recovery — Shard Failure + Admin Password Reset

**Category:** SIEM Administration / Incident Response
**Date:** April 2026
**Difficulty:** Intermediate

---

## Scenario

Wazuh indexer (OpenSearch) failed to start after a host reboot, timing out after 10+ hours. The dashboard returned "Wazuh dashboard server is not ready yet" with `all shards failed` errors in logs. Admin password was also unknown — changed during a prior recovery and not documented.

---

## Symptoms

```
wazuh-indexer.service: Failed with result 'timeout'
[search_phase_execution_exception]: all shards failed
HTTP 503 on dashboard
```

---

## Root Cause

1. Indexer startup timeout → unclean shutdown → shards marked failed
2. Dashboard can't become ready without a healthy indexer
3. Admin password stale — wazuh-passwords.txt from original install no longer valid

---

## Recovery Steps

### Step 1 — Restart the Indexer

```bash
sudo systemctl restart wazuh-indexer
sudo systemctl status wazuh-indexer
```

Wait for `active (running)` before proceeding. Indexer can take 30–60 seconds.

---

### Step 2 — Verify the Indexer Responds

```bash
curl -sk -u "admin:YOURPASSWORD" "https://localhost:9200/_cluster/health"
```

If you get `Unauthorized` — the password is stale. Proceed to Step 3.

If you get cluster health JSON — skip to Step 4.

---

### Step 3 — Reset Admin Password via Admin Certificate (No Password Required)

Wazuh ships admin TLS certificates specifically for this scenario. Use `securityadmin.sh` to bypass password auth entirely.

**3a. Generate a new bcrypt hash for your new password:**

```bash
# Use Wazuh's bundled Python environment
sudo /var/ossec/framework/python/bin/python3 -c "
from werkzeug.security import generate_password_hash
print(generate_password_hash('YourNewPassword!', method='scrypt'))
"
```

**3b. Update the hash in internal_users.yml:**

```bash
sudo cp /etc/wazuh-indexer/opensearch-security/internal_users.yml \
        /etc/wazuh-indexer/opensearch-security/internal_users.yml.bak

# Edit the admin hash line
sudo nano /etc/wazuh-indexer/opensearch-security/internal_users.yml
# Find: admin: / hash: "$2y$12$..."
# Replace hash value with output from 3a
```

**3c. Apply the updated config using admin certs:**

```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -icl -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -h 127.0.0.1
```

Expected output: `SUCC: Configuration for 'internalusers' created or updated` for each config type, ending with `Done with success`.

**3d. Test the new password:**

```bash
curl -sk -u "admin:YourNewPassword!" "https://localhost:9200/_cluster/health"
```

---

### Step 4 — Retry Failed Shards

After prolonged downtime, shards may be stuck in a failed state even after the indexer comes back. Force a reroute:

```bash
curl -sk -u "admin:YourNewPassword!" \
  -X POST "https://localhost:9200/_cluster/reroute?retry_failed=true"
```

Expected response: `{"acknowledged":true,...}`

Check cluster health:

```bash
curl -sk -u "admin:YourNewPassword!" "https://localhost:9200/_cluster/health" | python3 -m json.tool
```

- `"status": "green"` — all shards healthy
- `"status": "yellow"` — normal for single-node (replica shards unassigned, not a problem)
- `"status": "red"` — shards still failing, check disk space and memory

---

### Step 5 — Restart the Dashboard

```bash
sudo systemctl restart wazuh-dashboard
```

Dashboard takes 45–90 seconds to initialize. Monitor:

```bash
sudo journalctl -u wazuh-dashboard -f
```

Wait for: `Server running at https://0.0.0.0:PORT`

---

### Step 6 — Reset Wazuh API Users (if needed)

The Wazuh API (port 55000) uses a separate SQLite database from the indexer. If API passwords are also unknown:

```bash
# Find the API user database
sudo sqlite3 /var/ossec/api/configuration/security/rbac.db "SELECT id, username FROM Users;"

# Generate new hash using Wazuh's Python
sudo /var/ossec/framework/python/bin/python3 -c "
from werkzeug.security import generate_password_hash
print(generate_password_hash('NewAPIPassword!', method='scrypt'))
"

# Update the hash
sudo sqlite3 /var/ossec/api/configuration/security/rbac.db \
  "UPDATE Users SET password='HASH_FROM_ABOVE' WHERE username='wazuh';"

# Restart manager to apply
sudo systemctl restart wazuh-manager

# Test
curl -sk -u "wazuh:NewAPIPassword!" \
  -X POST "https://localhost:55000/security/user/authenticate"
```

---

## Checklist

```
[ ] wazuh-indexer running (systemctl status)
[ ] Cluster health yellow or green
[ ] Admin password documented in password manager
[ ] Dashboard accessible on HTTPS
[ ] Wazuh API responding (port 55000)
[ ] Agents showing connected in dashboard
```

---

## Notes

- Single-node OpenSearch will always show `yellow` (replicas can't be assigned to the only node) — this is normal
- The `wazuh-passwords.txt` file from install becomes stale if passwords are changed — don't rely on it
- Admin certs at `/etc/wazuh-indexer/certs/admin.pem` are the recovery key — protect them
- API users (wazuh, wazuh-wui) are in SQLite at `/var/ossec/api/configuration/security/rbac.db` — separate from indexer users
