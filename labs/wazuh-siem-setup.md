# Wazuh Lab Startup Guide

**Created:** December 10, 2025
**Purpose:** Quick reference for starting/restarting Wazuh SIEM lab

---

## Current Lab Setup

**Services:**
- Wazuh Indexer (OpenSearch) - Port 9200
- Wazuh Manager - Port 55000
- Wazuh Dashboard - Port 443 (https)

**Status:** All services are enabled to start at boot automatically

---

## Why Services Fail After Reboot

**Problem:** Wazuh Indexer (OpenSearch) times out during boot

**Reason:**
- OpenSearch takes 30-90+ seconds to fully start
- Systemd default timeout is 90 seconds
- On slower systems or after unclean shutdown, it can exceed timeout
- Manager depends on Indexer, so it fails too

**This is normal behavior for OpenSearch-based systems**

---

## Quick Restart After Boot (Manual Recovery)

If services are down after reboot, run these commands:

```bash
# 1. Clean up any zombie processes
sudo killall -9 wazuh-execd wazuh-analysisd wazuh-syscheckd wazuh-remoted wazuh-logcollector wazuh-monitord wazuh-modulesd 2>/dev/null

# 2. Restart indexer first (it takes longest)
sudo systemctl restart wazuh-indexer

# 3. Wait 30 seconds for indexer to fully start
sleep 30

# 4. Restart manager
sudo systemctl restart wazuh-manager

# 5. Dashboard should reconnect automatically (already running)
# If not, restart it:
# sudo systemctl restart wazuh-dashboard
```

---

## Check Service Status

```bash
# Check all Wazuh services
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard

# Check if services are listening on correct ports
ss -tlnp | grep -E '(9200|55000|443)'
```

**Expected output:**
- Port 9200: Wazuh Indexer (OpenSearch)
- Port 55000: Wazuh Manager API
- Port 443: Wazuh Dashboard (HTTPS)

---

## Access Wazuh Dashboard

**URL:** https://localhost (or https://dead-reckoning)

**Credentials:** Check `/home/sh1pwr3ck/wazuh-install-files/` for passwords

---

## Permanent Fix: Increase Indexer Timeout (Optional)

If you want to prevent timeout issues, increase the systemd timeout:

```bash
# Create override directory
sudo mkdir -p /etc/systemd/system/wazuh-indexer.service.d/

# Create timeout override
sudo tee /etc/systemd/system/wazuh-indexer.service.d/timeout.conf << 'EOF'
[Service]
TimeoutStartSec=300
EOF

# Reload systemd
sudo systemctl daemon-reload

# Test restart
sudo systemctl restart wazuh-indexer
```

This gives the indexer 5 minutes (300 seconds) to start instead of 90 seconds.

---

## One-Command Lab Startup Script

Save this as `~/start-wazuh-lab.sh`:

```bash
#!/bin/bash
echo "=== Wazuh Lab Startup ==="
echo ""

echo "[1/4] Cleaning up zombie processes..."
sudo killall -9 wazuh-execd wazuh-analysisd wazuh-syscheckd wazuh-remoted wazuh-logcollector wazuh-monitord wazuh-modulesd 2>/dev/null
echo "✓ Cleanup complete"
echo ""

echo "[2/4] Starting Wazuh Indexer (this takes 30-60 seconds)..."
sudo systemctl restart wazuh-indexer
sleep 30
echo "✓ Indexer started"
echo ""

echo "[3/4] Starting Wazuh Manager..."
sudo systemctl restart wazuh-manager
sleep 10
echo "✓ Manager started"
echo ""

echo "[4/4] Checking service status..."
systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard
echo ""

echo "=== Wazuh Lab Ready ==="
echo "Dashboard: https://localhost"
echo ""
```

**Make it executable:**
```bash
chmod +x ~/start-wazuh-lab.sh
```

**Usage after reboot:**
```bash
~/start-wazuh-lab.sh
```

---

## Service Management Commands

```bash
# Start services
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-dashboard

# Stop services
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
sudo systemctl stop wazuh-dashboard

# Restart services
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-dashboard

# Check status
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard

# Check if enabled at boot
systemctl is-enabled wazuh-indexer wazuh-manager wazuh-dashboard
```

---

## Troubleshooting

### Indexer won't start
```bash
# Check logs
sudo journalctl -u wazuh-indexer -n 50

# Check if port is already in use
sudo ss -tlnp | grep 9200

# Check disk space (OpenSearch needs space)
df -h
```

### Manager won't start
```bash
# Check logs
sudo tail -f /var/ossec/logs/ossec.log

# Verify indexer is running first
systemctl status wazuh-indexer

# Check for zombie processes
ps aux | grep wazuh
```

### Dashboard can't connect
```bash
# Verify indexer is running
curl -k -u admin:admin https://localhost:9200

# Check dashboard logs
sudo journalctl -u wazuh-dashboard -n 50

# Restart dashboard
sudo systemctl restart wazuh-dashboard
```

---

## Memory Usage Note

Wazuh uses significant memory:
- Indexer: ~1.6GB RAM
- Manager: ~5-6GB RAM
- Dashboard: ~300MB RAM

**Total: ~7-8GB RAM for full stack**

If system is low on memory, services may fail to start.

---

**File Location:** `/home/sh1pwr3ck/noble-technologies-llc/professional-development/labs/WAZUH-LAB-STARTUP-GUIDE.md`
