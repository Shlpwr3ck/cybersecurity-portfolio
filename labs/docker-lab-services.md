# Docker Lab Services Guide - noblehomeserver

**Created:** December 10, 2025
**Server:** noblehomeserver (192.168.x.x)
**Purpose:** Quick reference for Docker-based lab services

---

## Running Services

### 1. ntopng (Network Traffic Monitor)
- **Container:** ntopng
- **Image:** ntop/ntopng:latest
- **Access:** http://192.168.x.x:3000
- **Purpose:** Real-time network traffic monitoring and analysis
- **Auto-restart:** ✅ Configured

### 2. Pi-hole (DNS/Ad Blocker)
- **Container:** pihole
- **Image:** pihole/pihole:latest
- **Purpose:** Network-wide DNS filtering and ad blocking
- **Auto-restart:** ✅ Configured

### 3. Plex Media Server
- **Container:** plex
- **Image:** lscr.io/linuxserver/plex:latest
- **Purpose:** Media streaming server
- **Auto-restart:** ✅ Configured

---

## Quick Commands

### Check All Containers
```bash
docker ps -a
```

### Start All Services
```bash
docker start ntopng plex pihole
```

### Stop All Services
```bash
docker stop ntopng plex pihole
```

### Restart a Specific Service
```bash
# Examples:
docker restart ntopng
docker restart pihole
docker restart plex
```

### Check Logs
```bash
# View last 50 lines
docker logs ntopng --tail 50
docker logs pihole --tail 50
docker logs plex --tail 50

# Follow live logs
docker logs -f ntopng
```

### Check Container Status
```bash
docker ps | grep -E 'ntopng|pihole|plex'
```

---

## Auto-Restart Configuration

All containers are configured with `--restart=unless-stopped` which means they will:
- ✅ Auto-start when Docker starts
- ✅ Auto-start when system reboots
- ✅ Auto-restart if they crash
- ❌ NOT restart if you manually stop them

### Verify Auto-Restart Settings
```bash
docker inspect ntopng plex pihole --format '{{.Name}}: {{.HostConfig.RestartPolicy.Name}}'
```

**Expected output:**
```
/ntopng: unless-stopped
/plex: unless-stopped
/pihole: unless-stopped
```

### Change Restart Policy
```bash
# Set to always restart
docker update --restart=always ntopng

# Set to restart unless manually stopped (recommended)
docker update --restart=unless-stopped ntopng

# Disable auto-restart
docker update --restart=no ntopng
```

---

## Troubleshooting

### Container Won't Start
```bash
# Check logs for errors
docker logs ntopng

# Remove and recreate container (CAUTION: loses container-specific config)
docker rm ntopng
# Then recreate with docker run command
```

### Container Keeps Restarting
```bash
# Check if it's crashing
docker ps -a | grep ntopng

# View recent logs
docker logs ntopng --tail 100

# Check resource usage
docker stats ntopng
```

### Check Docker Service Status
```bash
sudo systemctl status docker
```

### Restart Docker Service
```bash
sudo systemctl restart docker

# All containers with restart policies will auto-start
```

---

## Service URLs

**From local network:**
- ntopng: http://192.168.x.x:3000
- Pi-hole Admin: http://192.168.x.x/admin (or configured port)
- Plex: http://192.168.x.x:32400/web

**From this machine (noblehomeserver):**
- ntopng: http://localhost:3000
- Pi-hole: http://localhost/admin
- Plex: http://localhost:32400/web

---

## What Happened on Dec 6, 2025

**ntopng stopped cleanly at 15:42:28 on Dec 6**

**Cause:** Something sent a shutdown signal to ntopng (possibly manual stop, or system event)

**Evidence from logs:**
```
06/Dec/2025 15:42:28 [main.cpp:498] Terminating...
```

This was a **clean shutdown**, not a crash. Possible causes:
- Manual `docker stop ntopng` command
- System maintenance
- Docker service restart without auto-restart policy set

**Solution:** Configured auto-restart policy so this won't happen again.

---

## Maintenance

### Update Container Images
```bash
# Pull latest images
docker pull ntop/ntopng:latest
docker pull pihole/pihole:latest
docker pull lscr.io/linuxserver/plex:latest

# Stop containers
docker stop ntopng pihole plex

# Remove old containers
docker rm ntopng pihole plex

# Recreate with new images (use original docker run commands)
# Then re-apply restart policy:
docker update --restart=unless-stopped ntopng pihole plex
```

### Clean Up Unused Images
```bash
docker image prune -a
```

### Backup Container Configurations
```bash
# Export container config
docker inspect ntopng > ~/ntopng-config-backup.json
```

---

## Security Notes

**Running Services:**
- ✅ Wazuh agent monitoring Docker host
- ✅ Snort IDS monitoring network interfaces (ens18, ens19)
- ✅ Pi-hole providing DNS filtering
- ✅ ntopng providing traffic visibility

**Network Exposure:**
- ntopng: Port 3000 (local network only)
- Pi-hole: DNS port 53 (network-wide)
- Plex: Port 32400 (media streaming)

**Container Isolation:**
- Containers run in isolated namespaces
- Limited host access
- Managed via Docker daemon

---

## Quick Startup After Reboot

**If services are down after reboot:**

```bash
# Check if Docker is running
sudo systemctl status docker

# If Docker is running but containers aren't:
docker ps -a

# Start all services
docker start ntopng plex pihole

# Verify they're running
docker ps
```

**With auto-restart configured, this should happen automatically!**

---

## Integration with Other Services

**noblehomeserver runs:**
1. **Docker containers** (ntopng, Pi-hole, Plex) - This guide
2. **Wazuh agent** - Reports to Wazuh manager on dead-reckoning (192.168.x.x)
3. **Snort IDS** - Network intrusion detection on 2 interfaces

**Network position:**
- Behind Proxmox (192.168.x.x)
- Part of 192.168.x.x/24 network
- Monitored by dead-reckoning's Wazuh SIEM

---

**File Location:** `/home/sh1pwr3ck/noble-technologies-llc/professional-development/labs/DOCKER-LAB-SERVICES-GUIDE.md`
