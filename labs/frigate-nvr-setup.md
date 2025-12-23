# Frigate NVR Installation Summary

**Date:** December 23, 2025
**VM:** frigate-nvr (192.168.1.60)
**Status:** ✅ Installed and Running

---

## Installation Details

### System Information
- **IP Address:** 192.168.1.60
- **Hostname:** frigate-nvr
- **OS:** Ubuntu 24.04 (Noble)
- **Virtualization:** Proxmox LXC Container (ID: 300)
- **User:** root
- **Disk:** 32GB (3% used)
- **Wazuh Agent:** Agent 007 - Active

### Installed Components
- **Docker:** v29.1.3
- **Docker Compose:** v5.0.0
- **Frigate:** stable (ghcr.io/blakeblackshear/frigate:stable)
- **go2rtc:** v1.9.9 (bundled with Frigate)

### Directory Structure
```
/opt/frigate/
├── config/
│   └── config.yml          # Frigate configuration
├── storage/                # Recordings and snapshots
├── media/                  # Additional media storage
└── docker-compose.yml      # Container configuration
```

---

## Access Information

### Web Interface
- **URL:** http://192.168.1.60:5000
- **Status:** ✅ Running and accessible
- **Authentication:** None (internal network only)

### Ports
- **5000:** Web UI (HTTP)
- **8554:** RTSP streams
- **8555:** WebRTC (TCP/UDP)
- **1984:** go2rtc API (internal)

### SSH Access
- **Command:** `ssh root@192.168.1.60`
- **Key:** Claude Code SSH key installed
- **Status:** ✅ Configured

---

## Current Configuration

### Detector
- **Type:** CPU (software detection)
- **Performance:** Limited - suitable for 1-2 cameras max
- **Planned Upgrade:** Coral TPU USB or PCIe accelerator

### Cameras
- **Configured:** 0
- **Status:** Placeholder configuration in place
- **Planned:** Pending camera purchase

### Recording Settings
- **Enabled:** Yes
- **Retention:** 7 days (motion-based)
- **Events Retention:** 14 days
- **Snapshots:** Enabled, 7 days retention

### Object Detection
- **Tracked Objects:**
  - person
  - car
  - dog
  - cat
- **Filters:**
  - Person: min_area=5000, threshold=0.7

---

## Docker Configuration

### Container Settings
```yaml
Container: frigate
Image: ghcr.io/blakeblackshear/frigate:stable
Network Mode: host (LXC compatibility)
Restart Policy: unless-stopped
Shared Memory: 256MB
Temp Cache: 1GB (tmpfs)
```

### Important Notes
- **Network Mode:** Using `host` mode due to LXC container restrictions
- **Security:** AppArmor unconfined (required for LXC)
- **GPU Acceleration:** Not available in LXC container
- **Hardware Accel:** Will add when Coral TPU is installed

---

## Next Steps (When Hardware Arrives)

### 1. Add Coral TPU AI Accelerator

**USB Coral:**
```yaml
# In docker-compose.yml, add:
devices:
  - /dev/bus/usb:/dev/bus/usb

# In config.yml, update:
detectors:
  coral:
    type: edgetpu
    device: usb
```

**PCIe Coral (if available):**
```yaml
devices:
  - /dev/apex_0:/dev/apex_0

detectors:
  coral:
    type: edgetpu
    device: pci
```

### 2. Add IP Cameras

**Example camera configuration:**
```yaml
cameras:
  front_door:
    ffmpeg:
      inputs:
        - path: rtsp://username:password@192.168.1.XXX:554/stream
          roles:
            - detect
            - record
    detect:
      width: 1920
      height: 1080
      fps: 5
    record:
      enabled: True
      retain:
        days: 7
    snapshots:
      enabled: True
      retain:
        default: 7
```

### 3. Performance Tuning

**After adding cameras, monitor:**
- CPU usage (should drop significantly with Coral TPU)
- Memory usage (increase shm_size if needed)
- Storage usage (adjust retention as needed)
- Detection accuracy (tune object filters)

---

## Monitoring & Maintenance

### Wazuh SIEM
- **Agent ID:** 007
- **Status:** Active
- **Monitoring:** System health, security events, resource usage

### Docker Management
```bash
# View container status
docker ps

# View logs
docker logs frigate

# Restart Frigate
docker restart frigate

# Stop/Start
docker stop frigate
docker start frigate

# Update Frigate
cd /opt/frigate
docker compose pull
docker compose up -d
```

### System Health
```bash
# Check disk usage
df -h /opt/frigate/storage

# Check container stats
docker stats frigate

# View Frigate logs
docker logs -f frigate
```

---

## Troubleshooting

### DNS Issues
If Docker can't pull images:
```bash
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
```

### Container Won't Start
```bash
# Check logs
docker logs frigate

# Check configuration
cd /opt/frigate
docker compose config

# Verify file permissions
ls -la /opt/frigate/config/
```

### Web UI Not Loading
```bash
# Check if container is running
docker ps | grep frigate

# Check nginx logs
docker logs frigate | grep nginx

# Verify port accessibility
curl -I http://localhost:5000
```

---

## Remote Access (Planned)

### Recommended: Twingate Zero-Trust Access
1. Add Frigate as Twingate resource:
   - Address: 192.168.1.60
   - Port: 5000
   - Name: frigate-nvr

2. Access from anywhere via Twingate client

**DO NOT expose Frigate directly to internet** - camera feeds are highly sensitive and Frigate has minimal built-in authentication.

---

## Backup & Recovery

### Configuration Backup
```bash
# Backup config
tar -czf frigate-config-backup-$(date +%Y%m%d).tar.gz /opt/frigate/config/

# Restore config
tar -xzf frigate-config-backup-YYYYMMDD.tar.gz -C /
```

### Full Backup
```bash
# Stop container
docker stop frigate

# Backup everything
tar -czf frigate-full-backup-$(date +%Y%m%d).tar.gz /opt/frigate/

# Restart container
docker start frigate
```

---

## Resources

### Documentation
- Frigate Docs: https://docs.frigate.video/
- go2rtc Docs: https://github.com/AlexxIT/go2rtc

### Configuration Files
- Main Config: `/opt/frigate/config/config.yml`
- Docker Compose: `/opt/frigate/docker-compose.yml`
- Logs: `docker logs frigate`

---

## Installation Timeline

- **13:00 UTC:** Started installation (Docker setup)
- **13:04 UTC:** Docker pull initiated (1.012GB image)
- **13:53 UTC:** Resolved DNS timeout issue
- **14:03 UTC:** Fixed LXC container compatibility issues
- **14:04 UTC:** Container started successfully
- **14:06 UTC:** Web UI confirmed accessible

**Total Installation Time:** ~1 hour (including troubleshooting)

---

**Created:** December 23, 2025
**Last Updated:** December 23, 2025
**Maintained by:** sh1pwr3ck via Claude Code
