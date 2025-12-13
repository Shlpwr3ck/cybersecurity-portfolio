# Home Lab Network Map

**Created:** December 10, 2025
**Purpose:** Quick reference for lab infrastructure IPs and services

---

## Network Overview

**Network:** 192.168.1.0/24

---

## Lab Infrastructure

### Proxmox Hypervisor
- **IP:** 192.168.1.50
- **Hostname:** proxmox
- **User:** root
- **Purpose:** Virtualization host
- **Web UI:** https://192.168.1.50:8006

---

### Ubuntu Server VM (on Proxmox)
- **IP:** 192.168.1.104
- **Hostname:** noblehomeserver
- **User:** sh1pwr3ck
- **Purpose:**
  - Docker lab services
  - Network monitoring
  - Wazuh agent (reports to dead-reckoning)
  - Snort IDS (2 interfaces)
- **Docker Services:**
  - ntopng: http://192.168.1.104:3000 (network traffic monitor)
  - Pi-hole: DNS filtering/ad blocking
  - Plex: Media server
- **Security:**
  - Wazuh agent monitoring
  - Snort IDS on ens18 & ens19
  - Auto-restart configured for all containers

---

### Dead Reckoning (Main Workstation)
- **IP:** 192.168.1.23
- **Hostname:** dead-reckoning
- **User:** sh1pwr3ck
- **Purpose:** Main workstation & Wazuh SIEM server
- **Services:**
  - Wazuh SIEM (local)
    - Indexer: port 9200
    - Manager: port 55000
    - Dashboard: https://localhost:443
    - Monitoring: noblehomeserver (Wazuh agent)
  - Claude Code
  - Development environment

---

## Future VMs (Planned)

### Kali Linux
- **IP:** 192.168.1.100
- **User:** kali
- **Purpose:** Penetration testing

### Metasploitable
- **IP:** 192.168.1.101
- **User:** msfadmin
- **Purpose:** Vulnerable target for practice

---

## Quick SSH Commands

```bash
# Proxmox host
ssh root@192.168.1.50

# Ubuntu Server (ntopng)
ssh sh1pwreck@192.168.1.104

# Dead Reckoning (main workstation)
ssh sh1pwr3ck@192.168.1.23

# Linux Mint
ssh [user]@192.168.1.134
```

---

## Service URLs

**Proxmox Web UI:**
- https://192.168.1.50:8006

**ntopng (Ubuntu Server):**
- http://192.168.1.104:3000

**Wazuh Dashboard (dead-reckoning):**
- https://localhost:443 (from dead-reckoning)
- https://192.168.1.23:443 (from remote)

---

## Quick Service Checks

```bash
# Check if Proxmox is up
ping 192.168.1.50

# Check if Ubuntu Server is up
ping 192.168.1.104

# SSH into Ubuntu Server
ssh sh1pwreck@192.168.1.104

# Check ntopng status on Ubuntu Server
ssh sh1pwreck@192.168.1.104 "systemctl status ntopng"
```

---

**File Location:** `/home/sh1pwr3ck/noble-technologies-llc/professional-development/labs/LAB-NETWORK-MAP.md`
