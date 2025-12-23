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

### Frigate NVR VM (on Proxmox)
- **IP:** 192.168.1.60
- **Hostname:** frigate-nvr
- **User:** root
- **Type:** LXC Container (Proxmox VMCT 300)
- **Purpose:**
  - Frigate NVR (Network Video Recorder)
  - AI-powered video surveillance & object detection
  - Wazuh agent (reports to dead-reckoning)
- **Services:**
  - Frigate NVR: http://192.168.1.60:5000 ✅ Running
  - Docker: v29.1.3
  - go2rtc: RTSP/WebRTC handler
- **Hardware (Planned):**
  - AI accelerator (Coral TPU or similar) - Not yet installed
  - IP cameras - Not yet installed
- **Security:**
  - Wazuh agent monitoring (Agent 007) ✅ Active
  - SSH key access configured
- **Installed:** December 23, 2025

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
    - Monitoring: 7 agents (see Wazuh Agents section)
  - Claude Code
  - Development environment

---

### Hacktop
- **IP:** 192.168.1.130
- **Hostname:** parrot
- **OS:** Parrot OS (Debian-based)
- **User:** sh1pwr3ck
- **Purpose:** Security testing workstation
- **Wazuh:** Agent 005 (active when powered on - auto-powers off after 1 hour)

---

### MacBook Pro
- **IP:** 192.168.1.218
- **Hostname:** Jax-Mac-Pro-2.local
- **OS:** macOS (Apple Silicon - arm64)
- **User:** shlpwr3ck
- **Purpose:** Development workstation
- **Wazuh:** Agent 006 (active)
- **Note:** Uses Pi-hole DNS at 192.168.1.104 (requires Ubuntu VM to be powered on)

---

### jax-23-b010 (Linux Mint)
- **IP:** 192.168.1.134
- **Hostname:** jax-23-b010
- **OS:** Linux Mint
- **User:** jax
- **Purpose:** Linux Mint laptop
- **Wazuh:** Agent 004 (active)

---

## Wazuh Agents

### Agent Overview
- **Manager:** dead-reckoning (192.168.1.23)
- **Version:** Wazuh v4.14.1

### Active Agents (As of Dec 23, 2025)
- **Agent 000:** dead-reckoning (manager/server) - 192.168.1.23 - ✅ Active
- **Agent 001:** NobleHomeServer (Kali VM on Proxmox) - 192.168.1.137 - ✅ Active
- **Agent 002:** noblehomeserver (Ubuntu VM on Proxmox) - 192.168.1.104 - ✅ Active
- **Agent 003:** Sh1pwr3ck (Proxmox host) - 192.168.1.50 - ✅ Active
- **Agent 004:** jax-23-b010 (Linux Mint laptop) - 192.168.1.134 - ✅ Active
- **Agent 005:** parrot (Hacktop - Parrot OS) - 192.168.1.130 - ⚠️ Active when powered on (auto-shutoff after 1hr)
- **Agent 006:** Jax-Mac-Pro-2.local (MacBook Pro - macOS arm64) - 192.168.1.218 - ✅ Active
- **Agent 007:** frigate-nvr (Frigate NVR VM on Proxmox) - 192.168.1.60 - ✅ Active

---

## Future VMs (Planned)

### Kali Linux (if not already NobleHomeServer)
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

# Hacktop (Parrot OS)
ssh sh1pwr3ck@192.168.1.130

# MacBook Pro (macOS)
ssh shlpwr3ck@192.168.1.218

# jax-23-b010 (Linux Mint)
ssh jax@192.168.1.134

# Frigate NVR
ssh root@192.168.1.60
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
