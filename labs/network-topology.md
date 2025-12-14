# Home Lab Network Map

**Created:** December 10, 2025
**Purpose:** Quick reference for lab infrastructure IPs and services

---

## Network Overview

**Network:** 192.168.x.x/24 (Private lab subnet)

---

## Lab Infrastructure

### Proxmox Hypervisor
- **IP:** 192.168.x.x
- **Hostname:** proxmox
- **User:** root
- **Purpose:** Virtualization host
- **Web UI:** https://192.168.x.x:8006

---

### Ubuntu Server VM (on Proxmox)
- **IP:** 192.168.x.x
- **Hostname:** noblehomeserver
- **User:** sh1pwr3ck
- **Purpose:**
  - Docker lab services
  - Network monitoring
  - Wazuh agent (reports to dead-reckoning)
  - Snort IDS (2 interfaces)
- **Docker Services:**
  - ntopng: http://192.168.x.x:3000 (network traffic monitor)
  - Pi-hole: DNS filtering/ad blocking
  - Plex: Media server
- **Security:**
  - Wazuh agent monitoring
  - Snort IDS on ens18 & ens19
  - Auto-restart configured for all containers

---

### Dead Reckoning (Main Workstation)
- **IP:** 192.168.x.x
- **Hostname:** dead-reckoning
- **OS:** Ubuntu 25.10
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

### Linux Mint All-in-One
- **IP:** 192.168.x.x
- **Hostname:** mint-allinone
- **OS:** Linux Mint
- **User:** sh1pwr3ck
- **Hardware:** All-in-one desktop computer
- **Purpose:** Secondary workstation / backup system

---

### Hacktop (Parrot Security Laptop)
- **Hostname:** hacktop
- **OS:** Parrot Security OS
- **User:** sh1pwr3ck
- **Hardware:** Laptop
- **Purpose:** AI-assisted penetration testing workstation
- **AI Tools:**
  - Claude Code CLI (cloud AI for code/research)
  - Google Gemini (multimodal analysis)
  - Ollama (local LLM hosting - Llama2, CodeLlama, Mistral)
- **Use Cases:**
  - Offensive security research
  - Exploit development
  - Privacy-preserving local AI analysis
  - Mobile pentesting platform
- **Documentation:** [AI-Assisted Security Workstation](./ai-assisted-security-workstation.md)

---

### MacBook Pro
- **Hostname:** macbook
- **OS:** macOS
- **User:** sh1pwr3ck
- **Hardware:** MacBook Pro
- **Purpose:** General computing / mobile workstation

---

## Future VMs (Planned)

### Kali Linux
- **IP:** 192.168.x.x
- **User:** kali
- **Purpose:** Penetration testing

### Metasploitable
- **IP:** 192.168.x.x
- **User:** msfadmin
- **Purpose:** Vulnerable target for practice

---

## Quick SSH Commands

```bash
# Proxmox host
ssh root@192.168.x.x

# Ubuntu Server (ntopng)
ssh sh1pwreck@192.168.x.x

# Dead Reckoning (main workstation)
ssh sh1pwr3ck@192.168.x.x

# Linux Mint
ssh [user]@192.168.x.x
```

---

## Service URLs

**Proxmox Web UI:**
- https://192.168.x.x:8006

**ntopng (Ubuntu Server):**
- http://192.168.x.x:3000

**Wazuh Dashboard (dead-reckoning):**
- https://localhost:443 (from dead-reckoning)
- https://192.168.x.x:443 (from remote)

---

## Quick Service Checks

```bash
# Check if Proxmox is up
ping 192.168.x.x

# Check if Ubuntu Server is up
ping 192.168.x.x

# SSH into Ubuntu Server
ssh sh1pwreck@192.168.x.x

# Check ntopng status on Ubuntu Server
ssh sh1pwreck@192.168.x.x "systemctl status ntopng"
```

---

**File Location:** `/home/sh1pwr3ck/noble-technologies-llc/professional-development/labs/LAB-NETWORK-MAP.md`
