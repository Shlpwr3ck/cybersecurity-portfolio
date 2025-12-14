# Home Lab Documentation

Infrastructure, network topology, and security tool implementations.

---

## Lab Environment

**Physical Hardware:**
- **Dead Reckoning** - Ubuntu 25.10 workstation (Wazuh SIEM server)
- **Hacktop** - Parrot Security OS laptop (AI-assisted pentesting)
- **Linux Mint All-in-One** - Secondary workstation
- **MacBook Pro** - Mobile workstation

**Virtualization:** Proxmox hypervisor (192.168.1.50)
**Network:** 192.168.1.0/24 home lab network

---

## Current Lab Components

### Security Monitoring
- **Wazuh SIEM** - Active security monitoring and log analysis
- Host-based intrusion detection
- Security event correlation

### Network Services
- Network service deployment for exploitation practice
- Vulnerable application hosting
- Attack surface simulation

### Testing Environment
- Multiple VMs for offensive/defensive scenarios
- Segregated networks for safe testing
- Snapshot-based state management

---

## Planned Expansions

- Docker container lab environment
- Additional vulnerable VMs
- Blue team defensive scenarios
- Malware analysis sandbox
- Network traffic analysis lab

---

## Documentation

### Lab Setup Guides

- **[AI-Assisted Security Workstation](./ai-assisted-security-workstation.md)** - Parrot OS workstation integrated with Claude Code, Google Gemini, and Ollama for AI-augmented penetration testing
- **[Wazuh SIEM Setup](./wazuh-siem-setup.md)** - Complete Wazuh SIEM installation and configuration for security monitoring
- **[Docker Lab Services](./docker-lab-services.md)** - Docker-based vulnerable services for penetration testing practice
- **[Network Topology](./network-topology.md)** - Lab network architecture and IP addressing scheme

### Lab Environment Overview

Detailed documentation of infrastructure components, security tools deployed, and testing methodologies used in the home lab environment.
