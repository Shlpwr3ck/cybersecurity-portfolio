# Home Lab Environment Overview

**Last Updated:** December 13, 2025
**Host:** dead-reckoning (Ubuntu 25.10)

---

## Purpose

This home lab provides a safe, isolated environment for:
- Offensive security skill development
- Security tool testing and configuration
- Vulnerability research and exploitation practice
- Blue team defensive techniques
- Security monitoring and incident response

---

## Infrastructure

### Host System
- **Operating System:** Ubuntu 25.10 (kernel 6.17.0-8)
- **Hostname:** dead-reckoning
- **CPU/RAM:** Sufficient for multiple VMs
- **Storage:** 915GB total, 726GB used

### Networking
- Isolated lab network for safe testing
- Segregated VLANs for different security zones
- Network traffic capture and analysis capabilities
- See [Network Topology](./network-topology.md) for details

---

## Current Lab Components

### 1. Wazuh SIEM
**Purpose:** Security monitoring and log analysis

**Status:** Active and running
**Documentation:** [Wazuh SIEM Setup](./wazuh-siem-setup.md)

**Capabilities:**
- Host-based intrusion detection
- File integrity monitoring
- Log collection and analysis
- Security event correlation
- Vulnerability detection
- Compliance monitoring (PCI-DSS, HIPAA, GDPR)

**Use Cases:**
- Blue team defensive monitoring
- Attack detection and alerting
- Incident response training
- Security operations center (SOC) simulation

---

### 2. Docker Lab Services
**Purpose:** Containerized vulnerable applications for exploitation practice

**Status:** Configured, ready to deploy
**Documentation:** [Docker Lab Services](./docker-lab-services.md)

**Services:**
- Vulnerable web applications
- Misconfigured services for exploitation
- Network services for enumeration practice
- CTF-style challenges

**Use Cases:**
- Web application penetration testing
- Service exploitation practice
- Network enumeration training
- CVE research and testing

---

### 3. Virtual Machines
**Purpose:** Multiple operating systems for offensive/defensive testing

**Virtualization:** VirtualBox (planning Proxmox migration)

**Current VMs:**
- Kali Linux (offensive security)
- Ubuntu Server (vulnerable targets)
- Windows Server (AD/domain testing - planned)

**Capabilities:**
- Snapshot-based state management
- Network isolation
- Resource allocation control
- Rapid environment deployment

---

## Security Tools Installed

### Network Analysis
- Nmap (network scanning)
- Wireshark (packet analysis)
- tcpdump (traffic capture)

### Security Monitoring
- Wazuh SIEM (active)
- System logs and audit trails

### Development
- Git version control
- VS Code (planned installation)
- Bash scripting environment

---

## Lab Network Architecture

**Network Segments:**
- Management network (host access)
- Attack network (offensive testing)
- Target network (vulnerable systems)
- Monitoring network (SIEM/logging)

**See:** [Network Topology](./network-topology.md) for detailed diagram

---

## Planned Expansions

### Short-term (Post-Security+ exam)
- Install Docker and Docker Compose
- Deploy vulnerable Docker containers
- Install Metasploit Framework
- Add pentest tools (gobuster, hydra, hashcat)
- Set up Burp Suite Community

### Medium-term
- Migrate to Proxmox hypervisor
- Add Active Directory lab environment
- Deploy malware analysis sandbox
- Set up vulnerable VMs (DVWA, Metasploitable)
- Implement network traffic analysis lab

### Long-term
- Build fully automated deployment (Terraform/Ansible)
- Create custom vulnerable applications
- Develop CTF-style challenges
- Document complete attack chains
- Build SOC simulation environment

---

## Skills Developed

Through this lab environment, the following skills are being developed:

**Offensive Security:**
- Network enumeration and reconnaissance
- Service exploitation and privilege escalation
- Web application penetration testing
- Post-exploitation techniques

**Defensive Security:**
- Security monitoring and alerting
- Incident detection and response
- Log analysis and correlation
- Threat hunting techniques

**Infrastructure:**
- Linux system administration
- Network configuration and troubleshooting
- Virtualization and containerization
- Security tool deployment and management

---

## Documentation Standards

All lab work is documented according to professional standards:
- Clear setup and configuration instructions
- Command reference and examples
- Troubleshooting and lessons learned
- Screenshots and evidence
- Reproducible methodologies

---

## Security Considerations

This lab operates under strict security guidelines:
- Isolated from production networks
- No real credentials or sensitive data
- All exploitation confined to authorized lab targets
- Proper shutdown procedures for vulnerable services
- Regular backups and snapshots

---

## Portfolio Integration

Lab documentation serves multiple purposes:
- Technical skill demonstration for job applications
- Reference material for certification exams
- Knowledge retention and review
- Professional portfolio content
- Interview talking points

---

**Related Documentation:**
- [Wazuh SIEM Setup](./wazuh-siem-setup.md)
- [Docker Lab Services](./docker-lab-services.md)
- [Network Topology](./network-topology.md)

---

**Maintained by:** James Jackson (sh1pwr3ck)
**Purpose:** Cybersecurity skill development and professional portfolio
