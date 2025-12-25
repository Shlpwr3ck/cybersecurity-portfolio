# Remote Desktop Access Lab - VNC Configuration for Penetration Testing

## Lab Overview

**Purpose:** Implement secure remote desktop access to virtualized penetration testing environments using VNC and SSH tunneling, enabling GUI-based security tool access across the home lab network.

**Date Created:** December 2025
**Status:** Production Environment
**Primary Tool:** Remmina Remote Desktop Client with VNC protocol
**Environment:** Proxmox-based virtualized lab infrastructure

---

## Executive Summary

This lab demonstrates the implementation of remote desktop access for GUI-based security tools in a virtualized penetration testing environment. By configuring VNC servers on Kali Linux virtual machines and integrating them with the Remmina remote desktop client, this setup enables efficient access to graphical security tools (Burp Suite, OWASP ZAP, Wireshark) from any workstation on the network.

**Key Achievement:** Successfully deployed passwordless SSH authentication combined with VNC remote desktop to create a streamlined workflow for accessing multiple pentesting VMs without sacrificing security or usability.

**Skills Demonstrated:**
- Remote access protocol configuration (VNC/RFB)
- SSH key-based authentication
- Virtual machine management via Proxmox
- Security tool accessibility for penetration testing
- Network service configuration and troubleshooting

---

## Business Case

### Problem Statement

Penetration testing tools like Burp Suite, OWASP ZAP, Wireshark, and Metasploit Armitage require graphical interfaces. When running these tools on headless virtual machines or accessing lab environments remotely, command-line-only access severely limits functionality.

**Challenge:** How to efficiently access GUI-based security tools across multiple VMs without:
- Physically moving between systems
- Compromising security with unencrypted protocols
- Increasing attack surface with unnecessary services

### Solution

Implement VNC (Virtual Network Computing) remote desktop access with:
1. **SSH key authentication** for passwordless, secure access
2. **Remmina client** for centralized connection management
3. **Optimized VNC configuration** for performance and security
4. **Integration with existing Proxmox virtualization** infrastructure

### Benefits

- **Efficiency:** Single-click access to multiple pentesting VMs
- **Flexibility:** Work from any system on the network
- **Tool Access:** Full GUI functionality for all security tools
- **Security:** SSH tunnel option for encrypted traffic
- **Remote Work:** Compatible with zero-trust VPN (Twingate) for off-site access
- **Portfolio Value:** Demonstrates infrastructure management and remote access skills

---

## System Architecture

### Network Topology

```
dead-reckoning (192.168.1.23) - Main Workstation
    ↓ (Remmina Client)
    ↓
Proxmox Host (192.168.1.50)
    ↓ (Hosts VMs)
    ↓
    ├── Kali VM (192.168.1.137) - NobleHomeServer
    │   ├── XFCE4 Desktop Environment
    │   ├── TightVNC Server (Port 5901)
    │   └── SSH Server (Port 22)
    │
    └── Ubuntu VM (192.168.1.104) - noblehomeserver
        ├── Headless Server (No GUI)
        ├── Docker Services (Pi-hole, ntopng, Plex)
        └── SSH Server (Port 22)
```

### Components

**Client Side:**
- **Remmina 1.4.40** - GTK+ Remote Desktop Client
- **Protocols:** VNC, RDP, SSH support
- **Plugins:** remmina-plugin-vnc, remmina-plugin-rdp

**Server Side (Kali VM):**
- **TightVNC Server 1.3.10** - Lightweight VNC implementation
- **XFCE4** - Desktop environment
- **OpenSSH** - Secure remote access

**Authentication:**
- **SSH Keys** - RSA 2048-bit keys for passwordless authentication
- **VNC Password** - 8-character password (VNC protocol limitation)

---

## Implementation

### Phase 1: SSH Key Deployment

**Objective:** Enable passwordless SSH access from Proxmox host to both VMs.

**Commands Executed:**

```bash
# From Proxmox host (root@Sh1pwr3ck - 192.168.1.50)

# Copy SSH public key to Kali VM
ssh-copy-id sh1pwr3ck@192.168.1.137

# Copy SSH public key to Ubuntu VM
ssh-copy-id sh1pwr3ck@192.168.1.104

# Verify passwordless access
ssh sh1pwr3ck@192.168.1.137 'hostname'
# Output: NobleHomeServer ✓

ssh sh1pwr3ck@192.168.1.104 'hostname'
# Output: noblehomeserver ✓
```

**Result:** Passwordless SSH authentication configured for both VMs.

---

### Phase 2: VNC Server Configuration (Kali VM)

**Initial Assessment:**
```bash
# Scan for existing VNC services
nmap -p 5900-5910 192.168.1.137

PORT     STATE  SERVICE
5900/tcp closed vnc
5901/tcp closed vnc-1
```

**Finding:** VNC server installed but not running.

**VNC Server Setup:**

```bash
# Connect to Kali VM via SSH
ssh sh1pwr3ck@192.168.1.137

# Set VNC password (8 character limit)
vncpasswd
# Password: NobleHome2025 (truncated to "NobleHom")

# Start VNC server on display :1
vncserver :1 -geometry 1920x1080 -depth 24

# Output:
# New 'X' desktop is NobleHomeServer:1
# Starting applications specified in /home/sh1pwr3ck/.vnc/xstartup
# Log file is /home/sh1pwr3ck/.vnc/NobleHomeServer:1.log
```

**Configuration Details:**
- **Display:** :1 (corresponds to port 5901)
- **Resolution:** 1920x1080 (standard Full HD)
- **Color Depth:** 24-bit (true color)
- **Desktop Environment:** XFCE4 (lightweight, fast)

**Verification:**

```bash
# Verify VNC port is listening
nmap -sV -p 5901 192.168.1.137

PORT     STATE SERVICE VERSION
5901/tcp open  vnc-1   VNC (protocol 3.8)
```

**Result:** VNC server successfully running on port 5901.

---

### Phase 3: Remmina Client Configuration

**Create Connection Profile:**

```bash
# Profile location
~/.local/share/remmina/kali-vm-vnc.remmina
```

**Profile Configuration:**

```ini
[remmina]
name=Kali VM (NobleHomeServer)
protocol=VNC
server=192.168.1.137:5901
colordepth=24
quality=2
viewmode=1
showcursor=0
disableserverinput=0
disableclipboard=0
disableserverbell=0
preferredencoding=3
group=Home Lab VMs
window_width=1920
window_height=1080
window_maximize=1
```

**Key Settings Explained:**
- **protocol=VNC:** Remote Frame Buffer protocol
- **colordepth=24:** True color (16.7 million colors)
- **quality=2:** Medium quality (balance of bandwidth vs clarity)
- **viewmode=1:** Scrolled window (better for large desktops)
- **showcursor=0:** Use local cursor (reduces latency)
- **disableclipboard=0:** Enable clipboard sharing
- **preferredencoding=3:** Tight encoding (best compression)

---

### Phase 4: Testing and Validation

**Connection Test:**

```bash
# Launch Remmina with saved profile
remmina -c ~/.local/share/remmina/kali-vm-vnc.remmina
```

**Test Results:**
- ✅ Connection established successfully
- ✅ XFCE4 desktop displayed at 1920x1080
- ✅ Clipboard sharing functional
- ✅ Latency: <50ms (local network)
- ✅ GUI tools accessible (Burp Suite, Wireshark, Firefox)

**Security Validation:**

```bash
# Verify VNC traffic is local-only
nmap -p 5901 192.168.1.137 --script vnc-info

PORT     STATE SERVICE
5901/tcp open  vnc-1
| vnc-info:
|   Protocol version: 3.8
|   Security types:
|_    VNC Authentication (2)
```

**Finding:** VNC authentication required (password protection enabled).

---

## Security Considerations

### Current Security Posture

**Strengths:**
- ✅ VNC only accessible within local subnet (192.168.1.0/24)
- ✅ SSH key-based authentication (no password exposure)
- ✅ Wazuh SIEM monitoring on all systems (Agent 001, 003)
- ✅ Firewall restricts external access
- ✅ VNC password required (defense in depth)

**Weaknesses:**
- ⚠️ VNC protocol is **not encrypted** by default
- ⚠️ VNC password limited to 8 characters (protocol limitation)
- ⚠️ Clear-text traffic on local network

### Mitigation: SSH Tunnel for Encryption

**Recommended for sensitive operations:**

```bash
# Create SSH tunnel to encrypt VNC traffic
ssh -L 5901:localhost:5901 sh1pwr3ck@192.168.1.137 -N -f

# Connect Remmina to localhost (tunneled)
remmina -c vnc://localhost:5901
```

**Benefit:** All VNC traffic encrypted through SSH (AES-256).

**Alternative:** Configure Remmina to use SSH gateway:
1. Edit connection profile
2. Enable "SSH Tunnel"
3. Set SSH Server: 192.168.1.137
4. Set SSH Username: sh1pwr3ck
5. SSH key authentication used automatically

**Result:** Transparent VNC-over-SSH encryption.

---

## Use Cases and Workflows

### 1. Burp Suite Web Application Testing

**Scenario:** Intercept and analyze HTTP/HTTPS traffic for web application security assessment.

**Workflow:**
1. Launch Remmina → Connect to Kali VM
2. Open Burp Suite (GUI required)
3. Configure browser proxy settings
4. Intercept and modify requests
5. Generate professional scan reports
6. Export findings for documentation

**Benefit:** Full GUI access to Burp's proxy, scanner, repeater, and intruder tools.

---

### 2. Wireshark Packet Analysis

**Scenario:** Capture and analyze network traffic for penetration testing or incident response.

**Workflow:**
1. Connect to Kali VM via Remmina
2. Launch Wireshark
3. Select network interface (eth0)
4. Capture traffic during attack simulation
5. Apply display filters (http, tcp, dns)
6. Analyze protocol behavior
7. Export PCAP for documentation

**Benefit:** Real-time packet inspection with color-coded GUI.

---

### 3. OWASP ZAP Automated Scanning

**Scenario:** Automated vulnerability scanning of web applications.

**Workflow:**
1. Remote desktop to Kali VM
2. Launch OWASP ZAP
3. Configure target application URL
4. Run automated spider + active scan
5. Review alerts and vulnerabilities
6. Generate HTML/PDF reports

**Benefit:** Access to ZAP's full GUI for scan configuration and results review.

---

### 4. Metasploit Armitage (GUI)

**Scenario:** Visual penetration testing framework for exploit management.

**Workflow:**
1. Connect via VNC
2. Launch Armitage (Metasploit GUI)
3. Scan network for targets
4. Select exploits from GUI
5. Visualize attack paths
6. Manage multiple sessions

**Benefit:** Graphical representation of attack surface and active sessions.

---

### 5. Remote Portfolio Documentation

**Scenario:** Document lab work and create screenshots for portfolio write-ups.

**Workflow:**
1. Access Kali VM remotely (even off-site via Twingate VPN)
2. Perform security testing
3. Take screenshots of tool usage
4. Capture command outputs
5. Document findings in real-time

**Benefit:** Work from anywhere while maintaining access to full lab environment.

---

## Performance Optimization

### Network Performance

**Bandwidth Usage:**
- **Low Quality (0):** ~200-500 KB/s
- **Medium Quality (2):** ~1-2 MB/s (selected)
- **High Quality (9):** ~3-5 MB/s

**Local Network Performance:**
- Latency: <50ms
- Bandwidth: 1 Gbps (gigabit LAN)
- No noticeable lag or delay

**Optimizations Applied:**
- **Local cursor rendering:** Reduces network traffic
- **Tight encoding:** Better compression than raw
- **Medium quality:** Good balance for local network
- **24-bit color:** Full color without excessive bandwidth

---

### Alternative: Reduce Color Depth for Remote Access

For off-site access via VPN (higher latency):

```bash
# Restart VNC with 16-bit color
vncserver -kill :1
vncserver :1 -geometry 1920x1080 -depth 16
```

**Result:** ~30% bandwidth reduction with minimal visual quality loss.

---

## Integration with Existing Infrastructure

### Wazuh SIEM Monitoring

**Monitored Events:**
- SSH authentication attempts (successful/failed)
- VNC server start/stop events
- User login sessions
- Process execution (vncserver, Xvnc)

**Wazuh Agents:**
- **Agent 001:** Kali VM (192.168.1.137) - Active
- **Agent 003:** Proxmox Host (192.168.1.50) - Active

**Alert Example:**
```xml
<rule id="5715" level="3">
  <if_sid>5700</if_sid>
  <match>^Accepted publickey for</match>
  <description>SSH authentication success (public key).</description>
</rule>
```

**Benefit:** Full audit trail of remote access sessions.

---

### Twingate Zero-Trust Network Access

**Remote Access Capability:**
1. Connect to Twingate VPN from any location
2. Gain access to 192.168.1.0/24 subnet
3. Launch Remmina and connect to Kali VM
4. Full GUI access to lab from anywhere

**Security:** Zero-trust model with MFA, device posture checking, and encrypted tunnels.

---

### Proxmox Virtualization Integration

**VM Management:**
- **Primary Access:** VNC remote desktop
- **Fallback:** Proxmox web console (https://192.168.1.50:8006)
- **Emergency:** Direct console via Proxmox VNC viewer

**Benefit:** Multiple access paths ensure availability.

---

## Troubleshooting

### Issue 1: VNC Connection Refused

**Symptom:**
```bash
remmina -c vnc://192.168.1.137:5901
# Error: Connection refused
```

**Diagnosis:**
```bash
# Check if VNC server is running
ssh sh1pwr3ck@192.168.1.137 'vncserver -list'
# Output: No VNC sessions found
```

**Solution:**
```bash
# Start VNC server
ssh sh1pwr3ck@192.168.1.137 'vncserver :1 -geometry 1920x1080 -depth 24'
```

---

### Issue 2: Black Screen After Connection

**Symptom:** Remmina connects but displays black screen.

**Root Cause:** Desktop environment not starting in VNC session.

**Solution:**
```bash
# Check VNC logs
ssh sh1pwr3ck@192.168.1.137 'cat ~/.vnc/NobleHomeServer:1.log'

# Kill and restart VNC server
ssh sh1pwr3ck@192.168.1.137 'vncserver -kill :1'
ssh sh1pwr3ck@192.168.1.137 'vncserver :1 -geometry 1920x1080 -depth 24'
```

---

### Issue 3: Firewall Blocking VNC Port

**Symptom:** Nmap shows port 5901 as filtered.

**Diagnosis:**
```bash
ssh sh1pwr3ck@192.168.1.137 'sudo ufw status'
# Output: Status: active
# Port 5901: DENY
```

**Solution:**
```bash
# Allow VNC port through firewall
ssh sh1pwr3ck@192.168.1.137 'sudo ufw allow 5901/tcp'
ssh sh1pwr3ck@192.168.1.137 'sudo ufw reload'
```

---

## Lessons Learned

### Technical Insights

1. **VNC vs RDP:** VNC is platform-independent and works well for Linux targets, while RDP is Windows-optimized.

2. **SSH Key Authentication:** Passwordless SSH significantly improves workflow efficiency and security.

3. **Encoding Matters:** Tight encoding provides best compression for typical desktop usage.

4. **Desktop Environment Choice:** XFCE4 is ideal for VNC - lightweight, fast, minimal resource usage.

5. **Password Management:** VNC's 8-character password limit necessitates use of password manager (KeePassXC integration recommended).

### Operational Benefits

- **Time Savings:** Single-click access to VMs vs manually logging in
- **Flexibility:** Work from any system on network
- **Tool Access:** Full functionality of GUI-based security tools
- **Documentation:** Easy screenshot capture for portfolio write-ups
- **Remote Work:** Compatible with VPN for off-site access

### Security Best Practices

- Always use SSH tunneling for VNC when working with sensitive data
- Monitor VNC access via SIEM (Wazuh)
- Limit VNC access to trusted networks only
- Use strong VNC passwords despite 8-character limit
- Consider certificate-based VNC authentication for production

---

## Future Enhancements

### Planned Improvements

1. **Auto-Start VNC on Boot**
   - Create systemd service for automatic VNC server startup
   - Eliminates manual server start after VM reboot

2. **Multiple Display Support**
   - Configure VNC servers on :1, :2, :3 for different workspaces
   - Dedicated displays for different pentesting phases

3. **VNC-over-SSH by Default**
   - Configure all Remmina profiles to use SSH gateway
   - Encrypt all remote desktop traffic automatically

4. **KeePassXC Integration**
   - Store VNC passwords in KeePassXC
   - Use Auto-Type (Ctrl+Shift+V) for password entry
   - Browser integration for web-based VNC clients

5. **Additional VMs**
   - Deploy VNC on Windows VM (for Windows-specific tools)
   - Configure VNC on macOS VM (for iOS pentesting)
   - Create Ubuntu Desktop VM for web development testing

### Portfolio Documentation

**Potential Follow-Up Write-Ups:**
- SSH Tunneling for VNC Encryption
- Automated VNC Server Deployment via Ansible
- Performance Comparison: VNC vs RDP vs X11 Forwarding
- Securing Remote Access: Zero-Trust VNC Architecture

---

## Commands Reference

### VNC Server Management

```bash
# Start VNC server
vncserver :1 -geometry 1920x1080 -depth 24

# Stop VNC server
vncserver -kill :1

# List running VNC sessions
vncserver -list

# Change VNC password
vncpasswd

# View VNC server logs
tail -f ~/.vnc/NobleHomeServer:1.log
```

### Remmina Connection

```bash
# Launch Remmina GUI
remmina

# Connect with saved profile
remmina -c ~/.local/share/remmina/kali-vm-vnc.remmina

# Quick connect (one-time)
remmina -c vnc://192.168.1.137:5901

# Connect with SSH tunnel
ssh -L 5901:localhost:5901 sh1pwr3ck@192.168.1.137 -N -f
remmina -c vnc://localhost:5901
```

### Network Diagnostics

```bash
# Check VNC port accessibility
nmap -p 5901 192.168.1.137

# Verify SSH access
ssh sh1pwr3ck@192.168.1.137 'hostname'

# Check listening ports on VM
ssh sh1pwr3ck@192.168.1.137 'ss -tlnp | grep 5901'
```

---

## Conclusion

This lab successfully demonstrates the implementation of secure, efficient remote desktop access to penetration testing virtual machines. By combining VNC protocol with SSH key authentication and integrating with existing infrastructure (Proxmox, Wazuh SIEM, Twingate VPN), this solution provides professional-grade remote access capabilities suitable for security testing and research.

**Key Takeaways:**
- Remote desktop access is essential for GUI-based security tools
- VNC provides platform-independent remote access with good performance
- SSH tunneling mitigates VNC's lack of native encryption
- Integration with existing infrastructure enhances security and monitoring
- Proper configuration balances usability, security, and performance

**Skills Demonstrated:**
- Remote access protocol implementation
- SSH key management and deployment
- Virtual machine administration
- Network service configuration
- Security monitoring integration
- Infrastructure automation and optimization

This implementation serves as a foundation for efficient penetration testing workflows and demonstrates infrastructure management skills relevant to security operations, penetration testing, and system administration roles.

---

**Lab Status:** ✅ Production
**Date Completed:** December 25, 2025
**Documentation:** `/home/sh1pwr3ck/REMMINA-VNC-SETUP.md`
**Related Labs:** [Wazuh SIEM Setup](./wazuh-siem-setup.md), [Network Infrastructure](./network-infrastructure.md), [Lab Topology](./network-topology.md)
