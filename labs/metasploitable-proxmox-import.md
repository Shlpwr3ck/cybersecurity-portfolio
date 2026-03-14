# Metasploitable 2 — Proxmox Import

## Lab Overview

**Purpose:** Deploy Metasploitable 2 (intentionally vulnerable Linux VM) on Proxmox for hands-on penetration testing practice in an isolated home lab environment.

**Date Deployed:** March 2026
**Status:** ✅ Running
**VM ID:** 104 — Metasploitable (10.34.43.244)

---

## Why This Is Tricky

Metasploitable 2 is distributed as a VMware image (`.vmdk`). Proxmox doesn't import VMware disks natively through the UI. The import requires manual VMDK-to-raw conversion at the command line, manual VM creation, and careful hardware configuration to match what the old Metasploitable kernel expects.

**Common failure points:**
- Using the wrong VMDK file (the package contains multiple — one is sparse/descriptor-only)
- Trying VirtIO disk or network drivers (old kernel doesn't support them — VM won't boot)
- Not setting the boot order after attaching the imported disk
- Skipping network isolation (VM ends up internet-exposed)

---

## Final VM Configuration (Confirmed Live)

```
VM ID:      104
Name:       Metasploitable
Memory:     512 MB
CPU:        1 core
Disk:       local-lvm:vm-104-disk-0 — 8G raw (LVM thin)
Disk bus:   IDE (ide0) — required, VirtIO will not work
NIC:        e1000 — required, VirtIO NIC will not work
Bridge:     vmbr0
IP:         10.34.43.244 (DHCP from Pi-hole)
Boot:       ide0
BIOS:       SeaBIOS (default)
```

---

## Import Process

### Step 1 — Get the Image

Download Metasploitable 2 from SourceForge (search "Metasploitable2-Linux"). Extract the zip — you'll get a folder with several files including:

```
Metasploitable.vmdk          ← sparse descriptor (small — not the actual disk)
Metasploitable-disk1.vmdk    ← the actual disk image
```

### Step 2 — Copy to Proxmox Host

```bash
scp Metasploitable-disk1.vmdk root@10.34.43.10:/tmp/
```

### Step 3 — Convert VMDK to Raw

```bash
ssh root@10.34.43.10
cd /tmp
qemu-img convert -f vmdk -O raw Metasploitable-disk1.vmdk metasploitable.raw
```

`qemu-img convert` flags:
- `-f vmdk` — input format
- `-O raw` — output format (raw works best for LVM thin storage)

### Step 4 — Create the VM Shell

```bash
qm create 104 \
  --name Metasploitable \
  --memory 512 \
  --cores 1 \
  --net0 e1000,bridge=vmbr0
```

> **Do NOT add a disk here.** You'll attach the imported disk in the next step.

### Step 5 — Import the Disk

```bash
qm importdisk 104 /tmp/metasploitable.raw local-lvm
```

Proxmox imports it as an unused disk — it won't boot yet.

### Step 6 — Attach the Disk

```bash
qm set 104 --ide0 local-lvm:vm-104-disk-0
```

IDE bus is required. The Metasploitable kernel is too old to recognize VirtIO block devices.

### Step 7 — Set Boot Order

```bash
qm set 104 --boot order=ide0
```

Without this, Proxmox tries to PXE boot and the VM hangs at the network boot screen.

### Step 8 — Start and Verify

```bash
qm start 104
```

Default credentials: `msfadmin / msfadmin`

---

## Network Considerations

Metasploitable is intentionally full of vulnerabilities. It should **never** be reachable from the internet.

**Current setup:** VM is on `vmbr0` (same bridge as the rest of the lab). This is acceptable because:
- The home network is behind NAT (no inbound port forwarding to this IP)
- Twingate Zero Trust controls any remote access — Metasploitable is not added as a resource

**Stronger isolation (optional):** Create a separate bridge (`vmbr1`) with no uplink and place Metasploitable and your attack VM on it. Nothing else can reach it.

```bash
# In Proxmox web UI: Datacenter → Node → Network → Create → Linux Bridge
# Leave "Bridge ports" empty (no physical uplink)
# Then: qm set 104 --net0 e1000,bridge=vmbr1
```

---

## Cleanup

```bash
# Clean up the temp files after import
rm /tmp/Metasploitable-disk1.vmdk /tmp/metasploitable.raw
```

---

## Usage

Metasploitable 2 runs dozens of intentionally vulnerable services — Samba, vsftpd 2.3.4 (backdoor), UnrealIRCd, DVWA, Mutillidae, OpenSSH weak keys, and more.

Attack from Kali or hacktop:

```bash
# Scan target
nmap -sV -O 10.34.43.244

# Launch Metasploit
msfconsole
msf6 > search metasploitable
```

---

## Snapshots

Take a snapshot before any destructive testing so you can roll back cleanly:

```bash
# Create snapshot
qm snapshot 104 clean "Clean baseline"

# List snapshots
qm listsnapshot 104

# Rollback
qm rollback 104 clean
```

---

## Skills Demonstrated

- VMware VMDK to Proxmox raw disk conversion
- Proxmox VM creation and disk import via CLI
- Legacy VM hardware compatibility (IDE bus, e1000 NIC)
- Lab network isolation planning
- Snapshot-based state management for safe testing

---

**Created:** March 2026
**Author:** Jax (Sh1pwr3ck)
**Environment:** Proxmox VE — VM 104
**Tags:** `#proxmox` `#metasploitable` `#homelab` `#vmdk-import` `#penetration-testing` `#vulnerable-vm`
