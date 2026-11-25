# Home SOC Audit and Sensor Recovery — November 2026

**Status:** Operational with known limitations

**Audit date:** November 24, 2026

**Scope:** Endpoint review, network baseline, packet capture, passive IDS, SIEM recovery, and end-to-end alert validation

## Executive Summary

An unexplained keyboard-input anomaly prompted a focused endpoint and home-network audit. The review found no confirmed evidence of unauthorized access. It did expose a more serious operational problem: the central security monitoring stack had partially failed without notification.

The audit was expanded into a recovery and validation exercise. A Linux laptop was configured as a dedicated passive network sensor using Dumpcap, Suricata, and a Wazuh agent. The central Wazuh indexer and analysis engine were recovered, the alert pipeline was tested end to end, and recurring rule updates and packet-retention jobs were enabled.

This public case study intentionally omits addresses, MAC addresses, credentials, usernames, internal hostnames, and sensitive topology.

## Initial Audit Findings

- The initiating keyboard anomaly remained unexplained, but the available endpoint and network evidence did not confirm compromise.
- A short Screen Sharing connection in the logs aligned with a locally initiated Nmap service scan and originated from the audited workstation itself.
- The persistent security-log collector was verified as the installed Wazuh agent.
- Remote-access services were listening on the workstation, but no active unauthorized inbound session was observed in the captured snapshot.
- Several network devices required owner verification or hardening, but no rogue device was confirmed.

## Sensor Deployment

### Continuous Packet Capture

Dumpcap was moved from an interactive terminal into a boot-enabled service:

- Passive capture on the sensor's active wireless interface.
- File rotation every five minutes or 50 MB.
- A 288-file ring per capture process.
- Restricted capture-directory permissions.
- Automatic restart after failure.
- Separate hourly cleanup of capture files older than 24 hours.

The manual capture test recorded 1,221 packets with zero reported drops. A later Suricata shutdown summary reported 21,194 inspected packets with zero drops and zero invalid checksums.

### Suricata IDS

Suricata 7.0.10 was installed in passive IDS mode and configured for the sensor's local network and active interface.

Verified results:

- 53,586 production rules loaded from Emerging Threats Open.
- Zero rule-load failures.
- Four capture threads started.
- Live ARP, TCP, UDP, and IPv6 processing observed.
- A temporary local ICMP signature was added for a controlled pipeline test, then commented out after validation.

The service remains passive: it detects and records matching traffic but does not block it.

### Wazuh Integration

The sensor's Wazuh agent was configured to collect Suricata JSON events. Initial forwarding of the complete event stream produced repeated `Too many fields for JSON decoder` errors on the manager. The sensor-side collector was then restricted to `event_type: alert`, keeping verbose statistics and flow records local while forwarding security alerts.

The filter passed configuration validation, and the Suricata, Wazuh-agent, and packet-capture services were all active after restart.

## Central Wazuh Recovery

The Wazuh dashboard failure exposed two separate faults:

1. The indexer had been offline for approximately 17 days after exceeding its startup timeout during two boot sequences.
2. The manager service appeared active, but its internal analysis engine was not running.

Recovery and resilience changes:

- Restored the indexer without disrupting unrelated workloads.
- Restored the analysis engine and verified its process was running.
- Increased the indexer startup timeout to 10 minutes.
- Set indexer restart behavior to `on-failure` with a 30-second delay.
- Verified the manager, indexer, dashboard, and Filebeat services were active.

The timeout explains the immediate service failure mechanism. The underlying reason the indexer needed more startup time remains unproven.

## End-to-End Validation

A repeatable local signature replaced an obsolete third-party IDS test site.

### Controlled Test

- Sent three ICMP echo requests from a separate workstation to the sensor.
- Suricata recorded all three in both its fast alert log and JSON event log.
- Wazuh received and decoded all three alerts under its Suricata ruleset.
- The observed event-to-manager delay was approximately one second.
- The manager's decoder errors stopped before the successful filtered test; this was encouraging immediate evidence, not a long-term stability result.

### Storage and Dashboard Path

- Filebeat passed DNS, TCP, certificate-chain, TLS handshake, and server communication checks.
- The connection used certificate-verified TLS 1.3.
- The dashboard displayed 16 indexed Suricata alerts from the sensor.
- No high-severity alerts appeared in the filtered dashboard results; that does not establish that the full network was threat-free.

## Automated Maintenance

Two boot-persistent timers were enabled:

| Job | Schedule | Action |
|---|---|---|
| Suricata rule maintenance | Daily at 03:00 | Update rules, validate configuration, then reload rules |
| Packet retention | Hourly | Delete routine sensor captures older than 24 hours |

The rule-update workflow was manually started once and completed without reported error. At audit close, the first naturally scheduled run of each timer had not yet occurred.

## Known Limitations

- **Partial visibility:** A wireless endpoint generally sees its own unicast traffic plus broadcast and multicast traffic, not all switched-network traffic.
- **Decoder stability:** Alert-only filtering passed the controlled test, but sustained decoder stability still requires observation.
- **Silent-failure risk:** Independent service-health checks and failure/recovery notifications were not yet implemented.
- **Retention evidence:** Timer configuration and scheduling were verified; the first scheduled cleanup run remained pending.
- **Historical gap:** The audit did not establish whether alerts were lost during the indexer and analysis-engine outage.

## Pending Maintenance

- Add Signal notifications for sensor reachability, capture failure, IDS failure, Wazuh component failure, disk pressure, rule-update failure, and high-severity alerts.
- Validate notification deduplication and recovery messages.
- Move the sensor to an appropriate mirrored Ethernet port or network tap for broader visibility.
- Observe decoder logs over a sustained period and define an alert threshold for recurrence.
- Verify the first scheduled rule-update and retention runs.
- Review network segmentation for IoT and camera devices.

## Skills Demonstrated

- macOS endpoint triage and network-service review
- Nmap-based asset validation
- Dumpcap ring-buffer capture and systemd service design
- Suricata deployment, rule management, and controlled signature testing
- Wazuh agent integration and JSON-event filtering
- Wazuh manager, indexer, dashboard, and Filebeat recovery
- Evidence-based verification and explicit limitation tracking
