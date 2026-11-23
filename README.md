# Network Intrusion Forensics & Automated IOC Triage (NetSupport RAT)

## Executive Summary
During a routine Tier-1 network traffic triage of a suspicious PCAP capture (`2026-02-28-traffic-analysis-exercise.pcap`), Command-and-Control (C2) beaconing activity associated with **NetSupport RAT** was identified originating from internal host **`10.2.28.88`**. 

The compromised endpoint established persistent outbound HTTP communications directly to external IP **`45.131.214.85`** over **TCP port 443** without performing a prior DNS lookup. To accelerate triage and eliminate manual lookups, a custom Python CLI tool (`ioc_enricher.py`) was developed to automatically enrich extracted Indicators of Compromise (IOCs) via the **VirusTotal v3** and **AbuseIPDB v2** REST APIs.

---

## Key Forensic Findings (Wireshark Analysis)

1. **C2 Beaconing & Direct-to-IP Communication:**
   * Internal host `10.2.28.88` sends periodic `HTTP POST` requests to `http://45.131.214.85/fakeurl.htm` at strict **60-second intervals** (e.g., timestamps `6903.25s`, `6963.33s`, `7023.40s`, `7083.68s`).
   * No DNS query precedes the connection to `45.131.214.85`, indicating hardcoded C2 infrastructure designed to evade DNS-based monitoring.
2. **Protocol / Port Mismatch:**
   * Cleartext HTTP traffic is transmitted over destination port **443** (standard HTTPS), triggering Wireshark's security warning (`Unencrypted HTTP protocol detected over encrypted port`).
3. **Malicious User-Agent & Server Banner:**
   * Client requests contain the signature header `User-Agent: NetSupport Manager/1.3`.
   * C2 responses (`HTTP/1.1 200 OK`) explicitly expose the server banner `Server: NetSupport Gateway/1.92 (Windows NT)`.
4. **C2 Protocol Handshake & Application-Layer Encryption (`tcp.stream eq 40`):**
   * Initial polling beacons transmit `CMD=POLL&INFO=1&ACK=1` to check for operator tasks.
   * Subsequent packets switch to encrypted payload exchange (`CMD=ENCD&ES=1&DATA=...`), transferring 62 KB of session data.

---

## Indicators of Compromise (IOCs) & Threat Intel Enrichment

All extracted indicators were programmatically verified using `ioc_enricher.py`:

| Indicator Type | Value | Context / Role | VirusTotal Result | AbuseIPDB Result |
| :--- | :--- | :--- | :--- | :--- |
| **IPv4 Address** | `45.131.214.85` | NetSupport RAT C2 Server (`MHost LLC`, DE) | **7 Malicious**, 3 Suspicious (48 Harmless) | `0%` Confidence Score (`0` reports) |
| **URL** | `http://45.131.214.85/fakeurl.htm` | C2 Polling & Command URI | Not indexed (`HTTP 200` empty body) | N/A |
| **User-Agent** | `NetSupport Manager/1.3` | Remote Access Trojan HTTP signature | Known RAT signature | N/A |
| **SHA-256** | `F0E200CACD273E3DD257057F27AEDA839A1F2F31482E0BB01EA8B1363A7AF245` | Exported HTTP C2 response object (`fakeurl.htm`) | `0` Malicious (Dynamic C2 response) | N/A |

> **Analyst Note:** While AbuseIPDB reports `0` abuse complaints for `45.131.214.85` (confirming it is not used for noisy internet-wide scanning), VirusTotal flags it across 7 security vendors. Cross-correlating multiple Threat Intelligence feeds is essential to avoid false negatives on dedicated C2 infrastructure.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence in PCAP |
| :--- | :--- | :--- | :--- |
| **Command and Control** | `T1071.001` | Application Layer Protocol: Web Protocols | Periodic `HTTP POST` beacons to `/fakeurl.htm` with `CMD=POLL` |
| **Command and Control** | `T1571` | Non-Standard Port | Unencrypted HTTP traffic routed over TCP port `443` |
| **Command and Control** | `T1573` | Encrypted Channel | Custom application-layer encryption (`CMD=ENCD&ES=1&DATA=...`) |
| **Command and Control** | `T1219` | Remote Access Software | Abuse of legitimate NetSupport Manager client (`NetSupport Manager/1.3`) |

---

## Containment & Remediation Recommendations

1. **Network Containment (Immediate):**
   * Block outbound traffic to `45.131.214.85` on perimeter firewalls, proxies, and EDR network isolation policies.
   * Implement firewall egress rules blocking cleartext HTTP traffic on TCP port `443`.
2. **Host Isolation & Forensics:**
   * Isolate internal host `10.2.28.88` from the corporate network via EDR to prevent lateral movement.
   * Inspect persistence mechanisms on `10.2.28.88` (Scheduled Tasks, Startup folders, Run registry keys) for unauthorized `client32.exe` / NetSupport binaries and remove them.
3. **Detection Engineering:**
   * Deploy SIEM/IDS rules alerting on `User-Agent` strings containing `NetSupport Manager` or HTTP `POST` requests targeting `/fakeurl.htm`.
   * Reset credentials for any accounts active on `10.2.28.88` during the compromise window.

---

## Automated IOC Enricher (`ioc_enricher.py`)

### Features
* Queries **AbuseIPDB v2** (`/api/v2/check`) for IP reputation, ISP, country code, and report history.
* Queries **VirusTotal v3** (`/api/v3/ip_addresses`, `/urls`, `/files`) for multi-engine vendor detections.
* Reads API keys securely from environment variables (`VT_API_KEY`, `ABUSEIPDB_API_KEY`) and exports structured results to `enrichment_output.json`.

### Usage
```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
python3 ioc_enricher.py
