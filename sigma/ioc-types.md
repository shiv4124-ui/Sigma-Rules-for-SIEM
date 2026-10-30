# Indicator of Compromise (IOC) Types

All examples use reserved documentation ranges (RFC 5737 IPs, RFC 5398 ASNs, `example.com`) or empty-input hashes — safe placeholders.

| Type | Example (placeholder) | Notes |
|---|---|---|
| IPv4/IPv6 address | `203.0.113[.]45` | C2 servers, scanners, exfiltration endpoints |
| Domain | `update-check[.]example[.]com` | Phishing, C2, malware delivery |
| URL | `hxxp://198.51.100[.]7/payload.exe` | Specific malicious paths |
| File hash (MD5) | `d41d8cd98f00b204e9800998ecf8427e` | Fast but weak — prefer SHA256 |
| File hash (SHA1) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | Legacy matching |
| File hash (SHA256) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Standard for malware identification |
| Email address | `billing@invoice-secure[.]example` | Phishing senders |
| Email subject / attachment | `Invoice_Overdue.zip` | Phishing campaigns |
| File name / path | `C:\Users\Public\svchost32.exe` | Masquerading binaries |
| Registry key | `HKCU\...\Run\Updater` | Persistence |
| Mutex | `Global\XyZ_mtx_01` | Malware-specific markers |
| User-agent string | Unusual or hardcoded browser strings | C2 beaconing |
| JA3/JA4 fingerprint | TLS client hash | Malware TLS traffic |
| SSL certificate hash | Certificate SHA1 | Self-signed C2 certificates |
| ASN | `AS64500` | Bulletproof hosting ranges |
| Crypto wallet | Wallet address | Ransomware payments |

## Columns every IOC list should have
Indicator (defanged) · IOC type · Threat actor / malware family · MITRE ATT&CK technique · Confidence ·
Severity · First seen · Last seen · Source · Action taken · Expiry / review date · Notes

IPs go stale in days to weeks; hashes last much longer. Set an expiry and re-validate.

## Free IOC sources
| Source | Provides |
|---|---|
| [abuse.ch MalwareBazaar](https://bazaar.abuse.ch) | Malware file hashes |
| [abuse.ch URLhaus](https://urlhaus.abuse.ch) | Malicious URLs |
| [abuse.ch ThreatFox](https://threatfox.abuse.ch) | Mixed IOCs |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch) | Botnet C2 IPs |
| [AlienVault OTX](https://otx.alienvault.com) | Community IOC pulses |
| [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | IOCs in official alerts |
| [CERT-In](https://www.cert-in.org.in) | Indian national CERT advisories |
| [MISP](https://www.misp-project.org) | Threat-intel sharing platform |
| [VirusTotal](https://www.virustotal.com) | Hash / domain / IP lookup |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Malicious IP ranges |

Tracker template with sample data: [`resources/IOC_Tracker.xlsx`](../resources/IOC_Tracker.xlsx)
(the sample indicators were pulled from abuse.ch on 2026-10-13 and are now stale).
