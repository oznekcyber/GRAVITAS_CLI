```
 ██████╗ ██████╗  █████╗ ██╗   ██╗██╗████████╗ █████╗ ███████╗
██╔════╝ ██╔══██╗██╔══██╗██║   ██║██║╚══██╔══╝██╔══██╗██╔════╝
██║  ███╗██████╔╝███████║██║   ██║██║   ██║   ███████║███████╗
██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██║   ██║   ██╔══██║╚════██║
╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║   ██║   ██║  ██║███████║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
```

> **GRAVITAS** — An Open Source Intelligence (OSINT) CLI framework for aggregating digital footprint data across breach databases, social platforms, IP threat feeds, and more.

---

## ✨ Features

- 🔍 **Email Intelligence** — Validate format, check Gravatar, analyze MX/SPF/DMARC DNS records, detect disposable domains
- 💥 **Breach Database Lookup** — HaveIBeenPwned v3 API integration for breach and paste exposure
- 🌐 **Platform Sweep** — Concurrent username check across 160+ platforms with enriched profile metadata
- 🖥️ **IP Intelligence** — AbuseIPDB scoring, IPInfo geolocation, Shodan port/CVE scan, reverse DNS, and classification (Tor/VPN/datacenter/residential)
- 📱 **Phone Intelligence** — Phonenumbers library + NumVerify API, VOIP detection, carrier lookup
- 🔗 **Correlation Engine** — Cross-references findings: name matching, bio link graph, breach+platform overlap
- 🧩 **Persona Clustering** — Groups findings into identity clusters with confidence levels
- 📅 **Activity Timeline** — Chronological view of breach dates, account creations, paste exposures
- ⚖️ **Gravity Score** — Composite 0–100 risk score with band classification (LOW → CRITICAL)
- 📤 **JSON Export** — Export full results to a structured JSON file
- 🗄️ **SQLite Caching** — 24-hour cache to avoid redundant API calls
- 🎨 **Rich Terminal UI** — Color-coded output with spinners, tables, and progress bars

---

## 🚀 Installation

```bash
git clone https://github.com/GRAVITAS-CLI/GRAVITAS_CLI.git
cd GRAVITAS_CLI
pip install -r requirements.txt
```

---

## 🔑 API Keys

Set environment variables before running. All keys are **optional** — GRAVITAS degrades gracefully when keys are missing.

| Key | Service | Free Tier |
|-----|---------|-----------|
| `HIBP_KEY` | [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | Paid |
| `ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com/account/api) | Free (1000/day) |
| `SHODAN_KEY` | [Shodan](https://account.shodan.io/) | Free (limited) |
| `NUMVERIFY_KEY` | [NumVerify](https://numverify.com/) | Free (100/month) |
| `IPINFO_KEY` | [IPInfo](https://ipinfo.io/account) | Free (50k/month) |

```bash
export HIBP_KEY="your_key_here"
export ABUSEIPDB_KEY="your_key_here"
export SHODAN_KEY="your_key_here"
export NUMVERIFY_KEY="your_key_here"
export IPINFO_KEY="your_key_here"
```

---

## 📋 Usage

```bash
# Scan an email address
python gravitas.py --email target@example.com

# Scan a username across 150+ platforms
python gravitas.py --username johndoe

# Scan an IP address
python gravitas.py --ip 1.2.3.4

# Scan a phone number
python gravitas.py --phone +12125551234

# Full scan combining email + username
python gravitas.py --email target@example.com --username johndoe --full

# Export results to JSON
python gravitas.py --email target@example.com --output results.json

# Bypass cache for fresh results
python gravitas.py --username johndoe --no-cache

# Batch scan from file
./batch_gravitas.sh targets.txt
```

### All flags

| Flag | Short | Description |
|------|-------|-------------|
| `--email` | `-e` | Target email address |
| `--username` | `-u` | Target username |
| `--name` | `-n` | Target full name |
| `--ip` | `-i` | Target IP address |
| `--phone` | `-p` | Target phone number |
| `--full` | `-f` | Run all modules including bio link extraction |
| `--no-cache` | | Bypass SQLite cache |
| `--timeout` | `-t` | HTTP timeout in seconds (default: 10) |
| `--output` | `-o` | Export JSON results to file |

---

## 📊 Output Explanation

### Confidence Tags

| Tag | Meaning |
|-----|---------|
| `[CONFIRMED]` ✅ | Directly verified from an authoritative source |
| `[PROBABLE]` ⚠️ | Strong indicator but not directly verified |
| `[INFERRED]` ℹ️ | Logical deduction from available data |

### Gravity Score Bands

| Score | Band | Meaning |
|-------|------|---------|
| 0–20 | 🟢 LOW | Minimal digital footprint / low risk indicators |
| 21–40 | 🟡 MODERATE | Moderate footprint, some risk factors present |
| 41–60 | 🟠 ELEVATED | Notable footprint, multiple risk indicators |
| 61–80 | 🔴 HIGH | Significant exposure across multiple vectors |
| 81–100 | 🔥 CRITICAL | Extreme exposure — breaches + platforms + correlations |

### Score Breakdown

| Component | Max Points | Criteria |
|-----------|-----------|---------|
| Breach Exposure | 25 | 5pts per breach |
| Platform Spread | 20 | 1pt per confirmed platform |
| Cross-Source Correlations | 20 | 5pts per confirmed link |
| Persona Count | 10 | 2pts per correlation |
| IP Threat Score | 10 | Scaled from AbuseIPDB |
| Disposable Email | 5 | +5 if disposable domain |
| VOIP Phone | 5 | +5 if VOIP detected |
| Bio Link Depth | 5 | 1pt per bio link found |

---

## ⚠️ Disclaimer

GRAVITAS is intended for **legitimate OSINT research, security investigations, and educational purposes only**. Only use this tool against targets you have explicit permission to investigate, or for research into your own digital footprint. Misuse of this tool may violate computer fraud laws, privacy regulations (GDPR, CCPA), and platform terms of service. The authors assume no liability for misuse.
