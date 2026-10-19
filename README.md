              ███████╗██╗   ██╗██████╗ ██████╗ ██╗     ██╗████████╗███████╗
              ██╔════╝██║   ██║██╔══██╗██╔══██╗██║     ██║╚══██╔══╝╚══███╔╝
              ███████╗██║   ██║██████╔╝██████╔╝██║     ██║   ██║     ███╔╝ 
              ╚════██║██║   ██║██╔══██╗██╔══██╗██║     ██║   ██║    ███╔╝  
              ███████║╚██████╔╝██████╔╝██████╔╝███████╗██║   ██║   ███████╗ 
              ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝                  
────  Fast multi-source subdomain enumeration for Python 3 ────
# Version 1.0
`subBlitz` is a modern subdomain enumeration tool written in Python 3. It combines passive enumeration across multiple public data sources with optional DNS bruteforce and TCP port scanning. Results are aggregated, deduplicated, and presented through a clean terminal interface.

---  
# Feature 
- Passive enumeration across multiple free, keyless data sources  
- Wildcard DNS detection to reduce false positives  
- Threaded DNS bruteforce with a built-in wordlist  
- Optional TCP port scan on all discovered hosts  
- Export results to a plain-text file  
- Rich terminal interface with live progress and a summary table  
- Optional API-keyed engines (VirusTotal, Chaos) for deeper coverage
---

# Installation

### 1. Clone the repository

```bash
git clone https://github.com/danish-pentest/subBlitz.git  
cd subBlitz  
```

## 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv  
source venv/bin/activate # Linux / macOS  
# venv\Scripts\activate # Windows  
```

## 3. Install dependencies

```bash
pip install -r requirements.txt  
```
## 4. Optional: set API keys

```
export VIRUSTOTAL_API_KEY="your_vt_key"  
export PDCP_API_KEY="your_chaos_key"  
# or  
export CHAOS_KEY="your_chaos_key"  
```


---

# Usage

```
python3 subBlitz.py -d <domain> [options]  
```

## Options

| Flag | Description |
| --- | --- |
| `-d, --domain` | Required. Target domain (e.g. `example.com`) |
| `-e, --engines` | Comma-separated engine list, or `all`. Omit for keyless defaults |
| `-b, --bruteforce` | Enable DNS bruteforce |
| `-p, --ports` | Comma-separated TCP ports to scan on findings (e.g. `80,443,8080`) |
| `-t, --threads` | Bruteforce thread count (default: `30`) |
| `-o, --output` | Save results to a text file |
| `-q, --quiet` | Suppress realtime subdomain output |
| `-v, --version` | Show version |

---

# Examples

```
# All keyless engines  
python3 subBlitz.py -d example.com

# Only crt.sh  
python3 subBlitz.py -d example.com -e crt

# Every registered engine (keyless + keyed)  
python3 subBlitz.py -d example.com -e all

# DNS bruteforce only  
python3 subBlitz.py -d example.com -b

# Scan the apex on ports 80 and 443 only  
python3 subBlitz.py -d example.com -p 80,443

# crt.sh + bruteforce + port scan  
python3 subBlitz.py -d example.com -e crt -b -p 80,443

# Save results to file  
python3 subBlitz.py -d example.com -o results.txt  
```

---

# Engines

## Keyless (default)

| Engine | Source |
| --- | --- |
| `hackertarget` | HackerTarget |
| `rapiddns` | RapidDNS |
| `certspotter` | Cert Spotter |
| `urlscan` | urlscan.io |
| `anubis` | AnubisDB |
| `domainee` | Domainee |
| `crt` | crt.sh |

## Keyed (optional)

| Engine | Environment Variable | Free Tier |
| --- | --- | --- |
| `virustotal` | `VIRUSTOTAL_API_KEY` | 4 requests/min, 500/day |
| `chaos` | `PDCP_API_KEY` or `CHAOS_KEY` | Public dataset |

API keys are available from [VirusTotal](https://www.virustotal.com/) and [ProjectDiscovery Cloud](https://cloud.projectdiscovery.io/sign-in?redirect_url=https%3A%2F%2Fcloud.projectdiscovery.io%2Fscans%3Fref%3Dapi_key).

---
## Wordlist and Resolvers

Place `names.txt` in the same directory (or `subBlitz/names.txt`) with one candidate per line. Optionally supply `resolvers.txt` with one resolver IP per line. If missing, subBlitz will attempt to discover the target's authoritative nameservers, then fall back to public resolvers.

---
## Example Output

```  
▸ sub.api.example.com (via crt.sh)  
▸ dev.example.com (via HackerTarget)  
▸ mail.example.com (via RapidDNS)

────────────────── Summary ──────────────────

&nbsp; Total subdomains 14  
  Engines used 7

 Contributions  
  ┌──────────────┬───────┐  
  │ Engine       │ Found │  
  ├──────────────┼───────┤  
  │ crt.sh       │   9   │  
  │ HackerTarget │   4   │  
  │ RapidDNS     │   3   │  
  └──────────────┴───────┘

 Finished in 6.42s  
```
---

## How It Works

1. **Passive enumeration** — All selected engines run in parallel. Each reports findings live and feeds a shared result set.  
2. **Wildcard detection** — Before bruteforce, random subdomains are probed across all record types to detect wildcard DNS and suppress false positives.  
3. **Bruteforce** — Names from `names.txt` are resolved using discovered or supplied nameservers, with automatic fallback on transient errors.  
4. **Port scan** — If `-p` is passed, discovered hosts are scanned concurrently for open TCP ports.

---

## Requirements

- Python 3.9 or higher  
- `requests` >= 2.31.0  
- `dnspython` >= 2.4.0  
- `rich` >= 13.7.0  
- `colorama` >= 0.4.6

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `names.txt not found` | Place it in the project directory or `subBlitz/names.txt` |
| Engines return `empty` | The source may be rate-limiting or the domain has no indexed certificates |
| `No API key` warning | Expected for keyed engines — set the environment variable or omit the engine |
| Slow bruteforce | Reduce `-t` (threads) or check resolver health |
| No hosts scanned | Confirm the target resolved and you passed valid ports with `-p` |

---


# License

Released under the MIT License. See  [LICENSE](https://github.com/danish-pentest/subBlitz-/blob/main/LICENSE) for details.

---

## Author

**Danish-Pentest**

GitHub: https://github.com/danish-pentest

Built for ethical security researchers. Use responsibly.---

## Contributing

Pull requests are welcome. For larger changes, please open an issue first to discuss what you would like to change.



  
