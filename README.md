# VIP Recovery mini-SOC (PCAP -> Zeek -> SQLite -> Report)

A small incident investigation pipeline built around the
2026-01-09 "VIP Recovery" malware-traffic case PCAP.

What it does:
- Takes a PCAP capture as evidence
- Runs Zeek to generate structured telemetry (JSON logs)
- Imports Zeek logs into a SQLite database (events table)
- Runs a few sanity/triage SQL queries
- Generates a compact Markdown summary report (reports/summary.md)

Purpose:
- Demonstrate SOC / incident-response skills: evidence handling, timeline reconstruction,
  IOC extraction, and repeatable analysis.

---

## Repository layout

viprecovery-mini-soc/
  scripts/            Pipeline scripts (committed)
  sql/                Example analysis queries (committed)
  reports/             Generated reports (you may commit Markdown reports)
  data/
    raw/              PCAP/IOC downloads (git-ignored)
    zeek/             Zeek logs (git-ignored)
    suricata/         Suricata output (git-ignored, optional)
  db/                 SQLite DB (git-ignored)
  requirements.txt
  .gitignore
  README.md

Important: this repo is set up to NOT commit PCAPs, Zeek output, or the SQLite database.
Only scripts + SQL + (optional) reports should be public.

---

## Prerequisites

- Linux or WSL (Ubuntu recommended)
- Python 3 + venv
- sqlite3
- Zeek (installed and on PATH)
- 7z (p7zip-full) for password-protected zip extraction
- curl

Ubuntu/WSL install:

```bash
sudo apt update
sudo apt install -y git curl p7zip-full sqlite3 python3-venv python3-pip jq
zeek -v
```

---

## Setup (one-time)

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## Data acquisition (PCAP + IOCs)

This project expects the following under data/raw/:

- data/raw/2026-01-09-VIP-Recovery-traffic.pcap
- (optional) IOC text file extracted from the same post

The source zips are password-protected. Use the password scheme described on the
source site's About page.

Example (adjust password and filenames if the source changes either):

```bash
mkdir -p data/raw

curl -L -o data/raw/2026-01-09-VIP-Recovery-traffic.pcap.zip \
  https://www.malware-traffic-analysis.net/2026/01/09/2026-01-09-VIP-Recovery-traffic.pcap.zip

curl -L -o data/raw/2026-01-09-IOCs-from-VIP-Recovery-infection.txt.zip \
  https://www.malware-traffic-analysis.net/2026/01/09/2026-01-09-IOCs-from-VIP-Recovery-infection.txt.zip

ZIP_PW="infected_20260109"
7z x -p"$ZIP_PW" -odata/raw data/raw/2026-01-09-VIP-Recovery-traffic.pcap.zip
7z x -p"$ZIP_PW" -odata/raw data/raw/2026-01-09-IOCs-from-VIP-Recovery-infection.txt.zip
```

Safety note: treat downloaded artifacts as potentially hazardous. This repo analyzes
network captures, you do not need to execute or open any malware payloads.

---

## Run the pipeline (recommended)

Use the rebuild script to avoid duplicated rows:

```bash
./scripts/rebuild.sh
```

The rebuild script does a clean rebuild:
1) Removes prior DB/log outputs
2) Runs Zeek on the PCAP (JSON output)
3) Imports Zeek JSON logs -> SQLite DB
4) Runs sql/quick_checks.sql
5) Generates reports/summary.md

Outputs:
- db/viprecovery.sqlite (git-ignored)
- reports/quick_checks.txt
- reports/summary.md

---

## Manual run (step-by-step)

```bash
source .venv/bin/activate

# 1) Clean artifacts to prevent duplicates
./scripts/clean.sh

# 2) Run Zeek -> JSON logs
(cd data/zeek && zeek -C -r ../raw/2026-01-09-VIP-Recovery-traffic.pcap LogAscii::use_json=T)

# 3) Import Zeek logs -> SQLite
python scripts/build_db.py --zeek-dir data/zeek --db db/viprecovery.sqlite

# 4) Quick triage queries
sqlite3 db/viprecovery.sqlite < sql/quick_checks.sql | tee reports/quick_checks.txt

# 5) Summary report
python scripts/make_report.py --db db/viprecovery.sqlite --out reports/summary.md
```

---

## Example queries

```bash
sqlite3 -header -column db/viprecovery.sqlite \
  "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC;"
```

Common pulls:
- HTTP requests (host/uri)
- DNS queries
- TLS SNI (ssl.server_name)
- SMTP metadata (mailfrom/rcptto)

Starter queries live in sql/quick_checks.sql.

---

## Optional: Suricata alerts (alerts table)

If you want IDS-style alerts, run Suricata on the PCAP and import eve.json:

```bash
sudo apt install -y suricata suricata-update
sudo suricata-update

mkdir -p data/suricata
suricata -r data/raw/2026-01-09-VIP-Recovery-traffic.pcap -l data/suricata

python scripts/import_suricata_alerts.py --eve data/suricata/eve.json --db db/viprecovery.sqlite

sqlite3 -header -column db/viprecovery.sqlite \
  "SELECT severity, rule_id, COUNT(*) AS n FROM alerts GROUP BY severity, rule_id ORDER BY severity DESC, n DESC;"
```

Suricata is optional, the project is complete without it.
