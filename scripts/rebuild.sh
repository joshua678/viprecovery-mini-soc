set -euo pipefail

rm -f db/viprecovery.sqlite
rm -f data/zeek/*.log
rm -f reports/summary.md reports/quick_checks.txt

(cd data/zeek && zeek -C -r ../raw/2026-01-09-VIP-Recovery-traffic.pcap LogAscii::use_json=T)

source .venv/bin/activate
python scripts/build_db.py --zeek-dir data/zeek --db db/viprecovery.sqlite
sqlite3 db/viprecovery.sqlite < sql/quick_checks.sql > reports/quick_checks.txt
python scripts/make_report.py --db db/viprecovery.sqlite --out reports/summary.md
