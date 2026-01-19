import argparse, json, sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

INTERESTING = [
    "firebasestorage.googleapis.com",
    "cubbit.eu",
    "checkip.dyndns.org",
    "reallyfreegeoip.org",
    "api.telegram.org",
    "eraqron.com",
    "eraqron.shop",
]

def ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    con = sqlite3.connect(args.db)
    cur = con.cursor()

    rows = cur.execute("""
  SELECT ts, event_type, detail_json
  FROM events
  WHERE ts IS NOT NULL AND event_type <> 'packet_filter'
""").fetchall()
    if not rows:
        raise SystemExit("No events in DB (did Zeek JSON import run?)")

    event_counts = Counter()
    first_seen = {}
    hit_counts = Counter()
    hits = defaultdict(list)

    for ts, et, dj in rows:
        event_counts[et] += 1
        if et not in first_seen or ts < first_seen[et]:
            first_seen[et] = ts

        try:
            obj = json.loads(dj)
        except json.JSONDecodeError:
            continue

        # Pull a few common fields if present
        host = obj.get("host") or obj.get("server_name") or obj.get("query")
        if isinstance(host, str):
            for pat in INTERESTING:
                if pat in host:
                    hit_counts[pat] += 1
                    if len(hits[pat]) < 8:
                        hits[pat].append((ts, et, host))
        # SMTP specifics
        if et == "smtp":
            mf = obj.get("mailfrom")
            rcpt = obj.get("rcptto")
            if mf or rcpt:
                for pat in INTERESTING:
                    blob = f"{mf} {rcpt}"
                    if pat in blob:
                        hit_counts[pat] += 1
                        if len(hits[pat]) < 8:
                            hits[pat].append((ts, et, blob))

    min_ts = min(ts for ts, _, _ in rows)
    max_ts = max(ts for ts, _, _ in rows)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        f.write("# VIP Recovery mini-SOC report (2026-01-09 PCAP)\n\n")
        f.write(f"- Time range (UTC): {ts_iso(min_ts)} -> {ts_iso(max_ts)}\n")
        f.write(f"- Total events (all Zeek logs imported): {len(rows)}\n\n")

        f.write("## Event volume by type\n\n")
        for et, n in event_counts.most_common():
            f.write(f"- {et}: {n}\n")
        f.write("\n")

        f.write("## First-seen timestamp by type (UTC)\n\n")
        for et, ts in sorted(first_seen.items(), key=lambda x: x[1]):
            f.write(f"- {et}: {ts_iso(ts)}\n")
        f.write("\n")

        f.write("## Hits for key indicators (derived from Zeek logs)\n\n")
        if not hit_counts:
            f.write("- No matches found for the built-in indicator list.\n")
        else:
            for pat, n in hit_counts.most_common():
                f.write(f"### {pat} (matches: {n})\n\n")
                for ts, et, val in hits[pat]:
                    f.write(f"- {ts_iso(ts)} [{et}] {val}\n")
                f.write("\n")

    con.close()

if __name__ == "__main__":
    main()
