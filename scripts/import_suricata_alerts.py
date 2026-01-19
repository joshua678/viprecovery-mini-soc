import argparse, json, sqlite3
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", required=True, help="Path to Suricata eve.json")
    ap.add_argument("--db", required=True, help="SQLite db path (same db as events is fine)")
    args = ap.parse_args()

    eve_path = Path(args.eve)
    db_path = Path(args.db)

    con = sqlite3.connect(str(db_path))
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        timestamp TEXT,
        severity INTEGER,
        rule_id INTEGER,
        signature TEXT,
        category TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        proto TEXT,
        raw_json TEXT
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);")

    ins = """
    INSERT INTO alerts (timestamp, severity, rule_id, signature, category, src_ip, src_port, dest_ip, dest_port, proto, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    batch = []
    with eve_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("event_type") != "alert":
                continue
            alert = obj.get("alert", {})
            batch.append((
                obj.get("timestamp"),
                alert.get("severity"),
                alert.get("signature_id"),
                alert.get("signature"),
                alert.get("category"),
                obj.get("src_ip"),
                obj.get("src_port"),
                obj.get("dest_ip"),
                obj.get("dest_port"),
                obj.get("proto"),
                json.dumps(obj, separators=(",", ":"), ensure_ascii=True),
            ))
            if len(batch) >= 2000:
                con.executemany(ins, batch)
                con.commit()
                batch.clear()

    if batch:
        con.executemany(ins, batch)
        con.commit()

    con.close()

if __name__ == "__main__":
    main()