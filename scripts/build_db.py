import argparse, json, sqlite3
from pathlib import Path

def get_field(obj, dotted, default=None):
    if dotted in obj:
        return obj.get(dotted, default)
    parts = dotted.split(".")
    cur = obj
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def iter_json_lines(p: Path):
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zeek-dir", required=True, help="Directory containing Zeek *.log files in JSON-lines format")
    ap.add_argument("--db", required=True, help="Output SQLite db path")
    args = ap.parse_args()

    zeek_dir = Path(args.zeek_dir)
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(str(db_path))
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("""
    CREATE TABLE IF NOT EXISTS events (
        ts REAL,
        event_type TEXT,
        uid TEXT,
        orig_h TEXT,
        orig_p INTEGER,
        resp_h TEXT,
        resp_p INTEGER,
        proto TEXT,
        service TEXT,
        detail_json TEXT
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")

    insert_sql = """
    INSERT INTO events (ts, event_type, uid, orig_h, orig_p, resp_h, resp_p, proto, service, detail_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    log_files = sorted([p for p in zeek_dir.glob("*.log") if p.is_file()])
    if not log_files:
        raise SystemExit(f"No Zeek *.log files found in: {zeek_dir}")

    for lf in log_files:
        event_type = lf.stem  # conn, http, dns, ssl, smtp, ...
        batch = []
        for obj in iter_json_lines(lf):
            ts = obj.get("ts", None)
            uid = obj.get("uid", None)
            orig_h = get_field(obj, "id.orig_h", None)
            orig_p = get_field(obj, "id.orig_p", None)
            resp_h = get_field(obj, "id.resp_h", None)
            resp_p = get_field(obj, "id.resp_p", None)
            proto = obj.get("proto", None)
            service = obj.get("service", None)
            detail_json = json.dumps(obj, separators=(",", ":"), ensure_ascii=True)
            batch.append((ts, event_type, uid, orig_h, orig_p, resp_h, resp_p, proto, service, detail_json))

            if len(batch) >= 5000:
                con.executemany(insert_sql, batch)
                con.commit()
                batch.clear()

        if batch:
            con.executemany(insert_sql, batch)
            con.commit()

    con.close()

if __name__ == "__main__":
    main()