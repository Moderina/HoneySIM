import argparse

from sqlalchemy import text
from database.database import init_db, make_engine

def print_table(rows, headers) -> None:
    rows = [["" if v is None else str(v) for v in row] for row in rows]
    widths = [min(max([len(h)] + [len(r[i]) for r in rows]), 60) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(v[:w].ljust(w) for v, w in zip(r, widths)))
    print(f"({len(rows)} rows)")


def run(conn, query: str, **params) -> None:
    result = conn.execute(text(query), params)
    print_table(result.fetchall(), list(result.keys()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    ev = sub.add_parser("events")
    ev.add_argument("-n", type=int, default=20)
    ev.add_argument("--type")
    ev.add_argument("--ip")
    al = sub.add_parser("alerts")
    al.add_argument("-n", type=int, default=20)
    sub.add_parser("hosts")
    sub.add_parser("rejected")
    sql = sub.add_parser("sql")
    sql.add_argument("query")
    args = parser.parse_args()

    engine = make_engine()
    init_db(engine)
    with engine.connect() as conn:
        if args.cmd == "stats":
            run(conn, "SELECT (SELECT COUNT(*) FROM events) AS events, (SELECT COUNT(*) FROM hosts) AS hosts, "
                      "(SELECT COUNT(*) FROM alerts) AS alerts, (SELECT COUNT(*) FROM rejected_logs) AS rejected")
            run(conn, "SELECT alert_type, severity, status, COUNT(*) AS count FROM alerts GROUP BY 1, 2, 3")
            run(conn, "SELECT protocol, event_type, severity, COUNT(*) AS count FROM events "
                      "GROUP BY 1, 2, 3 ORDER BY count DESC")
            run(conn, "SELECT path, \"offset\", updated_at FROM collector_state")
        elif args.cmd == "events":
            where, params = [], {"n": args.n}
            if args.type:
                where.append("event_type = :type")
                params["type"] = args.type.upper()
            if args.ip:
                where.append("source_ip = :ip")
                params["ip"] = args.ip
            clause = f"WHERE {' AND '.join(where)}" if where else ""
            run(conn, "SELECT id, timestamp, source_ip, destination_port AS dport, protocol, event_type, "
                      f"severity, username, password, message FROM events {clause} ORDER BY id DESC LIMIT :n",
                **params)
        elif args.cmd == "alerts":
            run(conn, "SELECT id, severity, alert_type, source_ip, status, event_count AS events, "
                      "first_seen, last_seen, description FROM alerts ORDER BY id DESC LIMIT :n", n=args.n)
        elif args.cmd == "hosts":
            run(conn, "SELECT ip, first_seen, last_seen, event_count FROM hosts ORDER BY event_count DESC")
        elif args.cmd == "rejected":
            run(conn, "SELECT id, received_at, error, raw_log FROM rejected_logs ORDER BY id DESC LIMIT 50")
        elif args.cmd == "sql":
            run(conn, args.query)


if __name__ == "__main__":
    main()
