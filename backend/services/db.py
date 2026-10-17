"""Tiny SQLite store: scan history, user feedback and the learned allow/block list."""
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "phishlens.db"


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT,
                target TEXT, score INTEGER, verdict TEXT);
            CREATE TABLE IF NOT EXISTS feedback(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, scan_id INTEGER,
                kind TEXT, target TEXT, user_label TEXT, predicted TEXT);
            CREATE TABLE IF NOT EXISTS learned(
                domain TEXT PRIMARY KEY, label TEXT, ts REAL);
            """
        )


init()


def add_scan(kind, target, score, verdict) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO scans(ts,kind,target,score,verdict) VALUES(?,?,?,?,?)",
            (time.time(), kind, target[:500], score, verdict),
        )
        return cur.lastrowid


def add_feedback(scan_id, kind, target, user_label, predicted, domain=None):
    """Store feedback; for links, also learn the domain (latest label wins)."""
    with connect() as c:
        c.execute(
            "INSERT INTO feedback(ts,scan_id,kind,target,user_label,predicted) VALUES(?,?,?,?,?,?)",
            (time.time(), scan_id, kind, target[:2000], user_label, predicted),
        )
        if domain:
            label = "block" if user_label == "phishing" else "allow"
            c.execute(
                "INSERT INTO learned(domain,label,ts) VALUES(?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET label=excluded.label, ts=excluded.ts",
                (domain, label, time.time()),
            )


def learned_label(domain):
    with connect() as c:
        row = c.execute("SELECT label FROM learned WHERE domain=?", (domain,)).fetchone()
        return row["label"] if row else None


def history(limit=50):
    with connect() as c:
        rows = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def feedback_rows(kinds=("url", "qr")):
    marks = ",".join("?" * len(kinds))
    with connect() as c:
        rows = c.execute(f"SELECT target, user_label, kind FROM feedback WHERE kind IN ({marks})", kinds).fetchall()
        return [dict(r) for r in rows]


def stats():
    with connect() as c:
        out = {"total": 0, "safe": 0, "suspicious": 0, "dangerous": 0}
        for row in c.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict"):
            out[row["verdict"]] = row["n"]
            out["total"] += row["n"]
        out["feedback"] = c.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        out["learned_domains"] = c.execute("SELECT COUNT(*) FROM learned").fetchone()[0]
        return out
