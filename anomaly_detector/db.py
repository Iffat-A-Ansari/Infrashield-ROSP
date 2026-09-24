"""
db.py
------
Bahut simple SQLite wrapper. Ye har collected metric sample ko store karta
hai, saath me anomaly flag aur anomaly score bhi (agar model trained hai).
"""

import os
import sqlite3
import threading

DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "metrics.db")

# Har thread ka apna connection (Flask + background thread dono alag threads hain)
_local = threading.local()


def get_conn():
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return _local.conn


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            cpu_percent REAL,
            mem_percent REAL,
            disk_read_rate REAL,
            disk_write_rate REAL,
            net_sent_rate REAL,
            net_recv_rate REAL,
            process_count INTEGER,
            is_anomaly INTEGER,
            anomaly_score REAL
        )
        """
    )
    conn.commit()


def insert_metric(sample, is_anomaly, score):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO metrics
        (timestamp, cpu_percent, mem_percent, disk_read_rate, disk_write_rate,
         net_sent_rate, net_recv_rate, process_count, is_anomaly, anomaly_score)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            sample["timestamp"],
            sample["cpu_percent"],
            sample["mem_percent"],
            sample["disk_read_rate"],
            sample["disk_write_rate"],
            sample["net_sent_rate"],
            sample["net_recv_rate"],
            sample["process_count"],
            int(is_anomaly),
            score,
        ),
    )
    conn.commit()


def fetch_recent(n):
    """Last n samples, purane se naye order me (chart ke liye)."""
    conn = get_conn()
    cur = conn.execute("SELECT * FROM metrics ORDER BY id DESC LIMIT ?", (n,))
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    return list(reversed(rows))


def fetch_anomalies(n):
    conn = get_conn()
    cur = conn.execute(
        "SELECT * FROM metrics WHERE is_anomaly=1 ORDER BY id DESC LIMIT ?", (n,)
    )
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def count_metrics():
    conn = get_conn()
    cur = conn.execute("SELECT COUNT(*) FROM metrics")
    return cur.fetchone()[0]
