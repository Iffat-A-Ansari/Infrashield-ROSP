"""
app.py
-------
Infrashield - Anomaly Detection Module (Feature 3)

Kya karta hai:
1. Background thread har 5 second me system metrics collect karta hai
   (CPU, memory, disk I/O rate, network I/O rate, process count).
2. Pehle 60 samples (~5 min) "baseline" ban jaate hain -- fir Isolation
   Forest model train hota hai un par.
3. Uske baad har naye sample ko model se check karte hain -- agar anomaly
   lage to flag + log + dashboard par highlight.
4. Model har 100 naye samples ke baad retrain hota hai taaki "normal" ka
   definition system ke actual usage pattern ke saath update hota rahe.

Run (local): python3 app.py
Run (docker): docker-compose up --build
Dashboard: http://localhost:5000
"""

import json
import os
import threading
import time

import psutil
from flask import Flask, jsonify, render_template

from anomaly_detector.db import init_db, insert_metric, fetch_recent, fetch_anomalies, count_metrics
from anomaly_detector.detector import AnomalyDetector

app = Flask(__name__)

BASELINE_SIZE = 60        # itne samples ke baad pehli baar training hogi
RETRAIN_INTERVAL = 100    # har itne naye samples ke baad retrain
COLLECT_INTERVAL = 5      # seconds between samples

DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
LOG_FILE = os.path.join(DATA_DIR, "anomalies.log")

detector = AnomalyDetector(contamination=0.05)
_prev_counters = {"disk": None, "net": None, "time": None}
_new_since_train = 0
_lock = threading.Lock()


def collect_sample():
    """Ek metric snapshot leta hai. Disk/network ke liye cumulative counters
    ko rate (bytes/sec) me convert karta hai kyunki raw cumulative values
    ML model ke liye useful nahi hote."""
    global _prev_counters

    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_io_counters()
    net = psutil.net_io_counters()
    now = time.time()

    if _prev_counters["time"] is None or disk is None:
        disk_read_rate = disk_write_rate = 0.0
        net_sent_rate = net_recv_rate = 0.0
    else:
        dt = max(now - _prev_counters["time"], 1e-6)
        disk_read_rate = (disk.read_bytes - _prev_counters["disk"].read_bytes) / dt
        disk_write_rate = (disk.write_bytes - _prev_counters["disk"].write_bytes) / dt
        net_sent_rate = (net.bytes_sent - _prev_counters["net"].bytes_sent) / dt
        net_recv_rate = (net.bytes_recv - _prev_counters["net"].bytes_recv) / dt

    _prev_counters = {"disk": disk, "net": net, "time": now}

    return {
        "timestamp": now,
        "cpu_percent": cpu,
        "mem_percent": mem,
        "disk_read_rate": max(disk_read_rate, 0.0),
        "disk_write_rate": max(disk_write_rate, 0.0),
        "net_sent_rate": max(net_sent_rate, 0.0),
        "net_recv_rate": max(net_recv_rate, 0.0),
        "process_count": len(psutil.pids()),
    }


def log_anomaly(sample, score):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({**sample, "anomaly_score": score}) + "\n")


def background_loop():
    global _new_since_train
    while True:
        sample = collect_sample()

        with _lock:
            is_anomaly, score = detector.predict(sample) if detector.model else (False, 0.0)

        insert_metric(sample, is_anomaly, score)
        if is_anomaly:
            log_anomaly(sample, score)

        with _lock:
            _new_since_train += 1
            total = count_metrics()

            if detector.model is None and total >= BASELINE_SIZE:
                detector.train(fetch_recent(BASELINE_SIZE))
                _new_since_train = 0
            elif detector.model is not None and _new_since_train >= RETRAIN_INTERVAL:
                detector.train(fetch_recent(200))
                _new_since_train = 0

        time.sleep(COLLECT_INTERVAL)


@app.route("/")
def index():
    return render_template("anomaly_detection.html")


@app.route("/api/metrics")
def api_metrics():
    return jsonify(fetch_recent(100))


@app.route("/api/anomalies")
def api_anomalies():
    return jsonify(fetch_anomalies(20))


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "total_samples": count_metrics(),
            "baseline_ready": detector.model is not None,
            "baseline_needed": BASELINE_SIZE,
        }
    )


if __name__ == "__main__":
    init_db()
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
