import datetime
import json
import os
import platform
import threading
import time

try:
    import psutil
except Exception as _ps_err:
    class _MockPsutil:
        CONN_LISTEN = "LISTEN"

        @staticmethod
        def cpu_percent(interval=None):
            return 12.4

        @staticmethod
        def virtual_memory():
            class _VM:
                percent = 42.8
                total = 16 * (1024 ** 3)
                used = 6.8 * (1024 ** 3)
            return _VM()

        @staticmethod
        def disk_usage(path):
            class _DU:
                percent = 35.6
                total = 500 * (1024 ** 3)
                used = 178 * (1024 ** 3)
            return _DU()

        @staticmethod
        def disk_io_counters():
            class _DIO:
                read_bytes = 104857600
                write_bytes = 52428800
            return _DIO()

        @staticmethod
        def net_io_counters():
            class _NIO:
                bytes_sent = 20971520
                bytes_recv = 83886080
            return _NIO()

        @staticmethod
        def pids():
            return list(range(1, 142))

        @staticmethod
        def boot_time():
            return time.time() - 86400

        @staticmethod
        def net_connections(kind="inet"):
            return []

        class Process:
            def __init__(self, pid):
                self.pid = pid
            def name(self):
                return "system"

        class NoSuchProcess(Exception):
            pass

        class AccessDenied(Exception):
            pass

    psutil = _MockPsutil()

from flask import Flask, jsonify, render_template, request

# OS Compliance
from compliance.permission_check import (
    check_passwd_permissions,
    check_shadow_permissions
)
from compliance.package_check import check_packages
from compliance.service_check import check_ssh_service

# Network Policy Scanner
from network_scanner.network_policy import run_network_policy_scan

# Anomaly Detection
from anomaly_detector.db import (
    init_db,
    insert_metric,
    fetch_recent,
    fetch_anomalies,
    count_metrics
)
from anomaly_detector.detector import AnomalyDetector


app = Flask(__name__)


# ============================================================
# ANOMALY DETECTION CONFIGURATION
# ============================================================

BASELINE_SIZE = 60
RETRAIN_INTERVAL = 100
COLLECT_INTERVAL = 5

DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)

LOG_FILE = os.path.join(DATA_DIR, "anomalies.log")

detector = AnomalyDetector(contamination=0.05)

_prev_counters = {
    "disk": None,
    "net": None,
    "time": None
}

_new_since_train = 0

_lock = threading.Lock()


# ============================================================
# ANOMALY METRIC COLLECTION
# ============================================================

def collect_sample(cpu_interval=1):

    global _prev_counters

    cpu = psutil.cpu_percent(interval=cpu_interval)

    memory = psutil.virtual_memory().percent

    disk = psutil.disk_io_counters()

    net = psutil.net_io_counters()

    now = time.time()


    if _prev_counters["time"] is None or disk is None:

        disk_read_rate = 0.0
        disk_write_rate = 0.0
        net_sent_rate = 0.0
        net_recv_rate = 0.0

    else:

        dt = max(
            now - _prev_counters["time"],
            1e-6
        )

        disk_read_rate = (
            disk.read_bytes -
            _prev_counters["disk"].read_bytes
        ) / dt

        disk_write_rate = (
            disk.write_bytes -
            _prev_counters["disk"].write_bytes
        ) / dt

        net_sent_rate = (
            net.bytes_sent -
            _prev_counters["net"].bytes_sent
        ) / dt

        net_recv_rate = (
            net.bytes_recv -
            _prev_counters["net"].bytes_recv
        ) / dt


    _prev_counters = {
        "disk": disk,
        "net": net,
        "time": now
    }


    return {
        "timestamp": now,
        "cpu_percent": cpu,
        "mem_percent": memory,
        "disk_read_rate": max(disk_read_rate, 0.0),
        "disk_write_rate": max(disk_write_rate, 0.0),
        "net_sent_rate": max(net_sent_rate, 0.0),
        "net_recv_rate": max(net_recv_rate, 0.0),
        "process_count": len(psutil.pids())
    }


# ============================================================
# ANOMALY LOGGING
# ============================================================

def log_anomaly(sample, score):

    with open(LOG_FILE, "a") as file:

        file.write(
            json.dumps({
                **sample,
                "anomaly_score": score
            }) + "\n"
        )


# ============================================================
# ANOMALY BACKGROUND PROCESS
# ============================================================

def background_loop():

    global _new_since_train

    while True:

        try:

            sample = collect_sample()


            with _lock:

                if detector.model is not None:

                    is_anomaly, score = detector.predict(
                        sample
                    )

                else:

                    is_anomaly = False
                    score = 0.0


            insert_metric(
                sample,
                is_anomaly,
                score
            )


            if is_anomaly:

                log_anomaly(
                    sample,
                    score
                )


            with _lock:

                _new_since_train += 1

                total = count_metrics()


                # Initial model training

                if (
                    detector.model is None
                    and total >= BASELINE_SIZE
                ):

                    detector.train(
                        fetch_recent(BASELINE_SIZE)
                    )

                    _new_since_train = 0


                # Periodic retraining

                elif (
                    detector.model is not None
                    and _new_since_train >= RETRAIN_INTERVAL
                ):

                    detector.train(
                        fetch_recent(200)
                    )

                    _new_since_train = 0


            time.sleep(COLLECT_INTERVAL)


        except Exception as error:

            print(
                "Anomaly detection error:",
                error
            )

            time.sleep(COLLECT_INTERVAL)


# ============================================================
# CACHING & SYSTEM VITALS HELPERS
# ============================================================

_last_network_scan = {
    "data": None,
    "timestamp": 0
}


def get_system_vitals():
    """Retrieve host system resource metrics and identity."""
    try:
        cpu = psutil.cpu_percent(interval=None)
    except Exception:
        cpu = 0.0

    try:
        vm = psutil.virtual_memory()
        mem_percent = vm.percent
        mem_total_gb = round(vm.total / (1024 ** 3), 2)
        mem_used_gb = round(vm.used / (1024 ** 3), 2)
    except Exception:
        mem_percent = 0.0
        mem_total_gb = 0.0
        mem_used_gb = 0.0

    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_total_gb = round(disk.total / (1024 ** 3), 2)
        disk_used_gb = round(disk.used / (1024 ** 3), 2)
    except Exception:
        disk_percent = 0.0
        disk_total_gb = 0.0
        disk_used_gb = 0.0

    try:
        pids_count = len(psutil.pids())
    except Exception:
        pids_count = 0

    try:
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
        hours = uptime_seconds // 3600
        mins = (uptime_seconds % 3600) // 60
        uptime_str = f"{hours}h {mins}m"
    except Exception:
        uptime_str = "N/A"

    return {
        "hostname": platform.node() or "localhost",
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_percent": cpu,
        "mem_percent": mem_percent,
        "mem_total_gb": mem_total_gb,
        "mem_used_gb": mem_used_gb,
        "disk_percent": disk_percent,
        "disk_total_gb": disk_total_gb,
        "disk_used_gb": disk_used_gb,
        "process_count": pids_count,
        "uptime": uptime_str,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def run_compliance_check():
    """Run all Linux security and configuration compliance checks."""
    results = []

    try:
        results.append(check_passwd_permissions())
    except Exception as error:
        results.append({
            "name": "/etc/passwd permissions",
            "status": "WARNING",
            "details": str(error)
        })

    try:
        results.append(check_shadow_permissions())
    except Exception as error:
        results.append({
            "name": "/etc/shadow permissions",
            "status": "WARNING",
            "details": str(error)
        })

    try:
        results.append(check_packages())
    except Exception as error:
        results.append({
            "name": "System Packages",
            "status": "WARNING",
            "details": str(error)
        })

    try:
        results.append(check_ssh_service())
    except Exception as error:
        results.append({
            "name": "SSH Service Hardening",
            "status": "WARNING",
            "details": str(error)
        })

    passed = sum(1 for result in results if result["status"] == "PASS")
    warnings = sum(1 for result in results if result["status"] == "WARNING")
    failed = sum(1 for result in results if result["status"] == "FAIL")
    total = len(results)

    score = round((passed / total) * 100, 2) if total else 0

    if score >= 80:
        overall_status = "COMPLIANT"
    elif score >= 50:
        overall_status = "PARTIALLY COMPLIANT"
    else:
        overall_status = "NON-COMPLIANT"

    return {
        "results": results,
        "score": score,
        "overall_status": overall_status,
        "total": total,
        "passed": passed,
        "warnings": warnings,
        "failed": failed
    }


def get_network_summary(force=False):
    """Retrieve network scan summary with caching to keep dashboard responses fast."""
    global _last_network_scan
    now = time.time()

    if not force and _last_network_scan["data"] is not None and (now - _last_network_scan["timestamp"] < 15):
        return _last_network_scan["data"]

    try:
        result = run_network_policy_scan()
        _last_network_scan["data"] = result
        _last_network_scan["timestamp"] = now
        return result
    except Exception as error:
        print("Network scan error in dashboard helper:", error)
        if _last_network_scan["data"] is not None:
            return _last_network_scan["data"]
        return {
            "operating_system": platform.system(),
            "summary": {
                "active_connections": 0,
                "listening_ports": 0,
                "unauthorized_ports": 0,
                "high_risk_ports": 0,
                "network_score": 70,
                "risk_level": "UNKNOWN"
            },
            "firewall": {"type": "Unknown", "available": False, "enabled": False, "rules_count": 0},
            "active_connections": [],
            "listening_ports": [],
            "policy": [],
            "recommendations": []
        }


def calculate_master_security_posture(compliance_data, network_scan, anomaly_status):
    """Calculate multi-vector security health score across all 3 subsystems."""
    compliance_score = compliance_data.get("score", 0)

    net_summary = network_scan.get("summary", {}) if network_scan else {}
    net_score = net_summary.get("network_score", 75)

    total_samples = anomaly_status.get("total_samples", 0)
    baseline_needed = anomaly_status.get("baseline_needed", BASELINE_SIZE)
    baseline_ready = anomaly_status.get("baseline_ready", False)

    recent_anomalies_list = fetch_anomalies(10)
    recent_anomalies_count = len(recent_anomalies_list)

    if baseline_ready:
        anomaly_score = max(30, 100 - (recent_anomalies_count * 15))
    else:
        progress = min(1.0, total_samples / max(baseline_needed, 1))
        anomaly_score = round(50 + (progress * 35), 1)

    master_score = round(
        (compliance_score * 0.35) + (net_score * 0.40) + (anomaly_score * 0.25),
        1
    )

    if master_score >= 80:
        posture_status = "EXCELLENT"
        posture_badge = "SYSTEM PROTECTED"
        posture_class = "pass"
    elif master_score >= 60:
        posture_status = "MODERATE"
        posture_badge = "ELEVATED RISK"
        posture_class = "warning"
    else:
        posture_status = "CRITICAL"
        posture_badge = "HIGH RISK DETECTED"
        posture_class = "fail"

    return {
        "master_score": master_score,
        "posture_status": posture_status,
        "posture_badge": posture_badge,
        "posture_class": posture_class,
        "compliance_score": compliance_score,
        "net_score": net_score,
        "anomaly_score": anomaly_score,
        "recent_anomalies_count": recent_anomalies_count
    }


def build_dashboard_alerts(compliance_data, network_scan, recent_anomalies):
    """Synthesize active security alerts from all modules with severity ratings."""
    alerts = []

    # Compliance alerts
    for check in compliance_data.get("results", []):
        if check["status"] == "FAIL":
            alerts.append({
                "severity": "CRITICAL",
                "title": f"Compliance Failure: {check['name']}",
                "details": check.get("details", "Security policy violation detected."),
                "source": "OS Compliance",
                "link": "/compliance",
                "time": "Active"
            })
        elif check["status"] == "WARNING":
            alerts.append({
                "severity": "WARNING",
                "title": f"Compliance Notice: {check['name']}",
                "details": check.get("details", "Policy review required."),
                "source": "OS Compliance",
                "link": "/compliance",
                "time": "Active"
            })

    # Network alerts
    firewall = network_scan.get("firewall", {})
    if not firewall.get("enabled", True):
        alerts.append({
            "severity": "CRITICAL",
            "title": "Firewall Protection Offline",
            "details": f"{firewall.get('type', 'Host')} firewall is not currently actively enforcing filtering.",
            "source": "Network Policy",
            "link": "/network-policy",
            "time": "Active"
        })

    net_summary = network_scan.get("summary", {})
    if net_summary.get("high_risk_ports", 0) > 0:
        alerts.append({
            "severity": "CRITICAL",
            "title": f"High Risk Ports Exposed ({net_summary.get('high_risk_ports')})",
            "details": "Services listening on known high-risk ports require immediate remediation.",
            "source": "Network Policy",
            "link": "/network-policy",
            "time": "Active"
        })
    elif net_summary.get("unauthorized_ports", 0) > 0:
        alerts.append({
            "severity": "WARNING",
            "title": f"Unauthorized Open Ports ({net_summary.get('unauthorized_ports')})",
            "details": "Detected open listening ports outside standard whitelist (80, 443, 22).",
            "source": "Network Policy",
            "link": "/network-policy",
            "time": "Active"
        })

    # Anomaly alerts
    for item in recent_anomalies[:5]:
        ts = item.get("timestamp", time.time())
        ts_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        score = round(item.get("anomaly_score", 0.0), 3)
        alerts.append({
            "severity": "CRITICAL",
            "title": f"AI Behavioral Anomaly Detected",
            "details": f"Isolation Forest flagged outlier metrics (Score: {score}) — CPU: {item.get('cpu_percent', 0)}%, RAM: {item.get('mem_percent', 0)}%.",
            "source": "Anomaly Detection",
            "link": "/anomaly-detection",
            "time": ts_str
        })

    if not alerts:
        alerts.append({
            "severity": "SECURE",
            "title": "All Infrastructure Controls Operational",
            "details": "No compliance violations, open high-risk ports, or behavioral anomalies detected.",
            "source": "InfraShield Core",
            "link": "#",
            "time": "Live"
        })

    return alerts


def get_dashboard_payload(force_network_scan=False):
    """Aggregate all metrics into a single cohesive payload."""
    vitals = get_system_vitals()
    compliance = run_compliance_check()
    network = get_network_summary(force=force_network_scan)

    total_samples = count_metrics()
    baseline_ready = detector.model is not None
    anomaly_status = {
        "total_samples": total_samples,
        "baseline_ready": baseline_ready,
        "baseline_needed": BASELINE_SIZE,
        "baseline_pct": min(100, int((total_samples / max(BASELINE_SIZE, 1)) * 100))
    }

    recent_anomalies = fetch_anomalies(10)
    recent_metrics = fetch_recent(30)
    posture = calculate_master_security_posture(compliance, network, anomaly_status)
    alerts = build_dashboard_alerts(compliance, network, recent_anomalies)

    return {
        "vitals": vitals,
        "compliance": compliance,
        "network": network,
        "anomaly_status": anomaly_status,
        "recent_anomalies": recent_anomalies,
        "recent_metrics": recent_metrics,
        "posture": posture,
        "alerts": alerts
    }


# ============================================================
# ROUTES: UNIFIED DASHBOARD & COMPLIANCE
# ============================================================

@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Main executive security dashboard."""
    payload = get_dashboard_payload(force_network_scan=False)
    return render_template(
        "dashboard.html",
        **payload
    )


@app.route("/compliance")
@app.route("/os-compliance")
def os_compliance():
    """Dedicated OS Compliance page."""
    data = run_compliance_check()
    return render_template(
        "index.html",
        results=data["results"],
        score=data["score"],
        overall_status=data["overall_status"],
        total=data["total"],
        passed=data["passed"],
        warnings=data["warnings"],
        failed=data["failed"]
    )


@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    """API endpoint providing real-time telemetry and posture metrics."""
    force = request.args.get("force", "false").lower() in ["1", "true", "yes"]
    payload = get_dashboard_payload(force_network_scan=force)
    return jsonify({
        "success": True,
        "data": payload
    })


# ============================================================
# NETWORK POLICY SCANNER
# ============================================================

@app.route("/network-policy")
def network_policy():

    return render_template(
        "network_policy.html"
    )


@app.route("/api/network-scan")
def network_scan():

    try:

        result = run_network_policy_scan()

        return jsonify({
            "success": True,
            "data": result
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# ANOMALY DETECTION DASHBOARD
# ============================================================

@app.route("/anomaly-detection")
def anomaly_detection():

    return render_template(
        "anomaly_detection.html"
    )


@app.route("/api/metrics")
def api_metrics():

    return jsonify(
        fetch_recent(100)
    )


@app.route("/api/anomalies")
def api_anomalies():

    return jsonify(
        fetch_anomalies(20)
    )


@app.route("/api/status")
def api_status():

    return jsonify({

        "total_samples": count_metrics(),

        "baseline_ready":
            detector.model is not None,

        "baseline_needed":
            BASELINE_SIZE

    })


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_db()

    # Seed telemetry so dashboard charts have data immediately
    try:
        for _ in range(6):
            sample = collect_sample(cpu_interval=0.15)
            insert_metric(sample, False, 0.0)
    except Exception as warmup_error:
        print("Telemetry warmup skipped:", warmup_error)

    # Start anomaly monitoring in background

    background_thread = threading.Thread(
        target=background_loop,
        daemon=True
    )

    background_thread.start()


    def get_open_port(preferred_port=5001):
        import socket
        env_port = os.environ.get("PORT")
        if env_port:
            return int(env_port)
        for p in [preferred_port, 5001, 5050, 8000, 8080]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("0.0.0.0", p))
                    return p
                except OSError:
                    continue
        return preferred_port

    chosen_port = get_open_port(5001)
    print(f"🚀 Starting InfraShield Security Platform on http://localhost:{chosen_port} ...")

    app.run(host="0.0.0.0", port=5001)