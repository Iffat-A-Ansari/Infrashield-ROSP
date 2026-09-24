"""
detector.py
------------
Isolation Forest wrapper. Ye "normal" system behaviour ka baseline seekhta
hai aur naye samples ko normal/anomaly classify karta hai.

Isolation Forest kaam kaise karta hai (short me):
Ye random decision trees banata hai jo data ko baar baar random split karte
hain. Anomaly points (jo baaki data se bahut alag hote hain) bahut jaldi
isolate ho jaate hain -- yaani unko separate karne ke liye kam splits
lagte hain. Isliye "isolation path length" jitna chhota, anomaly hone ka
chance utna zyada.
"""

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False
    np = None
    IsolationForest = None

# Features jo model training/prediction ke liye use honge
FEATURES = [
    "cpu_percent",
    "mem_percent",
    "disk_read_rate",
    "disk_write_rate",
    "net_sent_rate",
    "net_recv_rate",
    "process_count",
]


class AnomalyDetector:
    def __init__(self, contamination=0.05):
        """
        contamination = expected fraction of anomalies in training data.
        0.05 matlab hum assume kar rahe hain ki baseline data me ~5% samples
        thode unusual ho sakte hain (bilkul zero rakhna unrealistic hota hai).
        """
        self.model = None
        self.contamination = contamination
        self.mean = None
        self.std = None

    def _to_matrix(self, samples):
        if SKLEARN_AVAILABLE and np is not None:
            return np.array([[float(s.get(f, 0.0)) for f in FEATURES] for s in samples], dtype=float)
        return [[float(s.get(f, 0.0)) for f in FEATURES] for s in samples]

    def train(self, samples):
        if not samples:
            return

        if SKLEARN_AVAILABLE and np is not None:
            X = self._to_matrix(samples)
            self.mean = X.mean(axis=0)
            self.std = X.std(axis=0)
            self.std[self.std == 0] = 1.0  # divide-by-zero avoid karne ke liye

            X_scaled = (X - self.mean) / self.std

            self.model = IsolationForest(
                n_estimators=150,
                contamination=self.contamination,
                random_state=42,
            )
            self.model.fit(X_scaled)
        else:
            n = len(samples)
            self.mean = [sum(float(s.get(f, 0.0)) for s in samples) / n for f in FEATURES]
            self.std = []
            for i, f in enumerate(FEATURES):
                variance = sum((float(s.get(f, 0.0)) - self.mean[i]) ** 2 for s in samples) / max(n, 1)
                std_val = variance ** 0.5
                self.std.append(std_val if std_val > 0.001 else 1.0)
            self.model = "pure_python_baseline"

    def predict(self, sample):
        """Returns (is_anomaly: bool, score: float)."""
        if self.model is None or self.mean is None:
            return False, 0.0

        if SKLEARN_AVAILABLE and np is not None and self.model != "pure_python_baseline":
            x = np.array([[float(sample.get(f, 0.0)) for f in FEATURES]], dtype=float)
            x_scaled = (x - self.mean) / self.std

            pred = self.model.predict(x_scaled)[0]          # -1 = anomaly, 1 = normal
            score = self.model.decision_function(x_scaled)[0]  # kam score = zyada anomalous

            return bool(pred == -1), float(score)
        else:
            z_scores = [abs((float(sample.get(f, 0.0)) - self.mean[i]) / self.std[i]) for i, f in enumerate(FEATURES)]
            max_z = max(z_scores) if z_scores else 0.0
            avg_z = sum(z_scores) / len(z_scores) if z_scores else 0.0
            is_anomaly = max_z > 3.0 or avg_z > 2.0
            score = round(0.5 - (avg_z / 10.0), 3)
            return bool(is_anomaly), float(score)
