# Infrashield — Anomaly Detection Module (Feature 3)

Ye Infrashield project structure ko follow karta hai:

```
Infrashield/
│
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── anomaly_detector/
│   ├── __init__.py
│   ├── db.py            # SQLite storage layer
│   └── detector.py      # Isolation Forest model wrapper
│
├── templates/
│   └── anomaly_detection.html
│
└── static/
    ├── css/
    │   └── anomaly_detection.css
    └── js/
        └── anomaly_detection.js
```

Ye exact wahi pattern hai jo aapke `network_scanner/` (Feature 2) module me
tha — bas naam is feature ke hisaab se `anomaly_detector` rakha hai, taaki
jab aap Feature 1 aur 2 ko is repo me add karo, sab modules ek jaisi
structure follow karein (`compliance_engine/`, `network_scanner/`,
`anomaly_detector/` — sab sibling folders ho sakte hain isi Infrashield/
root ke andar).

## Kaise kaam karta hai

Same as pehle: `psutil` se metrics collect → Isolation Forest baseline
train (60 samples ke baad) → real-time anomaly detection → dashboard par
live charts + anomaly log.

## Local run (bina Docker ke)

```bash
cd Infrashield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Browser me: **http://localhost:5000**

## Docker se run

```bash
cd Infrashield
docker-compose up --build
```

**Zaroori note on Docker:** Agar aap sirf `docker-compose up` normal tarike
se chalate ho, to `psutil` sirf **container ke andar ka** resource usage
dekhega — host machine ka nahi. Isliye `docker-compose.yml` me
`pid: "host"` aur `network_mode: "host"` set kiya hai, jisse container host
ke process aur network namespace share karta hai aur real host metrics
dikhte hain. Ye production-safe setting nahi hai for all environments
(kuch cloud platforms is mode ko allow nahi karte) — agar aapko sirf
container ka apna monitoring test karna hai to inhe hata sakte ho.

Data (`metrics.db`, `anomalies.log`) `data/` folder me save hota hai, jo
Docker volume (`anomaly_data`) se persist hota hai — container restart hone
par purana data khatam nahi hoga.

## Environment variables

| Variable | Default | Kaam |
|---|---|---|
| `DATA_DIR` | `data` | Jahan `metrics.db` aur `anomalies.log` store honge |

## Tuning parameters (`app.py` ke top par)

- `BASELINE_SIZE` — kitne samples baad pehli training ho (default 60)
- `RETRAIN_INTERVAL` — kitne naye samples baad retrain ho (default 100)
- `COLLECT_INTERVAL` — har kitne second me sample liya jaye (default 5)

`anomaly_detector/detector.py` me `contamination` parameter (default 0.05)
adjust karke sensitivity control kar sakte ho.
