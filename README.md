# Cypher — Local Log Anomaly Detector (Offline, Open Source)

Cypher is a **local**, **offline-friendly** anomaly detector for Linux logs. It parses common logs,
extracts features, learns a baseline with **unsupervised ML** (IsolationForest), and highlights anomalies.
No cloud, no telemetry — everything stays on your machine.

## Key Features
- Parsers for `auth.log`/`secure`, `syslog`, and Apache/Nginx `access.log` (Common/Combined)
- Lightweight feature extraction (timestamps, IPs, status codes, auth outcomes, etc.)
- Unsupervised anomaly detection with scikit-learn IsolationForest
- Rule-based detectors (failed logins bursts, invalid users, sudo abuse, 4xx/5xx spikes)
- Reports (Markdown/HTML) with top anomalies + explainable features
- Reproducible: same CLI works offline; model persisted locally (.joblib)

## Quick Start

### 1) Install deps
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Configure
```bash
cp cypher.example.toml cypher.toml
# edit paths and options
```

### 3) Parse logs -> dataset
```bash
python -m cypher.cli parse --file /var/log/auth.log --out data/auth.parquet
python -m cypher.cli parse --file /var/log/syslog --out data/syslog.parquet
python -m cypher.cli parse --file /var/log/apache2/access.log --out data/apache.parquet
```

### 4) Train unsupervised model on "normal" period
```bash
python -m cypher.cli train --data data/auth.parquet data/syslog.parquet data/apache.parquet --model models/cypher_iforest.joblib
```

### 5) Score new logs (or same logs) and create a report
```bash
python -m cypher.cli score --data data/auth.parquet data/syslog.parquet data/apache.parquet --model models/cypher_iforest.joblib --out data/scores.parquet
python -m cypher.cli report --scores data/scores.parquet --format markdown --out reports/cypher_report.md
# or HTML
python -m cypher.cli report --scores data/scores.parquet --format html --out reports/cypher_report.html
```

## Ethics & Scope
Use Cypher only on systems you own or administer, or where you have explicit authorization.
This project is **defensive**: it does not include exploit tooling or offensive guidance.

## Modules Overview
- `cypher/parsers/` — line parsers for auth/syslog/apache
- `cypher/detectors/` — ML (IsolationForest) + rule-based heuristics
- `cypher/utils/` — feature extraction, io helpers, time utils
- `cypher/reports/` — Markdown/HTML report generation
- `cypher/cli.py` — CLI
- `cypher/config.py` — TOML config loader

## Notes
- Train on a period you consider "clean/normal" to get a good baseline.
- You can merge multiple parsed datasets for a holistic model.
- IsolationForest is unsupervised; threshold tuning is important (see config).

MIT Licensed. PRs welcome.
