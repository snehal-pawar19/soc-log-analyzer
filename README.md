# 🔐 SOC Log Analyzer — Mini Home Lab

A Python-based Security Operations Center (SOC) simulation tool 
that analyzes Windows Security Event logs, detects threats, 
triages alerts by severity, and auto-generates incident reports.

Built to simulate real-world SOC analyst workflows.

---

## 🎯 Features

- ✅ Brute Force Attack Detection (Event ID 4625)
- ✅ Off-Hours Login Detection
- ✅ External IP Access Alerts
- ✅ Privileged Credential Use (Event ID 4648)
- ✅ Automated Incident Report Generation (JSON)
- ✅ PowerShell Endpoint Investigation Script

---

## 🛠️ Tech Stack

- Python 3.x
- Pandas
- PowerShell
- Windows Event Log Analysis

---

## 📁 Project Structure

soc-log-analyzer/
├── logs/               # Sample security log data
├── analyzer/           # Python detection engine
├── powershell/         # Endpoint investigation scripts
├── reports/            # Auto-generated incident reports
└── docs/               # Written incident reports

---

## 🚀 How to Run

# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the analyzer
python analyzer/log_analyzer.py

# 3. View generated report
cat reports/incident_report.json

---

## 🔍 Detection Rules

| Rule | Event ID | Severity |
|------|----------|----------|
| Brute Force Attack | 4625 | CRITICAL |
| Off-Hours Login | 4624 | HIGH |
| External IP Access | 4624 | HIGH |
| Privileged Credential Use | 4648 | MEDIUM |

---

## 📄 Sample Incident Report

See `/docs/incident_report.md` for a full written 
incident report generated from detected alerts.

---

## 👤 Author

Snehal Pawar — Cybersecurity Enthusiast
LinkedIn: https://www.linkedin.com/in/snehal-pawar-0884b1278
