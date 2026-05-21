import pandas as pd
from datetime import datetime
import json
import os

# Load logs with correct path
df = pd.read_csv('logs/security_logs.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])

alerts = []

# Rule 1: Brute Force Detection (3+ failed logins from same IP)
failed_logins = df[df['event_id'] == 4625]
brute_force = failed_logins.groupby('source_ip').size()
for ip, count in brute_force.items():
    if count >= 3:
        alerts.append({
            "severity": "CRITICAL",
            "type": "Brute Force Attack",
            "source_ip": ip,
            "detail": f"{count} failed login attempts detected",
            "event_id": "4625",
            "action": "Block IP immediately, notify L2 analyst"
        })

# Rule 2: Off-Hours Login (between 11PM - 6AM)
for _, row in df[df['status'] == 'SUCCESS'].iterrows():
    hour = row['timestamp'].hour
    if hour >= 23 or hour <= 6:
        alerts.append({
            "severity": "HIGH",
            "type": "Off-Hours Login",
            "source_ip": row['source_ip'],
            "detail": f"User {row['username']} logged in at {row['timestamp']}",
            "event_id": "4624",
            "action": "Verify with user, check geolocation"
        })

# Rule 3: External IP Login (not internal 10.x or 192.168.x)
for _, row in df[df['status'] == 'SUCCESS'].iterrows():
    ip = row['source_ip']
    if not (ip.startswith('10.') or ip.startswith('192.168.')):
        alerts.append({
            "severity": "HIGH",
            "type": "External IP Access",
            "source_ip": ip,
            "detail": f"Login from external IP by {row['username']}",
            "event_id": str(row['event_id']),
            "action": "Verify legitimacy, check threat intel"
        })

# Rule 4: Privileged Login (Event ID 4648)
priv_logins = df[df['event_id'] == 4648]
for _, row in priv_logins.iterrows():
    alerts.append({
        "severity": "MEDIUM",
        "type": "Privileged Credential Use",
        "source_ip": row['source_ip'],
        "detail": f"Explicit credential use by {row['username']}",
        "event_id": "4648",
        "action": "Verify if authorized, check for lateral movement"
    })

# Generate Incident Report
print("\n" + "="*60)
print("       SOC INCIDENT REPORT")
print("="*60)
print(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Analyst   : Snehal Pawar")
print(f"Logs      : {len(df)} total entries analyzed")
print(f"Alerts    : {len(alerts)} total")
print(f"Critical  : {sum(1 for a in alerts if a['severity']=='CRITICAL')}")
print(f"High      : {sum(1 for a in alerts if a['severity']=='HIGH')}")
print(f"Medium    : {sum(1 for a in alerts if a['severity']=='MEDIUM')}")
print("="*60)

for i, alert in enumerate(alerts, 1):
    print(f"\n[{alert['severity']}] Alert #{i}: {alert['type']}")
    print(f"  Source IP : {alert['source_ip']}")
    print(f"  Event ID  : {alert['event_id']}")
    print(f"  Detail    : {alert['detail']}")
    print(f"  Action    : {alert['action']}")

# Create reports folder if it doesn't exist
os.makedirs('reports', exist_ok=True)

# Save report to JSON
with open('reports/incident_report.json', 'w') as f:
    json.dump(alerts, f, indent=2, default=str)

print("\n" + "="*60)
print("✅ Full report saved to reports/incident_report.json")
print("="*60)