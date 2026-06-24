import random
import re
import subprocess
from datetime import datetime

class DetectionEngine:
    def __init__(self, db):
        self.db = db
        self.rules = self.load_detection_rules()
        self.journal_process = None

    def load_detection_rules(self):
        return {
            'brute_force': {'threshold': 5, 'time_window': 300, 'severity': 'CRITICAL'},
            'sql_injection': {'patterns': [r"UNION.*SELECT", r"OR.*1=1", r"'; DROP TABLE"], 'severity': 'HIGH'},
            'privilege_escalation': {'keywords': ['sudo', 'su root', 'chmod 777'], 'severity': 'HIGH'}
        }

    def analyze_log(self, log):
        alerts = []
        if 'failed' in log['description'].lower():
            recent_fails = self.db.count_failed_logins(log['source_ip'], 300)
            if recent_fails >= 5:
                alerts.append({
                    'alert_id': f"ALT-BF-{log['event_id']}",
                    'event_id': log['event_id'],
                    'severity': 'CRITICAL',
                    'threat_type': 'Brute Force Attack',
                    'description': f"🔴 BRUTE FORCE: {log['source_ip']} ({recent_fails} attempts)",
                    'timestamp': datetime.now().isoformat()
                })
        if any(kw in log['description'].lower() for kw in ['sudo', 'root', 'chmod 777']):
            alerts.append({
                'alert_id': f"ALT-PE-{log['event_id']}",
                'event_id': log['event_id'],
                'severity': 'HIGH',
                'threat_type': 'Privilege Escalation',
                'description': f"🟠 PRIVILEGE ESCALATION: {log['source_ip']}",
                'timestamp': datetime.now().isoformat()
            })
        return alerts

    def start_realtime_monitoring(self):
        print("🔥 Starting REAL log monitoring (systemd journal)...")
        try:
            self.journal_process = subprocess.Popen(
                ['sudo', 'journalctl', '-f', '-n', '0'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            print("✅ Monitoring systemd journal - REAL EVENTS ONLY")
        except Exception as e:
            print(f"❌ Cannot monitor journal: {str(e)}")

    def read_realtime_logs(self):
        real_logs = []
        if self.journal_process and self.journal_process.poll() is None:
            line = self.journal_process.stdout.readline()
            if line.strip():
                log = self.parse_real_log(line.strip())
                if log:
                    real_logs.append(log)
                    print(f"⚡ REAL EVENT: {log['description'][:60]}")
        return real_logs

    def parse_real_log(self, line):
        try:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            source_ip = ip_match.group(1) if ip_match else '127.0.0.1'

            if 'Failed password' in line or 'authentication failure' in line:
                return {'event_id': f"EVT-REAL-{random.randint(10000, 99999)}", 'timestamp': datetime.now().isoformat(), 'source_ip': source_ip, 'severity': 'HIGH', 'event_type': 'Authentication', 'description': f'REAL: Failed login from {source_ip}'}
            elif 'sudo' in line.lower():
                return {'event_id': f"EVT-REAL-{random.randint(10000, 99999)}", 'timestamp': datetime.now().isoformat(), 'source_ip': source_ip, 'severity': 'HIGH', 'event_type': 'Privilege Escalation', 'description': f'REAL: Sudo command from {source_ip}'}
            elif any(word in line.lower() for word in ['session', 'login']):
                return {'event_id': f"EVT-REAL-{random.randint(10000, 99999)}", 'timestamp': datetime.now().isoformat(), 'source_ip': source_ip, 'severity': 'LOW', 'event_type': 'System Event', 'description': f'REAL: {line[:100]}'}
        except:
            pass
        return None

    def parse_uploaded_logs(self, content, filename):
        logs = []
        for i, line in enumerate(content.split('\n')[:100]):
            if line.strip():
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                logs.append({'event_id': f"EVT-UP-{i}", 'timestamp': datetime.now().isoformat(), 'source_ip': ip_match.group(1) if ip_match else '0.0.0.0', 'severity': 'HIGH' if 'failed' in line.lower() else 'LOW', 'event_type': 'Uploaded', 'description': line[:200]})
        return logs

    def stop_monitoring(self):
        if self.journal_process:
            self.journal_process.terminate()
