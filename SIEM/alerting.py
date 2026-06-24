from datetime import datetime

class AlertManager:
    def __init__(self, db):
        self.db = db
        self.alert_channels = ['console']

    def send_alert(self, alert):
        """Send alert to configured channels"""
        self.send_console_alert(alert)

    def send_console_alert(self, alert):
        """Print alert to console"""
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        emoji = severity_emoji.get(alert['severity'], '⚪')
        print(f"\n{emoji} ALERT [{alert['severity']}]: {alert['threat_type']}")
        print(f"   Event: {alert['event_id']}")
        print(f"   {alert['description']}")
        print(f"   Time: {alert['timestamp']}")
