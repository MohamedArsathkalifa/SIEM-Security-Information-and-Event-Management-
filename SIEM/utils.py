import hashlib
from datetime import datetime

def hash_string(text):
    """Generate SHA256 hash"""
    return hashlib.sha256(text.encode()).hexdigest()

def format_timestamp(dt=None):
    """Format timestamp in ISO format"""
    if dt is None:
        dt = datetime.now()
    return dt.isoformat()

def calculate_severity_score(severity):
    """Convert severity to numeric score"""
    scores = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    return scores.get(severity.upper(), 0)

def validate_ip_address(ip):
    """Validate IP address format"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False
