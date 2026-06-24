# SIEM Configuration

# Database
DATABASE_NAME = 'siem.db'

# API
API_HOST = '0.0.0.0'
API_PORT = 5000
DEBUG_MODE = True

# Detection Rules
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 300  # seconds

# Alert Configuration
ALERT_CHANNELS = ['console']

# Log Monitoring
LOG_FILES = ['/var/log/auth.log']
LOG_CHECK_INTERVAL = 0.5  # seconds
