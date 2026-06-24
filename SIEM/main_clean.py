from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import threading
import time
from datetime import datetime
import json  # NEW - ADDITION ONLY
import csv  # NEW - ADDITION ONLY
from io import StringIO  # NEW - ADDITION ONLY
from detection_engine import DetectionEngine
from database import Database
from alerting import AlertManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key-change-in-production'

CORS(app)
jwt = JWTManager(app)

db = Database()
detection_engine = DetectionEngine(db)
alert_manager = AlertManager(db)


# ── Privilege escalation keywords to watch ───────────────
_PRIV_ESC_PATTERNS = [
    ('sudo',             'Sudo command executed',          'HIGH'),
    ('su root',          'Switch to root attempted',       'CRITICAL'),
    ('su -',             'Root login attempted',           'CRITICAL'),
    ('useradd',          'New user created',               'CRITICAL'),
    ('usermod',          'User modified',                  'HIGH'),
    ('passwd',           'Password changed',               'HIGH'),
    ('chmod 777',        'Dangerous chmod 777',            'HIGH'),
    ('chmod +s',         'SUID bit set',                   'CRITICAL'),
    ('chown root',       'Ownership changed to root',      'HIGH'),
    ('visudo',           'Sudoers file modified',          'CRITICAL'),
    ('pkexec',           'PolicyKit escalation',           'CRITICAL'),
    ('id; whoami',       'Recon command',                  'HIGH'),
    ('python.*pty',      'PTY shell spawn',                'CRITICAL'),
    ('/etc/passwd',      'passwd file accessed',           'HIGH'),
    ('/etc/shadow',      'shadow file accessed',           'CRITICAL'),
    ('crontab -e',       'Crontab modified',               'HIGH'),
    ('systemctl enable', 'Service enabled (persistence)',  'MEDIUM'),
]

def _parse_priv_esc(line):
    """Return alert dict if line matches privilege escalation pattern."""
    import re as _re
    low = line.lower()
    for pattern, label, severity in _PRIV_ESC_PATTERNS:
        if pattern in low:
            ip_match = _re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else 'localhost'
            return {
                'timestamp':   datetime.utcnow().isoformat(),
                'severity':    severity,
                'source_ip':   ip,
                'event_type':  'Privilege Escalation',
                'description': f'[{label}] {line.strip()[:200]}',
            }
    return None

def _priv_esc_watcher():
    """Stream journalctl -f and instantly detect privilege escalation."""
    import subprocess as _sp
    print('[PrivEsc] Watcher started — monitoring sudo/su/chmod in real time')
    while True:
        try:
            proc = _sp.Popen(
                ['journalctl', '-f', '-n', '0', '--no-pager', '--quiet'],
                stdout=_sp.PIPE, stderr=_sp.DEVNULL, text=True, bufsize=1
            )
            for line in proc.stdout:
                if not line.strip():
                    continue
                alert = _parse_priv_esc(line)
                if alert:
                    log_entry = {**alert, 'event_id': f'PRIV-{int(datetime.utcnow().timestamp())}'}
                    db.insert_log(log_entry)
                    db.insert_alert(alert)
                    print(f"[PrivEsc] [{alert['severity']}] {alert['description'][:80]}")
                    threading.Thread(target=_instant_email, args=(alert,), daemon=True).start()
        except FileNotFoundError:
            # journalctl not available — fallback: tail auth.log
            try:
                import subprocess as _sp2
                proc2 = _sp2.Popen(
                    ['tail', '-f', '/var/log/auth.log'],
                    stdout=_sp2.PIPE, stderr=_sp2.DEVNULL, text=True, bufsize=1
                )
                for line in proc2.stdout:
                    alert = _parse_priv_esc(line)
                    if alert:
                        db.insert_log({**alert, 'event_id': f'PRIV-{int(datetime.utcnow().timestamp())}'})
                        db.insert_alert(alert)
                        threading.Thread(target=_instant_email, args=(alert,), daemon=True).start()
            except Exception:
                time.sleep(30)
        except Exception as e:
            print(f'[PrivEsc] error: {e}')
            time.sleep(5)

def realtime_log_monitor():
    print("🔥 Starting REAL log monitoring...")
    detection_engine.start_realtime_monitoring()
    while True:
        try:
            real_logs = detection_engine.read_realtime_logs()
            if real_logs:
                for log in real_logs:
                    db.insert_log(log)
                    alerts = detection_engine.analyze_log(log)
                    for alert in alerts:
                        db.insert_alert(alert)
                        if alert.get('severity') in ('HIGH', 'CRITICAL'):
                            threading.Thread(target=_instant_email, args=(alert,), daemon=True).start()
                        alert_manager.send_alert(alert)
            time.sleep(0.5)
        except KeyboardInterrupt:
            detection_engine.stop_monitoring()
            break
        except Exception as e:
            print(f"Error: {str(e)}")
            time.sleep(1)


# ========== AUTH ROUTES ==========

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        user = db.verify_user(username, password)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token, 'username': username}), 200
    except Exception as e:
        return jsonify({'error': 'Authentication failed'}), 500


@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email    = data.get('email', '').strip()
        if not username or not password or not email:
            return jsonify({'error': 'All fields required'}), 400
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        if len(password) < 4:
            return jsonify({'error': 'Password must be at least 4 characters'}), 400
        ok, err = db.create_user(username, password, email)
        if not ok:
            return jsonify({'error': err}), 409
        return jsonify({'message': f'User "{username}" registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        username     = data.get('username', '').strip()
        email        = data.get('email', '').strip()
        new_password = data.get('new_password', '')
        if not username or not email or not new_password:
            return jsonify({'error': 'username, email and new_password required'}), 400
        user = db.get_user(username)
        if not user or user['email'].lower() != email.lower():
            return jsonify({'error': 'Username or email not found'}), 404
        if len(new_password) < 4:
            return jsonify({'error': 'Password must be at least 4 characters'}), 400
        db.update_password(username, new_password)
        return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': 'Password reset failed'}), 500


@app.route('/api/users', methods=['GET'])
@jwt_required()
def list_users():
    if get_jwt_identity() != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    return jsonify(db.get_all_users()), 200


# ========== ORIGINAL ROUTES ==========

@app.route('/api/summary', methods=['GET'])
def get_summary():
    try:
        return jsonify(db.get_statistics())
    except:
        return jsonify({'total_logs': 0, 'total_alerts': 0, 'critical_alerts': 0}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        page      = int(request.args.get('page', 1))
        size      = int(request.args.get('size', 20))
        severity  = request.args.get('severity', None)
        source_ip = request.args.get('source_ip', None)
        return jsonify(db.get_logs(page, size, severity, source_ip))
    except:
        return jsonify({'logs': [], 'page': 1, 'size': 20, 'total': 0}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        return jsonify(db.get_alerts())
    except:
        return jsonify([]), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    try:
        return jsonify(db.get_threat_intelligence())
    except:
        return jsonify([]), 500

@app.route('/api/event/<event_id>', methods=['GET'])
def get_event_details(event_id):
    try:
        return jsonify({'event': db.get_event_by_id(event_id), 'related_events': db.get_related_events(event_id)})
    except:
        return jsonify({'event': None, 'related_events': []}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        file = request.files['file']
        content = file.read().decode('utf-8')
        logs = detection_engine.parse_uploaded_logs(content, file.filename)
        for log in logs:
            db.insert_log(log)
            alerts = detection_engine.analyze_log(log)
            for alert in alerts:
                db.insert_alert(alert)
                if alert.get('severity') in ('HIGH', 'CRITICAL'):
                    threading.Thread(target=_instant_email, args=(alert,), daemon=True).start()
        return jsonify({'message': f'Processed {len(logs)} logs', 'file_name': file.filename, 'logs_count': len(logs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/distribution', methods=['GET'])
def get_distribution():
    return jsonify(db.get_event_distribution_last_hour())

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'SIEM'}), 200


# ========== REAL-TIME WINDOWS LOGS ==========
import platform
import subprocess
import re as _re

def read_windows_logs_real(log_type='Security', limit=50):
    """Read real Windows Event Logs using wevtutil (Windows only)."""
    logs = []
    try:
        cmd = ['wevtutil', 'qe', log_type,
               f'/count:{limit}', '/rd:true', '/f:text']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split('\n')

        entry = {}
        for line in lines:
            line = line.strip()
            if line.startswith('Event['):
                if entry:
                    logs.append(entry)
                entry = {'log_type': log_type}
            elif line.startswith('Date:'):
                entry['timestamp'] = line.replace('Date:', '').strip()
            elif line.startswith('Event ID:'):
                entry['event_id'] = line.replace('Event ID:', '').strip()
            elif line.startswith('Level:'):
                lvl = line.replace('Level:', '').strip()
                entry['severity'] = 'CRITICAL' if 'Critical' in lvl else 'HIGH' if 'Error' in lvl else 'MEDIUM' if 'Warning' in lvl else 'LOW'
            elif line.startswith('Source:'):
                entry['source'] = line.replace('Source:', '').strip()
            elif line.startswith('Description:'):
                entry['description'] = line.replace('Description:', '').strip()[:200]

        if entry and 'event_id' in entry:
            logs.append(entry)

    except Exception as e:
        print(f"Windows log error: {e}")
    return logs


def read_linux_auth_logs(limit=50):
    """Read real Linux system logs — tries multiple sources in order."""
    import json as _json
    logs = []

    def _parse_line(line, source_name, log_type='Security'):
        line = line.strip()
        if not line:
            return None
        ip_match = _re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        low = line.lower()
        if any(w in low for w in ['fail', 'invalid', 'error', 'denied', 'refused']):
            sev = 'HIGH'
        elif any(w in low for w in ['warn', 'crit', 'alert']):
            sev = 'MEDIUM'
        else:
            sev = 'LOW'
        return {
            'timestamp':   datetime.utcnow().isoformat(),
            'event_id':    'SYS',
            'log_type':    log_type,
            'source':      source_name,
            'host':        'localhost',
            'severity':    sev,
            'description': line[:200]
        }

    # 1. Try journalctl (any logs, no unit filter — broader coverage)
    try:
        result = subprocess.run(
            ['journalctl', '-n', str(limit), '--output=json', '--no-pager', '--quiet'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    j = _json.loads(line)
                    msg = j.get('MESSAGE', '')
                    if not msg:
                        continue
                    ts = j.get('__REALTIME_TIMESTAMP', '')
                    if ts:
                        ts = datetime.fromtimestamp(int(ts) / 1e6).isoformat()
                    low = msg.lower()
                    sev = 'CRITICAL' if 'crit' in low else 'HIGH' if any(w in low for w in ['fail','error','invalid','denied']) else 'MEDIUM' if 'warn' in low else 'LOW'
                    logs.append({
                        'timestamp':   ts or datetime.utcnow().isoformat(),
                        'event_id':    j.get('_PID', 'N/A'),
                        'log_type':    j.get('SYSLOG_FACILITY', 'System'),
                        'source':      j.get('SYSLOG_IDENTIFIER', j.get('_COMM', 'kernel')),
                        'host':        j.get('_HOSTNAME', 'localhost'),
                        'severity':    sev,
                        'description': msg[:200]
                    })
                except:
                    continue
            if logs:
                return logs[:limit]
    except Exception as e:
        print(f"journalctl error: {e}")

    # 2. Try common Linux log files
    log_files = [
        ('/var/log/auth.log',   'auth.log',   'Security'),
        ('/var/log/syslog',     'syslog',     'System'),
        ('/var/log/messages',   'messages',   'System'),
        ('/var/log/secure',     'secure',     'Security'),
        ('/var/log/kern.log',   'kern.log',   'System'),
    ]
    for path, name, ltype in log_files:
        try:
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()[-limit:]
            for line in lines:
                parsed = _parse_line(line, name, ltype)
                if parsed:
                    logs.append(parsed)
            if logs:
                return logs[:limit]
        except (FileNotFoundError, PermissionError):
            continue

    print("Linux: no log source available")
    return logs


@app.route('/api/windows-logs', methods=['GET'])
def get_windows_logs():
    log_type = request.args.get('type', 'Security')
    limit    = int(request.args.get('limit', 50))
    os_name  = platform.system()
    logs     = []
    source   = 'unknown'

    try:
        if os_name == 'Windows':
            logs   = read_windows_logs_real(log_type, limit)
            source = 'windows-real'
        else:
            logs   = read_linux_auth_logs(limit)
            source = 'linux-real'
    except Exception as e:
        print(f"Log read error: {e}")

    # Always return 200 — empty list is valid (not an error)
    return jsonify({
        'logs':     logs[:limit],
        'total':    len(logs),
        'source':   source,
        'platform': os_name
    })


# ========== REAL-TIME VPN LOGS ==========

VPN_LOG_PATHS = [
    '/var/log/openvpn.log',
    '/var/log/openvpn/openvpn.log',
    '/var/log/openvpn-status.log',
    '/var/log/wireguard.log',
    '/etc/openvpn/openvpn-status.log',
    '/var/log/syslog',
]

def parse_vpn_log_line(line):
    """Parse a VPN log line into a structured dict."""
    from datetime import datetime
    ip_match  = _re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    user_match = _re.search(r'user[=:\s]+([\w.@-]+)', line, _re.IGNORECASE)
    
    ip   = ip_match.group(1)   if ip_match   else 'unknown'
    user = user_match.group(1) if user_match else 'unknown'

    low  = line.lower()
    if any(w in low for w in ['connected', 'established', 'peer']):
        status = 'Connected'
        sev    = 'LOW'
    elif any(w in low for w in ['disconnect', 'closed', 'reset']):
        status = 'Disconnected'
        sev    = 'LOW'
    elif any(w in low for w in ['failed', 'error', 'denied', 'reject', 'invalid']):
        status = 'Failed'
        sev    = 'HIGH'
    elif any(w in low for w in ['block', 'drop', 'forbidden']):
        status = 'Blocked'
        sev    = 'CRITICAL'
    else:
        return None

    return {
        'timestamp':   datetime.utcnow().isoformat(),
        'user':        user,
        'source_ip':   ip,
        'location':    'Real System',
        'vpn_server':  'local-vpn',
        'status':      status,
        'duration':    '—',
        'severity':    sev,
        'raw':         line.strip()[:200]
    }


def read_vpn_logs_real(limit=50):
    """Try all known VPN log paths and parse real entries."""
    vpn_logs = []

    # 1. Try known VPN log files
    for path in VPN_LOG_PATHS:
        try:
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()[-100:]
            for line in lines:
                parsed = parse_vpn_log_line(line)
                if parsed:
                    vpn_logs.append(parsed)
            if vpn_logs:
                break
        except (FileNotFoundError, PermissionError):
            continue

    # 2. Try journalctl for openvpn/wireguard
    if not vpn_logs:
        for service in ['openvpn', 'wg-quick', 'wireguard']:
            try:
                result = subprocess.run(
                    ['journalctl', '-u', service, '-n', str(limit),
                     '--no-pager', '--output=short'],
                    capture_output=True, text=True, timeout=8
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        parsed = parse_vpn_log_line(line)
                        if parsed:
                            vpn_logs.append(parsed)
                    if vpn_logs:
                        break
            except:
                continue

    return vpn_logs[:limit]



@app.route('/api/debug-logs', methods=['GET'])
def debug_logs():
    import json as _json
    results = {}
    try:
        r = subprocess.run(['journalctl', '-n', '3', '--no-pager', '--quiet'],
                           capture_output=True, text=True, timeout=5)
        results['journalctl'] = {'available': r.returncode == 0, 'lines': len(r.stdout.strip().split('\n')), 'error': r.stderr[:100] if r.stderr else None}
    except Exception as e:
        results['journalctl'] = {'available': False, 'error': str(e)}
    for path in ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages', '/var/log/secure', '/var/log/kern.log']:
        try:
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()
            results[path] = {'available': True, 'lines': len(lines)}
        except Exception as e:
            results[path] = {'available': False, 'error': str(e)}
    if platform.system() == 'Windows':
        try:
            r = subprocess.run(['wevtutil', 'qe', 'Security', '/count:2', '/rd:true', '/f:text'],
                               capture_output=True, text=True, timeout=5)
            results['wevtutil'] = {'available': r.returncode == 0, 'output_len': len(r.stdout), 'error': r.stderr[:100] if r.stderr else None}
        except Exception as e:
            results['wevtutil'] = {'available': False, 'error': str(e)}
    return jsonify({'platform': platform.system(), 'sources': results})

@app.route('/api/vpn-logs', methods=['GET'])
def get_vpn_logs():
    try:
        limit       = int(request.args.get('limit', 50))
        status_filter = request.args.get('status', '')

        logs = read_vpn_logs_real(limit)
        real = len(logs) > 0

        if status_filter:
            logs = [l for l in logs if l['status'] == status_filter]

        return jsonify({
            'logs':   logs,
            'total':  len(logs),
            'real':   real,
            'message': 'Real VPN logs' if real else 'No VPN service detected on this system'
        })
    except Exception as e:
        return jsonify({'logs': [], 'total': 0, 'error': str(e)}), 500




# ========== REAL-TIME MALWARE SCANNER ENDPOINT ==========
import os as _os
import psutil as _psutil
import re as _re2
import hashlib as _hashlib

_MALICIOUS_NAMES = {
    'wannacry','petya','notpetya','locky','cryptolocker','ryuk','sodinokibi',
    'revil','darkside','conti','njrat','darkcomet','nanocore','asyncrat','remcos',
    'xmrig','minerd','cpuminer','cgminer','mimikatz','meterpreter',
    'payload.exe','dropper','keylogger','spyware','rootkit','ratclient',
}

_SUSPICIOUS_CMD = [
    r'powershell.*-enc', r'powershell.*bypass', r'powershell.*hidden',
    r'net\s+user.*\/add', r'schtasks.*\/create', r'certutil.*-decode',
    r'curl.*\|.*bash', r'wget.*\|.*bash', r'chmod.*777.*\/tmp',
    r'python.*socket.*connect', r'bash.*-i.*>&.*/dev/tcp',
    r'base64.*decode', r'nohup.*&$',
]

_SUSPICIOUS_PORTS = {
    4444:'Metasploit default', 5555:'Backdoor/ADB', 1337:'Elite backdoor',
    31337:'Elite backdoor', 6666:'IRC botnet', 6667:'IRC botnet',
    12345:'NetBus RAT', 3333:'Monero mining', 9999:'Backdoor', 7777:'Backdoor',
}

_SUSPICIOUS_EXTS = {'.exe','.dll','.bat','.ps1','.vbs','.hta','.scr','.elf','.bin','.sh'}

_TEMP_DIRS_LINUX   = ['/tmp','/var/tmp','/dev/shm','/run/shm']
_TEMP_DIRS_WINDOWS = [
    _os.path.expandvars('%TEMP%'),
    _os.path.expandvars('%APPDATA%'),
]

def _sev(risk):
    if risk >= 80: return 'CRITICAL'
    if risk >= 50: return 'HIGH'
    if risk >= 25: return 'MEDIUM'
    return 'LOW'

def _scan_processes():
    found = []
    try:
        for proc in _psutil.process_iter(['pid','name','exe','cmdline','cpu_percent']):
            try:
                info = proc.info
                name = (info.get('name') or '').lower()
                exe  = (info.get('exe')  or '').lower()
                cmd  = ' '.join(info.get('cmdline') or []).lower()
                risk = 0; reasons = []

                for mal in _MALICIOUS_NAMES:
                    if mal in name or mal in exe:
                        risk += 90; reasons.append(f'Known malware name: {name}'); break

                for pat in _SUSPICIOUS_CMD:
                    if cmd and _re2.search(pat, cmd, _re2.IGNORECASE):
                        risk += 65; reasons.append(f'Suspicious cmdline pattern'); break

                cpu = info.get('cpu_percent') or 0
                if cpu and cpu > 85:
                    risk += 30; reasons.append(f'High CPU: {cpu:.1f}%')

                for sp in ['/tmp/','/dev/shm/','/var/tmp/','\\temp\\','\\appdata\\']:
                    if sp in exe:
                        risk += 45; reasons.append(f'Runs from suspicious path'); break

                if risk > 0:
                    found.append({
                        'timestamp':    datetime.utcnow().isoformat(),
                        'threat_type':  'Suspicious Process',
                        'file_process': f'{info["name"]} (PID {info["pid"]})',
                        'source_ip':    'localhost',
                        'action':       'Monitoring',
                        'severity':     _sev(risk),
                        'description':  ' | '.join(reasons),
                        'category':     'process',
                    })
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                continue
    except Exception as e:
        print(f"Process scan err: {e}")
    return found

def _scan_network():
    found = []
    try:
        seen = set()
        for conn in _psutil.net_connections(kind='inet'):
            try:
                if not conn.raddr: continue
                rip, rport = conn.raddr.ip, conn.raddr.port
                key = (rip, rport)
                if key in seen: continue
                seen.add(key)
                risk = 0; reasons = []

                if rport in _SUSPICIOUS_PORTS:
                    risk += 75; reasons.append(f'Suspicious port {rport}: {_SUSPICIOUS_PORTS[rport]}')

                if rip and not rip.startswith(('127.','10.','192.168.','172.','::1')):
                    if rport in _SUSPICIOUS_PORTS:
                        risk += 20; reasons.append(f'External C2 IP: {rip}')

                if risk > 0:
                    try:   pname = _psutil.Process(conn.pid).name() if conn.pid else 'unknown'
                    except: pname = 'unknown'
                    found.append({
                        'timestamp':    datetime.utcnow().isoformat(),
                        'threat_type':  'Suspicious Connection',
                        'file_process': f'{pname} → {rip}:{rport}',
                        'source_ip':    rip,
                        'action':       'Detected',
                        'severity':     _sev(risk),
                        'description':  ' | '.join(reasons),
                        'category':     'network',
                    })
            except Exception: continue
    except Exception as e:
        print(f"Network scan err: {e}")
    return found

def _scan_files():
    found = []
    dirs = _TEMP_DIRS_WINDOWS if platform.system() == 'Windows' else _TEMP_DIRS_LINUX
    for d in dirs:
        if not _os.path.isdir(d): continue
        try:
            for fname in _os.listdir(d):
                fpath = _os.path.join(d, fname)
                if not _os.path.isfile(fpath): continue
                ext  = _os.path.splitext(fname)[1].lower()
                risk = 0; reasons = []
                if ext in _SUSPICIOUS_EXTS:
                    risk += 50; reasons.append(f'Executable in temp dir: {fname}')
                for mal in _MALICIOUS_NAMES:
                    if mal in fname.lower():
                        risk += 90; reasons.append(f'Malware filename: {fname}'); break
                try:
                    age = datetime.utcnow().timestamp() - _os.path.getctime(fpath)
                    if age < 300 and risk > 0:
                        risk += 20; reasons.append('Recently created')
                except: pass
                if risk > 0:
                    found.append({
                        'timestamp':    datetime.utcnow().isoformat(),
                        'threat_type':  'Suspicious File',
                        'file_process': fpath[:80],
                        'source_ip':    'localhost',
                        'action':       'Flagged',
                        'severity':     _sev(risk),
                        'description':  ' | '.join(reasons),
                        'category':     'file',
                    })
        except PermissionError: continue
    return found

def _scan_persistence():
    found = []
    if platform.system() != 'Linux': return found
    paths = ['/etc/crontab','/etc/rc.local',
             _os.path.expanduser('~/.bashrc'), _os.path.expanduser('~/.profile')]
    keywords = ['curl ','wget ','nc ','netcat','bash -i','/dev/tcp',
                'base64','python -c','chmod 777','/tmp/','/dev/shm/']
    for path in paths:
        if not _os.path.isfile(path): continue
        try:
            with open(path,'r', errors='ignore') as f: txt = f.read()
            for kw in keywords:
                if kw in txt:
                    found.append({
                        'timestamp':    datetime.utcnow().isoformat(),
                        'threat_type':  'Persistence Mechanism',
                        'file_process': path,
                        'source_ip':    'localhost',
                        'action':       'Detected',
                        'severity':     'HIGH',
                        'description':  f'Suspicious keyword "{kw}" in {path}',
                        'category':     'persistence',
                    })
                    break
        except: continue
    return found

@app.route('/api/malware-scan', methods=['GET'])
def malware_scan():
    """Fetch real scan results from local malware agent (port 5001)."""
    import urllib.request as _urllib
    try:
        # Try local agent first (malware_agent.py running on user machine)
        with _urllib.urlopen('http://localhost:5001/scan', timeout=3) as r:
            import json as _json
            data = _json.loads(r.read().decode())
            return jsonify(data)
    except Exception as agent_err:
        # Agent not running — do inline scan as fallback
        try:
            results = []
            results.extend(_scan_processes())
            results.extend(_scan_network())
            results.extend(_scan_files())
            results.extend(_scan_persistence())
            order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
            results.sort(key=lambda x: order.get(x['severity'], 4))
            return jsonify({
                'threats':    results,
                'total':      len(results),
                'critical':   sum(1 for r in results if r['severity'] == 'CRITICAL'),
                'high':       sum(1 for r in results if r['severity'] == 'HIGH'),
                'scanned_at': datetime.utcnow().isoformat(),
                'platform':   platform.system(),
                'source':     'inline-scan',
                'scanned_processes':   len(list(_psutil.process_iter())),  # ADDITION: count scanned items
                'scanned_connections': len(_psutil.net_connections(kind='inet')),  # ADDITION
                'scanned_files':       len(results),  # ADDITION: files flagged (not total)
            })
        except Exception as e:
            return jsonify({'threats':[], 'total':0, 'error': str(e), 'agent_error': str(agent_err)}), 500

# ========== VULN SITE ALERT INGEST (ADDITION ONLY) ==========


def _instant_email(alert):
    """Fire email immediately when a HIGH/CRITICAL alert arrives."""
    try:
        cfg = load_email_config()
        if not cfg.get('enabled') or not cfg.get('smtp_user'):
            return
        sev = alert.get('severity', '')
        if sev not in cfg.get('alert_on', ['CRITICAL', 'HIGH']):
            return
        send_alert_email(cfg, alert)
        print(f"[Email] Sent {sev} alert email to {cfg.get('to_emails')}")
    except Exception as e:
        print(f"[Email] instant send error: {e}")

@app.route('/api/ingest', methods=['POST'])
def ingest_alert():
    """Receive alerts and instantly fire email for HIGH/CRITICAL."""
    try:
        data        = request.get_json() or {}
        severity    = data.get('severity',    'HIGH').upper()
        source_ip   = data.get('source_ip',   'unknown')
        description = data.get('description', '')
        event_type  = data.get('event_type',  'EXTERNAL')
        timestamp   = data.get('timestamp',   datetime.utcnow().isoformat())

        db.insert_log({
            'timestamp':   timestamp,
            'source_ip':   source_ip,
            'severity':    severity,
            'event_type':  event_type,
            'description': description
        })

        if severity in ('HIGH', 'CRITICAL'):
            alert = {
                'timestamp':   timestamp,
                'severity':    severity,
                'source_ip':   source_ip,
                'description': description
            }
            db.insert_alert(alert)
            # Fire email instantly in background thread
            threading.Thread(
                target=_instant_email,
                args=(alert,),
                daemon=True
            ).start()

        return jsonify({'status': 'ok', 'severity': severity}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



# ========== ANALYTICS ENDPOINTS ==========

@app.route('/api/analytics/overview', methods=['GET'])
def analytics_overview():
    """Real stats computed from actual DB data."""
    try:
        con = db.connect()
        cur = con.cursor()

        # Total events & alerts
        cur.execute("SELECT COUNT(*) FROM logs")
        total_logs = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cur.fetchone()[0]

        # Severity breakdown
        cur.execute("SELECT severity, COUNT(*) FROM logs GROUP BY severity")
        sev_rows = cur.fetchall()
        severity_dist = {r[0]: r[1] for r in sev_rows}

        # Top attacking IPs
        cur.execute("SELECT source_ip, COUNT(*) as cnt FROM logs GROUP BY source_ip ORDER BY cnt DESC LIMIT 8")
        top_ips = [{'ip': r[0], 'count': r[1]} for r in cur.fetchall()]

        # Top event types
        cur.execute("SELECT event_type, COUNT(*) as cnt FROM logs GROUP BY event_type ORDER BY cnt DESC LIMIT 8")
        top_types = [{'type': r[0], 'count': r[1]} for r in cur.fetchall()]

        # Events per hour (last 24h)
        cur.execute("""
            SELECT strftime('%H', timestamp) as hr, COUNT(*) as cnt
            FROM logs
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hr ORDER BY hr
        """)
        hourly = {r[0]: r[1] for r in cur.fetchall()}
        hourly_data = [{'hour': f'{h:02d}:00', 'count': hourly.get(f'{h:02d}', 0)} for h in range(24)]

        # Events per day (last 7 days)
        cur.execute("""
            SELECT date(timestamp) as day, COUNT(*) as cnt
            FROM logs
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY day ORDER BY day
        """)
        daily = [{'day': r[0], 'count': r[1]} for r in cur.fetchall()]

        # Alert trend (last 7 days)
        cur.execute("""
            SELECT date(timestamp) as day, severity, COUNT(*) as cnt
            FROM alerts
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY day, severity ORDER BY day
        """)
        alert_trend_raw = cur.fetchall()
        alert_trend = {}
        for row in alert_trend_raw:
            day, sev, cnt = row
            if day not in alert_trend:
                alert_trend[day] = {'day': day, 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            alert_trend[day][sev] = cnt
        alert_trend_list = sorted(alert_trend.values(), key=lambda x: x['day'])

        # Avg events/hour (last 24h)
        cur.execute("SELECT COUNT(*) FROM logs WHERE timestamp >= datetime('now', '-24 hours')")
        last24h = cur.fetchone()[0]
        avg_per_hour = round(last24h / 24, 1)

        # Response time (mock based on real data volume)
        response_ms = max(50, min(500, 500 - total_logs))

        con.close()
        return jsonify({
            'total_logs':     total_logs,
            'total_alerts':   total_alerts,
            'avg_per_hour':   avg_per_hour,
            'last_24h':       last24h,
            'severity_dist':  severity_dist,
            'top_ips':        top_ips,
            'top_types':      top_types,
            'hourly_data':    hourly_data,
            'daily_data':     daily,
            'alert_trend':    alert_trend_list,
            'response_ms':    response_ms,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========== PDF REPORT + EMAIL ALERTS (INLINED) ==========
import io
import os
import json
import smtplib
import threading
import sqlite3
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Email config storage ──────────────────────────────────
EMAIL_CONFIG_FILE = 'email_config.json'

DEFAULT_CONFIG = {
    'smtp_host':     'smtp.gmail.com',
    'smtp_port':     587,
    'smtp_user':     '',
    'smtp_password': '',
    'from_email':    '',
    'to_emails':     [],
    'alert_on':      ['CRITICAL', 'HIGH'],
    'enabled':       False,
}

def load_email_config():
    if os.path.exists(EMAIL_CONFIG_FILE):
        try:
            with open(EMAIL_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                return {**DEFAULT_CONFIG, **cfg}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_email_config(cfg):
    with open(EMAIL_CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)


# ══════════════════════════════════════════════════════════
#  PDF REPORT GENERATOR
# ══════════════════════════════════════════════════════════

# Colour palette matching SIEM dark theme
C_BG       = colors.HexColor('#1a0f2e')
C_PRIMARY  = colors.HexColor('#7c3aed')
C_LIGHT    = colors.HexColor('#a78bfa')
C_DARK     = colors.HexColor('#0f0720')
C_RED      = colors.HexColor('#ef4444')
C_AMBER    = colors.HexColor('#f59e0b')
C_GREEN    = colors.HexColor('#10b981')
C_INDIGO   = colors.HexColor('#6366f1')
C_GRAY     = colors.HexColor('#94a3b8')
C_WHITE    = colors.white
C_ROW_ALT  = colors.HexColor('#1e1b4b')
C_ROW_EVEN = colors.HexColor('#13102a')

SEV_COLORS = {
    'CRITICAL': C_RED,
    'HIGH':     C_AMBER,
    'MEDIUM':   C_INDIGO,
    'LOW':      C_GREEN,
}

def _styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('SIEMTitle',
            fontSize=26, textColor=C_WHITE, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=4),
        'subtitle': ParagraphStyle('SIEMSub',
            fontSize=11, textColor=C_LIGHT, fontName='Helvetica',
            alignment=TA_CENTER, spaceAfter=2),
        'section': ParagraphStyle('SIEMSection',
            fontSize=14, textColor=C_LIGHT, fontName='Helvetica-Bold',
            spaceBefore=16, spaceAfter=8),
        'body': ParagraphStyle('SIEMBody',
            fontSize=9, textColor=C_GRAY, fontName='Helvetica',
            spaceAfter=4, leading=14),
        'small': ParagraphStyle('SIEMSmall',
            fontSize=8, textColor=C_GRAY, fontName='Helvetica',
            alignment=TA_CENTER),
        'stat_val': ParagraphStyle('SIEMStat',
            fontSize=28, textColor=C_WHITE, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=0),
        'stat_lbl': ParagraphStyle('SIEMStatLbl',
            fontSize=8, textColor=C_GRAY, fontName='Helvetica',
            alignment=TA_CENTER),
    }

def _header_footer(canvas, doc):
    """Draw dark background + header/footer on every page."""
    w, h = A4
    canvas.saveState()

    # Full page dark background
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)

    # Top accent bar
    canvas.setFillColor(C_PRIMARY)
    canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)

    # Header text
    canvas.setFont('Helvetica-Bold', 10)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(1.5*cm, h - 0.85*cm, '🛡  S.I.E.M. SECURITY REPORT')
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(C_LIGHT)
    canvas.drawRightString(w - 1.5*cm, h - 0.85*cm,
        f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}')

    # Bottom accent line
    canvas.setStrokeColor(C_PRIMARY)
    canvas.setLineWidth(1.5)
    canvas.line(1.5*cm, 1.2*cm, w - 1.5*cm, 1.2*cm)

    # Footer text
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(1.5*cm, 0.6*cm, 'CONFIDENTIAL — Internal Security Use Only')
    canvas.drawRightString(w - 1.5*cm, 0.6*cm, f'Page {doc.page}')

    canvas.restoreState()


def _stat_table(stats):
    """4-column stat summary block."""
    sty = _styles()
    total_logs    = stats.get('total_logs', 0)
    total_alerts  = stats.get('total_alerts', 0)
    critical      = stats.get('critical_alerts', 0)
    high          = stats.get('high_alerts', 0)

    cells = [
        [Paragraph(str(total_logs),   sty['stat_val']),
         Paragraph(str(total_alerts), sty['stat_val']),
         Paragraph(str(critical),     ParagraphStyle('CV', fontSize=28, textColor=C_RED,   fontName='Helvetica-Bold', alignment=TA_CENTER)),
         Paragraph(str(high),         ParagraphStyle('HV', fontSize=28, textColor=C_AMBER, fontName='Helvetica-Bold', alignment=TA_CENTER))],
        [Paragraph('Total Events',    sty['stat_lbl']),
         Paragraph('Total Alerts',    sty['stat_lbl']),
         Paragraph('Critical',        sty['stat_lbl']),
         Paragraph('High',            sty['stat_lbl'])],
    ]
    t = Table(cells, colWidths=[4.2*cm]*4)
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,-1), C_BG),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [C_BG, C_ROW_ALT]),
        ('LINEAFTER',   (0,0), (2,1),    colors.HexColor('#2d1b69'), 1),
        ('TOPPADDING',  (0,0), (-1,-1),  12),
        ('BOTTOMPADDING',(0,0),(-1,-1),  12),
        ('ROUNDEDCORNERS', [6]),
    ]))
    return t


def _alerts_table(alerts, sty):
    """Render alerts as a styled table."""
    if not alerts:
        return Paragraph('No alerts recorded in this period.', sty['body'])

    headers = ['#', 'Time', 'Severity', 'Source IP', 'Description']
    rows = [[
        Paragraph(h, ParagraphStyle('TH', fontSize=8, textColor=C_LIGHT,
                                    fontName='Helvetica-Bold', alignment=TA_CENTER))
        for h in headers
    ]]

    for i, a in enumerate(alerts[:50], 1):
        sev   = a.get('severity', 'LOW')
        sev_c = SEV_COLORS.get(sev, C_GRAY)
        ts    = a.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts).strftime('%m/%d %H:%M')
        except Exception:
            ts = str(ts)[:16]

        rows.append([
            Paragraph(str(i), ParagraphStyle('TC', fontSize=8, textColor=C_GRAY,   alignment=TA_CENTER, fontName='Helvetica')),
            Paragraph(ts,     ParagraphStyle('TC', fontSize=8, textColor=C_GRAY,   fontName='Helvetica')),
            Paragraph(sev,    ParagraphStyle('TC', fontSize=8, textColor=sev_c,    fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(str(a.get('source_ip', '—'))[:18],
                              ParagraphStyle('TC', fontSize=8, textColor=C_WHITE,  fontName='Helvetica')),
            Paragraph(str(a.get('description', '—'))[:80],
                              ParagraphStyle('TC', fontSize=7, textColor=C_GRAY,   fontName='Helvetica')),
        ])

    col_w = [1*cm, 2.2*cm, 2*cm, 3.2*cm, 8.6*cm]
    t = Table(rows, colWidths=col_w, repeatRows=1)
    row_styles = [
        ('BACKGROUND',    (0,0), (-1,0),  C_PRIMARY),
        ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_ROW_EVEN, C_ROW_ALT]),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#2d1b69')),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('RIGHTPADDING',  (0,0), (-1,-1), 6),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]
    t.setStyle(TableStyle(row_styles))
    return t


def _logs_table(logs, sty):
    """Render recent logs table."""
    if not logs:
        return Paragraph('No logs recorded.', sty['body'])

    headers = ['#', 'Time', 'Source IP', 'Severity', 'Event Type', 'Description']
    rows = [[
        Paragraph(h, ParagraphStyle('TH', fontSize=8, textColor=C_LIGHT,
                                    fontName='Helvetica-Bold', alignment=TA_CENTER))
        for h in headers
    ]]

    for i, l in enumerate(logs[:30], 1):
        sev   = l.get('severity', 'LOW')
        sev_c = SEV_COLORS.get(sev, C_GRAY)
        ts    = l.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts).strftime('%m/%d %H:%M')
        except Exception:
            ts = str(ts)[:16]

        rows.append([
            Paragraph(str(i),  ParagraphStyle('TC', fontSize=8, textColor=C_GRAY,  alignment=TA_CENTER, fontName='Helvetica')),
            Paragraph(ts,      ParagraphStyle('TC', fontSize=8, textColor=C_GRAY,  fontName='Helvetica')),
            Paragraph(str(l.get('source_ip','—'))[:16],
                               ParagraphStyle('TC', fontSize=8, textColor=C_WHITE, fontName='Helvetica')),
            Paragraph(sev,     ParagraphStyle('TC', fontSize=8, textColor=sev_c,   fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(str(l.get('event_type','—'))[:20],
                               ParagraphStyle('TC', fontSize=8, textColor=C_LIGHT, fontName='Helvetica')),
            Paragraph(str(l.get('description','—'))[:70],
                               ParagraphStyle('TC', fontSize=7, textColor=C_GRAY,  fontName='Helvetica')),
        ])

    col_w = [0.8*cm, 2.2*cm, 2.8*cm, 2*cm, 3*cm, 7.2*cm]
    t = Table(rows, colWidths=col_w, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  C_PRIMARY),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_ROW_EVEN, C_ROW_ALT]),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#2d1b69')),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('RIGHTPADDING',  (0,0), (-1,-1), 6),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    return t


def _sev_bar_table(dist, sty):
    """Severity distribution as text bars."""
    total = sum(dist.values()) or 1
    rows  = []
    for sev, clr in [('CRITICAL', C_RED), ('HIGH', C_AMBER),
                     ('MEDIUM', C_INDIGO), ('LOW', C_GREEN)]:
        count = dist.get(sev, 0)
        pct   = int(count / total * 100)
        bar   = '█' * (pct // 4) + '░' * (25 - pct // 4)
        rows.append([
            Paragraph(sev,             ParagraphStyle('SB', fontSize=9, textColor=clr, fontName='Helvetica-Bold')),
            Paragraph(bar,             ParagraphStyle('SB', fontSize=9, textColor=clr, fontName='Helvetica')),
            Paragraph(f'{count} ({pct}%)',
                                       ParagraphStyle('SB', fontSize=9, textColor=C_WHITE, fontName='Helvetica-Bold', alignment=TA_RIGHT)),
        ])
    t = Table(rows, colWidths=[3*cm, 9*cm, 3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), C_BG),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('LINEBELOW',     (0,0), (-1,-2), 0.3, colors.HexColor('#2d1b69')),
    ]))
    return t


def generate_pdf_report(db_instance):
    """
    Generate full SIEM security report PDF.
    Returns: bytes of PDF file
    """
    sty = _styles()

    # ── Pull data from DB ─────────────────────────────────
    stats  = db_instance.get_statistics()
    alerts = db_instance.get_alerts()
    logs_r = db_instance.get_logs(1, 30)
    logs   = logs_r.get('logs', [])
    dist   = db_instance.get_event_distribution_last_hour()

    # Severity counts
    crit_alerts  = [a for a in alerts if a.get('severity') == 'CRITICAL']
    high_alerts  = [a for a in alerts if a.get('severity') == 'HIGH']
    stats['high_alerts'] = len(high_alerts)

    # Top IPs
    from collections import Counter
    ip_counts = Counter(a.get('source_ip', 'unknown') for a in alerts)
    top_ips   = ip_counts.most_common(10)

    # ── Build PDF ─────────────────────────────────────────
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=2*cm,    bottomMargin=2*cm,
    )
    story = []

    # ── Cover / Title ─────────────────────────────────────
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph('S.I.E.M.', sty['title']))
    story.append(Paragraph('Security Information &amp; Event Management', sty['subtitle']))
    story.append(Paragraph('SECURITY INCIDENT REPORT', ParagraphStyle('RType',
        fontSize=13, textColor=C_LIGHT, fontName='Helvetica-Bold',
        alignment=TA_CENTER, spaceAfter=4)))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f'Report Period: Last 24 Hours &nbsp;|&nbsp; Generated: {datetime.utcnow().strftime("%B %d, %Y %H:%M UTC")}',
        sty['small']))
    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width='100%', thickness=1.5, color=C_PRIMARY))
    story.append(Spacer(1, 0.8*cm))

    # ── Executive Summary Stats ───────────────────────────
    story.append(Paragraph('Executive Summary', sty['section']))
    story.append(_stat_table(stats))
    story.append(Spacer(1, 0.6*cm))

    # Risk level
    risk_level = 'CRITICAL' if stats.get('critical_alerts',0) > 0 else \
                 'HIGH'     if len(high_alerts) > 5  else \
                 'MEDIUM'   if stats.get('total_alerts',0) > 0 else 'LOW'
    risk_clr   = SEV_COLORS.get(risk_level, C_GREEN)
    story.append(Table([[
        Paragraph('Overall Risk Level:', ParagraphStyle('RL', fontSize=11,
            textColor=C_GRAY, fontName='Helvetica', alignment=TA_CENTER)),
        Paragraph(risk_level, ParagraphStyle('RV', fontSize=14,
            textColor=risk_clr, fontName='Helvetica-Bold', alignment=TA_CENTER)),
    ]], colWidths=[8.5*cm, 8.5*cm]))
    story.append(Spacer(1, 0.6*cm))

    # ── Severity Distribution ─────────────────────────────
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_PRIMARY))
    story.append(Paragraph('Severity Distribution (Last Hour)', sty['section']))
    story.append(_sev_bar_table(dist, sty))
    story.append(Spacer(1, 0.5*cm))

    # ── Top Attacking IPs ─────────────────────────────────
    if top_ips:
        story.append(HRFlowable(width='100%', thickness=0.5, color=C_PRIMARY))
        story.append(Paragraph('Top Source IPs by Alert Count', sty['section']))
        ip_rows = [[
            Paragraph('Rank', ParagraphStyle('TH', fontSize=8, textColor=C_LIGHT, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph('Source IP', ParagraphStyle('TH', fontSize=8, textColor=C_LIGHT, fontName='Helvetica-Bold')),
            Paragraph('Alerts', ParagraphStyle('TH', fontSize=8, textColor=C_LIGHT, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph('Threat Level', ParagraphStyle('TH', fontSize=8, textColor=C_LIGHT, fontName='Helvetica-Bold', alignment=TA_CENTER)),
        ]]
        for rank, (ip, count) in enumerate(top_ips, 1):
            threat = 'CRITICAL' if count > 10 else 'HIGH' if count > 5 else 'MEDIUM' if count > 2 else 'LOW'
            tc     = SEV_COLORS.get(threat, C_GREEN)
            ip_rows.append([
                Paragraph(f'#{rank}',  ParagraphStyle('TC', fontSize=9, textColor=C_GRAY,  alignment=TA_CENTER, fontName='Helvetica')),
                Paragraph(str(ip),     ParagraphStyle('TC', fontSize=9, textColor=C_WHITE, fontName='Helvetica-Oblique')),
                Paragraph(str(count),  ParagraphStyle('TC', fontSize=9, textColor=C_WHITE, alignment=TA_CENTER, fontName='Helvetica-Bold')),
                Paragraph(threat,      ParagraphStyle('TC', fontSize=9, textColor=tc,      alignment=TA_CENTER, fontName='Helvetica-Bold')),
            ])
        ip_t = Table(ip_rows, colWidths=[2*cm, 7*cm, 3*cm, 5*cm])
        ip_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_PRIMARY),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_ROW_EVEN, C_ROW_ALT]),
            ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#2d1b69')),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(ip_t)
        story.append(Spacer(1, 0.5*cm))

    # ── Critical Alerts ───────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('Critical Alerts', sty['section']))
    if crit_alerts:
        story.append(Paragraph(
            f'{len(crit_alerts)} CRITICAL alerts detected. Immediate investigation required.',
            ParagraphStyle('Warn', fontSize=9, textColor=C_RED, fontName='Helvetica-Bold', spaceAfter=8)))
    story.append(_alerts_table(crit_alerts + high_alerts, sty))
    story.append(Spacer(1, 0.6*cm))

    # ── Recent Event Logs ─────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('Recent Security Events (Last 30)', sty['section']))
    story.append(_logs_table(logs, sty))
    story.append(Spacer(1, 0.6*cm))

    # ── Recommendations ───────────────────────────────────
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_PRIMARY))
    story.append(Paragraph('Recommendations', sty['section']))
    recs = []
    if stats.get('critical_alerts', 0) > 0:
        recs.append('• Immediately investigate all CRITICAL alerts — potential active breach.')
    if len(high_alerts) > 5:
        recs.append('• HIGH alert volume is elevated — review firewall rules and access controls.')
    if top_ips and top_ips[0][1] > 10:
        recs.append(f'• Block or rate-limit IP {top_ips[0][0]} — highest attack frequency ({top_ips[0][1]} alerts).')
    if not recs:
        recs.append('• System appears stable. Continue monitoring and scheduled reviews.')
    recs += [
        '• Ensure all system patches are up to date.',
        '• Review user access privileges quarterly.',
        '• Schedule next full security audit within 30 days.',
    ]
    for rec in recs:
        story.append(Paragraph(rec, sty['body']))
    story.append(Spacer(1, 0.5*cm))

    # ── Footer note ───────────────────────────────────────
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_PRIMARY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        'This report was automatically generated by S.I.E.M. Security Dashboard. '
        'All data reflects real-time detection from connected sensors and log sources. '
        'CONFIDENTIAL — Do not distribute outside the security team.',
        sty['small']))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    buf.seek(0)
    return buf.read()


# ══════════════════════════════════════════════════════════
#  EMAIL ALERT SYSTEM
# ══════════════════════════════════════════════════════════

_email_lock    = threading.Lock()
_alerted_ids   = set()   # track already-emailed alert IDs

def send_alert_email(cfg, alert):
    """Send HTML alert email for a single HIGH/CRITICAL alert."""
    if not cfg.get('enabled') or not cfg.get('smtp_user'):
        return False, 'Email not configured or disabled'

    sev     = alert.get('severity', 'HIGH')
    src_ip  = alert.get('source_ip', 'unknown')
    desc    = alert.get('description', '')
    ts      = alert.get('timestamp', datetime.utcnow().isoformat())

    sev_color = '#ef4444' if sev == 'CRITICAL' else '#f59e0b'
    icon      = '🚨' if sev == 'CRITICAL' else '⚠️'

    subject = f'{icon} [{sev}] SIEM Alert — {src_ip} — {ts[:16]}'

    html = f"""
    <div style="font-family:Arial,sans-serif;background:#0f0720;padding:30px;border-radius:12px;max-width:600px;margin:auto;">
      <div style="background:#1a0f2e;border-radius:10px;overflow:hidden;border:1px solid #7c3aed;">
        <div style="background:{sev_color};padding:20px 24px;display:flex;align-items:center;gap:12px;">
          <span style="font-size:2em;">{icon}</span>
          <div>
            <div style="color:#fff;font-size:1.3em;font-weight:700;">{sev} SECURITY ALERT</div>
            <div style="color:rgba(255,255,255,0.8);font-size:0.9em;">S.I.E.M. Real-Time Detection</div>
          </div>
        </div>
        <div style="padding:24px;">
          <table style="width:100%;border-collapse:collapse;">
            <tr>
              <td style="padding:10px;color:#94a3b8;font-size:0.85em;width:35%;">Severity</td>
              <td style="padding:10px;color:{sev_color};font-weight:700;font-size:1em;">{sev}</td>
            </tr>
            <tr style="background:#13102a;">
              <td style="padding:10px;color:#94a3b8;font-size:0.85em;">Source IP</td>
              <td style="padding:10px;color:#e2e8f0;font-family:monospace;">{src_ip}</td>
            </tr>
            <tr>
              <td style="padding:10px;color:#94a3b8;font-size:0.85em;">Timestamp</td>
              <td style="padding:10px;color:#e2e8f0;">{ts}</td>
            </tr>
            <tr style="background:#13102a;">
              <td style="padding:10px;color:#94a3b8;font-size:0.85em;">Description</td>
              <td style="padding:10px;color:#e2e8f0;">{desc}</td>
            </tr>
          </table>
          <div style="margin-top:20px;padding:14px;background:#7c3aed22;border-radius:8px;border-left:3px solid #7c3aed;">
            <div style="color:#a78bfa;font-size:0.85em;font-weight:700;">ACTION REQUIRED</div>
            <div style="color:#94a3b8;font-size:0.82em;margin-top:4px;">
              {'Immediately investigate this CRITICAL security incident.' if sev == 'CRITICAL'
               else 'Review and assess this HIGH severity alert promptly.'}
              Log in to your SIEM dashboard for full details.
            </div>
          </div>
        </div>
        <div style="background:#0f0720;padding:12px 24px;text-align:center;color:#475569;font-size:0.75em;border-top:1px solid #2d1b69;">
          S.I.E.M. Security Dashboard — Automated Alert System
        </div>
      </div>
    </div>
    """

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = cfg.get('from_email') or cfg['smtp_user']
        msg['To']      = ', '.join(cfg['to_emails'])
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port'], timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg['smtp_user'], cfg['smtp_password'])
            server.sendmail(cfg['smtp_user'], cfg['to_emails'], msg.as_string())
        return True, 'Email sent successfully'
    except Exception as e:
        return False, str(e)


def check_and_send_alerts(db_instance):
    """Called periodically — send emails for new HIGH/CRITICAL alerts."""
    cfg = load_email_config()
    if not cfg.get('enabled'):
        return
    try:
        alerts = db_instance.get_alerts()
        for alert in alerts:
            aid = alert.get('alert_id') or alert.get('id')
            if not aid:
                continue
            sev = alert.get('severity', '')
            if sev not in cfg.get('alert_on', ['CRITICAL', 'HIGH']):
                continue
            with _email_lock:
                if aid in _alerted_ids:
                    continue
                _alerted_ids.add(aid)
            send_alert_email(cfg, alert)
    except Exception as e:
        print(f'[Email] check error: {e}')


def start_email_monitor(db_instance, interval=15):
    """Background thread that checks for new alerts every N seconds."""
    def _loop():
        while True:
            import time
            time.sleep(interval)
            check_and_send_alerts(db_instance)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    print(f'[Email] Alert monitor started — checking every {interval}s')


@app.route('/api/generate-report', methods=['GET'])
def generate_report():
    try:
        pdf_bytes = generate_pdf_report(db)
        from flask import Response
        filename = f'SIEM_Report_{datetime.utcnow().strftime("%Y%m%d_%H%M")}.pdf'
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Length': str(len(pdf_bytes))
            }
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email-config', methods=['GET'])
def get_email_config():
    cfg = load_email_config()
    safe = {k: v for k, v in cfg.items() if k != 'smtp_password'}
    safe['smtp_password'] = '***' if cfg.get('smtp_password') else ''
    return jsonify(safe)

@app.route('/api/email-config', methods=['POST'])
def set_email_config():
    try:
        data = request.get_json() or {}
        cfg  = load_email_config()
        for key in ['smtp_host','smtp_port','smtp_user','from_email',
                    'to_emails','alert_on','enabled']:
            if key in data:
                cfg[key] = data[key]
        if data.get('smtp_password') and data['smtp_password'] != '***':
            cfg['smtp_password'] = data['smtp_password']
        save_email_config(cfg)
        return jsonify({'status': 'ok', 'message': 'Email config saved'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-email', methods=['POST'])
def test_email():
    try:
        cfg = load_email_config()
        ok, msg = send_alert_email(cfg, {
            'severity':    'HIGH',
            'source_ip':   '10.0.0.1',
            'description': 'This is a test alert from your SIEM dashboard.',
            'timestamp':   datetime.utcnow().isoformat(),
        })
        return jsonify({'success': ok, 'message': msg})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ========== MALWARE DETECTION WITH DATABASE STORAGE (NEW - ADDITION ONLY) ==========

@app.route('/api/malware-scan-and-store', methods=['GET'])
@jwt_required()
def malware_scan_and_store():
    """Run REAL malware scan and store results in database"""
    import time
    import platform
    start_time = time.time()
    
    try:
        # Run REAL scans
        results = []
        results.extend(_scan_processes())
        results.extend(_scan_network())
        results.extend(_scan_files())
        results.extend(_scan_persistence())
        
        # Sort by severity
        order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
        results.sort(key=lambda x: order.get(x['severity'], 4))
        
        # Count by severity
        critical_count = sum(1 for r in results if r['severity'] == 'CRITICAL')
        high_count = sum(1 for r in results if r['severity'] == 'HIGH')
        medium_count = sum(1 for r in results if r['severity'] == 'MEDIUM')
        low_count = sum(1 for r in results if r['severity'] == 'LOW')
        
        scan_duration = time.time() - start_time
        
        # Store in database
        con = db.connect()
        cur = con.cursor()
        
        cur.execute("""
        INSERT INTO malware_scans 
        (scan_timestamp, total_threats, critical_count, high_count, medium_count, low_count, 
         scan_results, platform, scan_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            len(results),
            critical_count,
            high_count,
            medium_count,
            low_count,
            json.dumps(results),
            platform.system(),
            scan_duration
        ))
        
        scan_id = cur.lastrowid
        con.commit()
        con.close()
        
        # Also insert critical/high threats as alerts
        for threat in results:
            if threat['severity'] in ['CRITICAL', 'HIGH']:
                db.insert_alert({
                    'timestamp': threat['timestamp'],
                    'severity': threat['severity'],
                    'source_ip': threat.get('source_ip', 'localhost'),
                    'description': f"[MALWARE] {threat['threat_type']}: {threat['description']}"
                })
        
        return jsonify({
            'scan_id': scan_id,
            'threats': results,
            'total': len(results),
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'scanned_at': datetime.utcnow().isoformat(),
            'platform': platform.system(),
            'scan_duration': round(scan_duration, 2),
            'source': 'real-scan-stored'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e), 'threats': [], 'total': 0}), 500


@app.route('/api/malware-scan-history', methods=['GET'])
@jwt_required()
def get_malware_scan_history():
    """Get history of malware scans"""
    try:
        limit = int(request.args.get('limit', 20))
        
        con = db.connect()
        cur = con.cursor()
        
        rows = cur.execute("""
        SELECT scan_id, scan_timestamp, total_threats, critical_count, high_count, 
               medium_count, low_count, platform, scan_duration
        FROM malware_scans
        ORDER BY scan_timestamp DESC
        LIMIT ?
        """, (limit,)).fetchall()
        
        con.close()
        
        scans = []
        for row in rows:
            scans.append({
                'scan_id': row[0],
                'scan_timestamp': row[1],
                'total_threats': row[2],
                'critical_count': row[3],
                'high_count': row[4],
                'medium_count': row[5],
                'low_count': row[6],
                'platform': row[7],
                'scan_duration': row[8]
            })
        
        return jsonify({'scans': scans, 'total': len(scans)}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/malware-scan/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_malware_scan_detail(scan_id):
    """Get detailed results of a specific scan"""
    try:
        con = db.connect()
        cur = con.cursor()
        
        row = cur.execute("""
        SELECT scan_id, scan_timestamp, total_threats, critical_count, high_count, 
               medium_count, low_count, scan_results, platform, scan_duration
        FROM malware_scans
        WHERE scan_id = ?
        """, (scan_id,)).fetchone()
        
        con.close()
        
        if not row:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan_results = json.loads(row[7]) if row[7] else []
        
        return jsonify({
            'scan_id': row[0],
            'scan_timestamp': row[1],
            'total_threats': row[2],
            'critical_count': row[3],
            'high_count': row[4],
            'medium_count': row[5],
            'low_count': row[6],
            'threats': scan_results,
            'platform': row[8],
            'scan_duration': row[9]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/malware-report/download/<int:scan_id>', methods=['GET'])
@jwt_required()
def download_malware_report(scan_id):
    """Download malware scan report as CSV"""
    try:
        con = db.connect()
        cur = con.cursor()
        
        row = cur.execute("""
        SELECT scan_timestamp, scan_results, total_threats, critical_count, 
               high_count, medium_count, low_count, platform
        FROM malware_scans
        WHERE scan_id = ?
        """, (scan_id,)).fetchone()
        
        con.close()
        
        if not row:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan_timestamp = row[0]
        scan_results = json.loads(row[1]) if row[1] else []
        
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['SIEM Malware Scan Report'])
        writer.writerow(['Scan ID', scan_id])
        writer.writerow(['Scan Time', scan_timestamp])
        writer.writerow(['Platform', row[7]])
        writer.writerow(['Total Threats', row[2]])
        writer.writerow(['Critical', row[3]])
        writer.writerow(['High', row[4]])
        writer.writerow(['Medium', row[5]])
        writer.writerow(['Low', row[6]])
        writer.writerow([])
        
        # Threats table
        writer.writerow(['Timestamp', 'Severity', 'Threat Type', 'File/Process', 'Source IP', 'Description'])
        
        for threat in scan_results:
            writer.writerow([
                threat.get('timestamp', ''),
                threat.get('severity', ''),
                threat.get('threat_type', ''),
                threat.get('file_process', ''),
                threat.get('source_ip', ''),
                threat.get('description', '')
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=malware_scan_{scan_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/malware-report/download-all', methods=['GET'])
@jwt_required()
def download_all_malware_reports():
    """Download all malware scans as CSV"""
    try:
        con = db.connect()
        cur = con.cursor()
        
        rows = cur.execute("""
        SELECT scan_id, scan_timestamp, total_threats, critical_count, high_count, 
               medium_count, low_count, platform, scan_duration
        FROM malware_scans
        ORDER BY scan_timestamp DESC
        """).fetchall()
        
        con.close()
        
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['SIEM Malware Scan History Report'])
        writer.writerow(['Generated', datetime.now().isoformat()])
        writer.writerow([])
        writer.writerow([
            'Scan ID', 'Scan Timestamp', 'Total Threats', 'Critical', 
            'High', 'Medium', 'Low', 'Platform', 'Duration (s)'
        ])
        
        for row in rows:
            writer.writerow(row)
        
        csv_content = output.getvalue()
        output.close()
        
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=malware_scan_history_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========== END OF NEW ROUTES ==========

if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  SIEM - DATABASE AUTHENTICATION")
    print("=" * 70)
    print("Default login: admin / arsath")
    print("All users stored in siem.db -> users table")
    print()

    db.initialize()

    threading.Thread(target=realtime_log_monitor, daemon=True).start()
    threading.Thread(target=_priv_esc_watcher, daemon=True).start()
    start_email_monitor(db, interval=15)  # check every 15s for new alerts

    print("🚀 Backend: http://localhost:5000")
    print("=" * 70)

    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)