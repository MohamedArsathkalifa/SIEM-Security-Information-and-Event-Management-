import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class Database:

    def _normalize_log(self, log):
        if isinstance(log, dict):
            return type("Obj", (), log)
        return log

    def __init__(self, db_name="siem.db"):
        self.db_name = db_name

    def connect(self):
        return sqlite3.connect(self.db_name, check_same_thread=False)

    def initialize(self):
        con = self.connect()
        cur = con.cursor()

        # --- LOGS TABLE ---
        cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            severity TEXT,
            event_type TEXT,
            description TEXT
        )
        """)

        # --- ALERTS TABLE ---
        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            source_ip TEXT,
            description TEXT
        )
        """)

        # --- USERS TABLE ---
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            email     TEXT UNIQUE NOT NULL,
            created_at TEXT
        )
        """)

        # Seed default admin if not exists
        cur.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO users (username, password, email, created_at)
            VALUES (?, ?, ?, ?)
            """, (
                'admin',
                generate_password_hash('arsath'),
                'admin@siem.local',
                datetime.utcnow().isoformat()
            ))


        # =================== MALWARE SCANS TABLE (NEW - ADDITION ONLY) ===================
        cur.execute("""
        CREATE TABLE IF NOT EXISTS malware_scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_timestamp TEXT NOT NULL,
            total_threats INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            scan_results TEXT,
            platform TEXT,
            scan_duration REAL,
            created_at TEXT DEFAULT (datetime('now'))
        )
        """)
        
        cur.execute("CREATE INDEX IF NOT EXISTS idx_malware_scans_timestamp ON malware_scans(scan_timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_malware_scans_critical ON malware_scans(critical_count)")
        
        print("✅ Malware scans table initialized")

        con.commit()
        con.close()

    # =================== USER METHODS ===================

    def create_user(self, username, password, email):
        """Returns (True, None) on success or (False, error_msg) on failure."""
        try:
            con = self.connect()
            cur = con.cursor()
            cur.execute("""
            INSERT INTO users (username, password, email, created_at)
            VALUES (?, ?, ?, ?)
            """, (
                username,
                generate_password_hash(password),
                email,
                datetime.utcnow().isoformat()
            ))
            con.commit()
            con.close()
            return True, None
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return False, 'Username already exists'
            if 'email' in str(e):
                return False, 'Email already registered'
            return False, 'Registration failed'

    def get_user(self, username):
        """Return user row dict or None."""
        con = self.connect()
        cur = con.cursor()
        row = cur.execute(
            "SELECT user_id, username, password, email, created_at FROM users WHERE username=?",
            (username,)
        ).fetchone()
        con.close()
        if not row:
            return None
        return {
            'user_id': row[0],
            'username': row[1],
            'password': row[2],
            'email': row[3],
            'created_at': row[4]
        }

    def verify_user(self, username, password):
        """Returns user dict if credentials valid, else None."""
        user = self.get_user(username)
        if user and check_password_hash(user['password'], password):
            return user
        return None

    def get_all_users(self):
        """Return list of users (no passwords)."""
        con = self.connect()
        cur = con.cursor()
        rows = cur.execute(
            "SELECT user_id, username, email, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        con.close()
        return [{'user_id': r[0], 'username': r[1], 'email': r[2], 'created_at': r[3]} for r in rows]

    def update_password(self, username, new_password):
        """Update a user's password."""
        con = self.connect()
        cur = con.cursor()
        cur.execute(
            "UPDATE users SET password=? WHERE username=?",
            (generate_password_hash(new_password), username)
        )
        updated = cur.rowcount
        con.commit()
        con.close()
        return updated > 0

    # =================== LOG METHODS ===================

    def insert_log(self, log):
        con = self.connect()
        cur = con.cursor()
        cur.execute("""
        INSERT INTO logs (timestamp, source_ip, severity, event_type, description)
        VALUES (?, ?, ?, ?, ?)
        """, (
            log.get("timestamp", datetime.utcnow().isoformat()),
            log.get("source_ip", "unknown"),
            log.get("severity", "LOW"),
            log.get("event_type", "unknown"),
            log.get("description", "")
        ))
        con.commit()
        con.close()

    def insert_alert(self, alert):
        con = self.connect()
        cur = con.cursor()
        cur.execute("""
        INSERT INTO alerts (timestamp, severity, source_ip, description)
        VALUES (?, ?, ?, ?)
        """, (
            alert.get("timestamp", datetime.utcnow().isoformat()),
            alert.get("severity", "LOW"),
            alert.get("source_ip", "unknown"),
            alert.get("description", "")
        ))
        con.commit()
        con.close()

    # =================== STATS ===================

    def get_statistics(self):
        con = self.connect()
        cur = con.cursor()
        total_logs = cur.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        total_alerts = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical_alerts = cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
        con.close()
        return {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "last_updated": datetime.utcnow().isoformat()
        }

    # =================== LOGS (WITH FILTERS) ===================

    def get_logs(self, page, size, severity=None, source_ip=None):
        offset = (page - 1) * size
        con = self.connect()
        cur = con.cursor()
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if source_ip:
            query += " AND source_ip LIKE ?"
            params.append(f"%{source_ip}%")
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([size, offset])
        rows = cur.execute(query, params).fetchall()
        logs = [{"event_id": r[0], "timestamp": r[1], "source_ip": r[2],
                 "severity": r[3], "event_type": r[4], "description": r[5]} for r in rows]
        total = cur.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        con.close()
        return {"logs": logs, "page": page, "size": size, "total": total}

    # =================== ALERTS ===================

    def get_alerts(self):
        con = self.connect()
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
        con.close()
        return [{"alert_id": r[0], "timestamp": r[1], "severity": r[2],
                 "source_ip": r[3], "description": r[4]} for r in rows]

    # =================== THREAT INTEL ===================

    def get_threat_intelligence(self):
        con = self.connect()
        cur = con.cursor()
        rows = cur.execute("""
        SELECT event_type, COUNT(*) FROM logs GROUP BY event_type ORDER BY COUNT(*) DESC
        """).fetchall()
        con.close()
        return [{"threat": r[0], "count": r[1]} for r in rows]

    # =================== EVENT DETAILS ===================

    def get_event_by_id(self, event_id):
        con = self.connect()
        cur = con.cursor()
        row = cur.execute("SELECT * FROM logs WHERE event_id=?", (event_id,)).fetchone()
        con.close()
        if not row:
            return None
        return {"event_id": row[0], "timestamp": row[1], "source_ip": row[2],
                "severity": row[3], "event_type": row[4], "description": row[5]}

    def get_related_events(self, event_id):
        con = self.connect()
        cur = con.cursor()
        row = cur.execute("SELECT source_ip FROM logs WHERE event_id=?", (event_id,)).fetchone()
        if not row:
            return []
        ip = row[0]
        rows = cur.execute("""
        SELECT * FROM logs WHERE source_ip=? AND event_id!=?
        ORDER BY timestamp DESC LIMIT 10
        """, (ip, event_id)).fetchall()
        con.close()
        return [{"event_id": r[0], "timestamp": r[1], "source_ip": r[2],
                 "severity": r[3], "event_type": r[4], "description": r[5]} for r in rows]

    def get_event_distribution_last_hour(self):
        con = self.connect()
        cur = con.cursor()
        cur.execute("""
        SELECT severity, COUNT(*) FROM logs
        WHERE timestamp >= datetime('now', '-1 hour')
        GROUP BY severity
        """)
        rows = cur.fetchall()
        con.close()
        data = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for sev, count in rows:
            data[sev] = count
        return data
