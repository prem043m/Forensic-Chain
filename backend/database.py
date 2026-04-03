import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///forensic.db")
if DATABASE_URL.startswith("sqlite:///"):
    sqlite_target = DATABASE_URL[len("sqlite:///") :]
    db_path = Path(sqlite_target)
    if not db_path.is_absolute():
        db_path = (PROJECT_ROOT / db_path).resolve()
    DB_PATH = str(db_path)
else:
    DB_PATH = str((PROJECT_ROOT / "backend" / "forensic.db").resolve())


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'investigator',
            wallet_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash TEXT NOT NULL,
            case_id TEXT,
            description TEXT,
            uploaded_by INTEGER,
            tx_hash TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS custody_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL,
            action TEXT NOT NULL,
            user_id INTEGER,
            note TEXT,
            tx_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    # Seed admin user if not exists
    from werkzeug.security import generate_password_hash
    cursor.execute("SELECT id FROM users WHERE email = 'admin@forensic.gov'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (name, email, password, role, wallet_address)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "System Admin",
            "admin@forensic.gov",
            generate_password_hash("admin123"),
            "admin",
            ""
        ))

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")


# ── Users ──────────────────────────────────────────────────────────────────

def create_user(name, email, password_hash, role, wallet_address=""):
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO users (name, email, password, role, wallet_address)
            VALUES (?, ?, ?, ?, ?)
        """, (name, email, password_hash, role, wallet_address))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_email(email):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    conn = get_db()
    users = conn.execute("SELECT id, name, email, role, created_at FROM users").fetchall()
    conn.close()
    return [dict(u) for u in users]


# ── Evidence ───────────────────────────────────────────────────────────────

def save_evidence(evidence_id, file_name, file_path, file_size, file_hash,
                  case_id, description, uploaded_by, tx_hash=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO evidence
            (evidence_id, file_name, file_path, file_size, file_hash,
             case_id, description, uploaded_by, tx_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (evidence_id, file_name, file_path, file_size, file_hash,
          case_id, description, uploaded_by, tx_hash))
    conn.commit()
    conn.close()


def get_all_evidence():
    conn = get_db()
    rows = conn.execute("""
        SELECT e.*, u.name as uploader_name, u.role as uploader_role
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        ORDER BY e.created_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_evidence_by_id(evidence_id):
    conn = get_db()
    row = conn.execute("""
        SELECT e.*, u.name as uploader_name
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        WHERE e.evidence_id = ?
    """, (evidence_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_evidence_status(evidence_id, status):
    conn = get_db()
    conn.execute("UPDATE evidence SET status = ? WHERE evidence_id = ?",
                 (status, evidence_id))
    conn.commit()
    conn.close()


# ── Custody Logs ───────────────────────────────────────────────────────────

def add_custody_log(evidence_id, action, user_id, note="", tx_hash=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO custody_logs (evidence_id, action, user_id, note, tx_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (evidence_id, action, user_id, note, tx_hash))
    conn.commit()
    conn.close()


def get_custody_logs(evidence_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT cl.*, u.name as actor_name, u.role as actor_role
        FROM custody_logs cl
        LEFT JOIN users u ON cl.user_id = u.id
        WHERE cl.evidence_id = ?
        ORDER BY cl.created_at ASC
    """, (evidence_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_custody_logs():
    conn = get_db()
    rows = conn.execute("""
        SELECT cl.*, u.name as actor_name
        FROM custody_logs cl
        LEFT JOIN users u ON cl.user_id = u.id
        ORDER BY cl.created_at DESC
        LIMIT 100
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM evidence").fetchone()["c"]
    verified = conn.execute(
        "SELECT COUNT(*) as c FROM evidence WHERE status='verified'"
    ).fetchone()["c"]
    tampered = conn.execute(
        "SELECT COUNT(*) as c FROM evidence WHERE status='tampered'"
    ).fetchone()["c"]
    users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    logs = conn.execute("SELECT COUNT(*) as c FROM custody_logs").fetchone()["c"]
    conn.close()
    return {
        "total_evidence": total,
        "verified": verified,
        "tampered": tampered,
        "total_users": users,
        "total_logs": logs
    }
