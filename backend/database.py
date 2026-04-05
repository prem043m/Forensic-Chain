import os
from pathlib import Path

from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/forensic_chain"
)
ADMIN_NAME = os.getenv("ADMIN_NAME", "System Admin")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# Some providers export postgres://, psycopg2 expects postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL.startswith("sqlite://"):
    raise ValueError(
        "Invalid DATABASE_URL for PostgreSQL mode. Received SQLite DSN. "
        "Set DATABASE_URL to a postgresql:// connection string."
    )


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'investigator',
            wallet_address VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Enforce exactly one admin account at database level.
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS users_single_admin_idx
        ON users ((role))
        WHERE role = 'admin';
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash VARCHAR(128) NOT NULL,
            case_id VARCHAR(255),
            description TEXT,
            uploaded_by INTEGER,
            tx_hash VARCHAR(255),
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS custody_logs (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) NOT NULL,
            action VARCHAR(100) NOT NULL,
            user_id INTEGER,
            note TEXT,
            tx_hash VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    # Seed one private admin user if not exists and credentials are provided.
    from werkzeug.security import generate_password_hash
    cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not cursor.fetchone() and ADMIN_EMAIL and ADMIN_PASSWORD:
        cursor.execute("""
            INSERT INTO users (name, email, password, role, wallet_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            ADMIN_NAME,
            ADMIN_EMAIL,
            generate_password_hash(ADMIN_PASSWORD),
            "admin",
            ""
        ))
    elif not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("[DB] Admin user not auto-created. Set ADMIN_EMAIL and ADMIN_PASSWORD in environment.")

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")


# ── Users ──────────────────────────────────────────────────────────────────

def create_user(name, email, password_hash, role, wallet_address=""):
    conn = get_db()
    try:
        conn.cursor().execute("""
            INSERT INTO users (name, email, password, role, wallet_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, password_hash, role, wallet_address))
        conn.commit()
        return True
    except psycopg2.IntegrityError:
        conn.rollback()
        return False
    finally:
        conn.close()


def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()
    return user if user else None


def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user if user else None


def get_all_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, role, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    return users


# ── Evidence ───────────────────────────────────────────────────────────────

def save_evidence(evidence_id, file_name, file_path, file_size, file_hash,
                  case_id, description, uploaded_by, tx_hash=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO evidence
            (evidence_id, file_name, file_path, file_size, file_hash,
             case_id, description, uploaded_by, tx_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (evidence_id, file_name, file_path, file_size, file_hash,
          case_id, description, uploaded_by, tx_hash))
    conn.commit()
    conn.close()


def get_all_evidence():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.*, u.name as uploader_name, u.role as uploader_role
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        ORDER BY e.created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_evidence_by_id(evidence_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.*, u.name as uploader_name
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        WHERE e.evidence_id = %s
    """, (evidence_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None


def update_evidence_status(evidence_id, status):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET status = %s WHERE evidence_id = %s",
                 (status, evidence_id))
    conn.commit()
    conn.close()


# ── Custody Logs ───────────────────────────────────────────────────────────

def add_custody_log(evidence_id, action, user_id, note="", tx_hash=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO custody_logs (evidence_id, action, user_id, note, tx_hash)
        VALUES (%s, %s, %s, %s, %s)
    """, (evidence_id, action, user_id, note, tx_hash))
    conn.commit()
    conn.close()


def get_custody_logs(evidence_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cl.*, u.name as actor_name, u.role as actor_role
        FROM custody_logs cl
        LEFT JOIN users u ON cl.user_id = u.id
        WHERE cl.evidence_id = %s
        ORDER BY cl.created_at ASC
    """, (evidence_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_custody_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cl.*, u.name as actor_name
        FROM custody_logs cl
        LEFT JOIN users u ON cl.user_id = u.id
        ORDER BY cl.created_at DESC
        LIMIT 100
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_stats():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM evidence")
    total = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE status='verified'")
    verified = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE status='tampered'")
    tampered = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM users")
    users = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM custody_logs")
    logs = cursor.fetchone()["c"]
    conn.close()
    return {
        "total_evidence": total,
        "verified": verified,
        "tampered": tampered,
        "total_users": users,
        "total_logs": logs
    }
