import os
from pathlib import Path

from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL not set")

DATABASE_URL = DATABASE_URL.strip()

print("Using DB:", DATABASE_URL)
ADMIN_NAME = os.getenv("ADMIN_NAME", "System Admin")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
VARCHAR_255 = "VARCHAR(255)"

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
            password_reset_token VARCHAR(255),
            password_reset_expiry TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            disabled_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Allow multiple admins so sensitive admin actions can require multi-approval.
    cursor.execute("DROP INDEX IF EXISTS users_single_admin_idx;")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash VARCHAR(128) NOT NULL,
            case_id VARCHAR(255),
            warrant_number VARCHAR(255),
            source_gps VARCHAR(255),
            source_device_id VARCHAR(255),
            description TEXT,
            uploaded_by INTEGER,
            tx_hash VARCHAR(255),
            status VARCHAR(50) DEFAULT 'active',
            is_private BOOLEAN NOT NULL DEFAULT FALSE,
            is_sealed BOOLEAN NOT NULL DEFAULT FALSE,
            sealed_by INTEGER,
            sealed_at TIMESTAMP,
            parent_evidence_id VARCHAR(64),
            witness_required_id INTEGER,
            witness_signed_by INTEGER,
            witness_signed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id),
            FOREIGN KEY (sealed_by) REFERENCES users(id),
            FOREIGN KEY (witness_required_id) REFERENCES users(id),
            FOREIGN KEY (witness_signed_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS evidence_file_hash_idx
        ON evidence (file_hash);
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_requests (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) NOT NULL,
            requester_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'pending',
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            FOREIGN KEY (requester_id) REFERENCES users(id),
            FOREIGN KEY (owner_id) REFERENCES users(id),
            FOREIGN KEY (reviewed_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS access_requests_lookup_idx
        ON access_requests (evidence_id, requester_id, status);
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verification_links (
            id SERIAL PRIMARY KEY,
            token_hash VARCHAR(128) UNIQUE NOT NULL,
            evidence_id VARCHAR(64) NOT NULL,
            created_by INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS verification_links_expiry_idx
        ON verification_links (expires_at);
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_actions (
            id SERIAL PRIMARY KEY,
            action_type VARCHAR(50) NOT NULL,
            target_user_id INTEGER NOT NULL,
            requested_by INTEGER NOT NULL,
            approved_by INTEGER,
            reason TEXT NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_at TIMESTAMP,
            FOREIGN KEY (target_user_id) REFERENCES users(id),
            FOREIGN KEY (requested_by) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS admin_actions_pending_idx
        ON admin_actions (status, action_type, target_user_id);
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS police_access_tokens (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) NOT NULL,
            token_hash VARCHAR(128) UNIQUE NOT NULL,
            issued_by INTEGER NOT NULL,
            note TEXT,
            expires_at TIMESTAMP NOT NULL,
            max_uses INTEGER NOT NULL DEFAULT 1,
            uses_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            FOREIGN KEY (issued_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS police_access_tokens_lookup_idx
        ON police_access_tokens (evidence_id, expires_at, uses_count);
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS police_access_grants (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) NOT NULL,
            grantee_id INTEGER NOT NULL,
            token_id INTEGER,
            granted_by INTEGER,
            note TEXT,
            tx_hash VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            FOREIGN KEY (grantee_id) REFERENCES users(id),
            FOREIGN KEY (token_id) REFERENCES police_access_tokens(id),
            FOREIGN KEY (granted_by) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS police_access_grants_lookup_idx
        ON police_access_grants (evidence_id, grantee_id);
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            event_type VARCHAR(80) NOT NULL,
            message TEXT NOT NULL,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS system_logs_user_time_idx
        ON system_logs (user_id, created_at DESC);
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_entries (
            id SERIAL PRIMARY KEY,
            evidence_id VARCHAR(64) NOT NULL,
            user_id INTEGER NOT NULL,
            source VARCHAR(60) NOT NULL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS access_entries_lookup_idx
        ON access_entries (evidence_id, user_id, created_at DESC);
    """)

    # Migration: Add new columns if they don't exist (for existing databases)
    def safe_alter_users(col_name, col_def):
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            conn.commit()
        except psycopg2.Error:
            conn.rollback()  # Rollback failed ALTER statement

    def safe_alter_evidence(col_name, col_def):
        try:
            cursor.execute(f"ALTER TABLE evidence ADD COLUMN {col_name} {col_def}")
            conn.commit()
        except psycopg2.Error:
            conn.rollback()
    
    safe_alter_users("password_reset_token", VARCHAR_255)
    safe_alter_users("password_reset_expiry", "TIMESTAMP")
    safe_alter_users("last_login", "TIMESTAMP")
    safe_alter_users("is_active", "BOOLEAN NOT NULL DEFAULT TRUE")
    safe_alter_users("disabled_at", "TIMESTAMP")

    safe_alter_evidence("warrant_number", VARCHAR_255)
    safe_alter_evidence("source_gps", VARCHAR_255)
    safe_alter_evidence("source_device_id", VARCHAR_255)
    safe_alter_evidence("is_private", "BOOLEAN NOT NULL DEFAULT FALSE")
    safe_alter_evidence("is_sealed", "BOOLEAN NOT NULL DEFAULT FALSE")
    safe_alter_evidence("sealed_by", "INTEGER")
    safe_alter_evidence("sealed_at", "TIMESTAMP")
    safe_alter_evidence("parent_evidence_id", "VARCHAR(64)")
    safe_alter_evidence("witness_required_id", "INTEGER")
    safe_alter_evidence("witness_signed_by", "INTEGER")
    safe_alter_evidence("witness_signed_at", "TIMESTAMP")

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
    cursor.execute("SELECT id, name, email, role, is_active, last_login, disabled_at, created_at FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return users


def get_non_admin_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, name, email, role, is_active, last_login, created_at
        FROM users
        WHERE role <> 'admin'
        ORDER BY name ASC
        """
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def set_user_active(user_id, is_active):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET is_active = %s,
                disabled_at = CASE WHEN %s THEN NULL ELSE CURRENT_TIMESTAMP END
            WHERE id = %s
            """,
            (is_active, is_active, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def can_delete_user(user_id):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE uploaded_by = %s", (user_id,))
        evidence_count = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) as c FROM custody_logs WHERE user_id = %s", (user_id,))
        logs_count = cursor.fetchone()["c"]
        return evidence_count == 0 and logs_count == 0, evidence_count, logs_count
    finally:
        conn.close()


def delete_user(user_id):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ── Evidence ───────────────────────────────────────────────────────────────

def save_evidence(
    evidence_id,
    file_name,
    file_path,
    file_size,
    file_hash,
    case_id,
    description,
    uploaded_by,
    tx_hash="",
    **metadata,
):
    warrant_number = metadata.get("warrant_number", "")
    source_gps = metadata.get("source_gps", "")
    source_device_id = metadata.get("source_device_id", "")
    is_private = bool(metadata.get("is_private", False))
    parent_evidence_id = metadata.get("parent_evidence_id")
    witness_required_id = metadata.get("witness_required_id")
    witness_signed_by = metadata.get("witness_signed_by")
    witness_signed_at = metadata.get("witness_signed_at")
    status = "pending_witness" if witness_required_id else "active"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO evidence
            (evidence_id, file_name, file_path, file_size, file_hash,
             case_id, warrant_number, source_gps, source_device_id,
             description, uploaded_by, tx_hash, status, is_private,
             parent_evidence_id, witness_required_id, witness_signed_by, witness_signed_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        evidence_id,
        file_name,
        file_path,
        file_size,
        file_hash,
        case_id,
        warrant_number,
        source_gps,
        source_device_id,
        description,
        uploaded_by,
        tx_hash,
        status,
        is_private,
        parent_evidence_id,
        witness_required_id,
        witness_signed_by,
        witness_signed_at,
    ))
    conn.commit()
    conn.close()


def get_all_evidence(user_id=None, role=None):
    conn = get_db()
    cursor = conn.cursor()
    if role and role != "admin" and user_id is not None:
        cursor.execute(
            """
            SELECT e.*, u.name as uploader_name, u.role as uploader_role
            FROM evidence e
            LEFT JOIN users u ON e.uploaded_by = u.id
            WHERE e.uploaded_by = %s
            ORDER BY e.created_at DESC
            """,
            (user_id,),
        )
    else:
        cursor.execute("""
            SELECT e.*, u.name as uploader_name, u.role as uploader_role
            FROM evidence e
            LEFT JOIN users u ON e.uploaded_by = u.id
            ORDER BY e.created_at DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_evidence_by_uploader(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT e.*, u.name as uploader_name, u.role as uploader_role
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        WHERE e.uploaded_by = %s
        ORDER BY e.created_at DESC
        """,
        (user_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_evidence_by_id(evidence_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.*, u.name as uploader_name, u.role as uploader_role
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        WHERE e.evidence_id = %s
    """, (evidence_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None


def get_evidence_by_hash(file_hash):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.*, u.name as uploader_name
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.id
        WHERE e.file_hash = %s
        ORDER BY e.created_at DESC
        LIMIT 1
    """, (file_hash,))
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


def update_evidence_file_path(evidence_id, file_path):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE evidence SET file_path = %s WHERE evidence_id = %s",
        (file_path, evidence_id),
    )
    conn.commit()
    conn.close()


def mark_evidence_witness_signed(evidence_id, witness_user_id, tx_hash):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE evidence
        SET witness_signed_by = %s,
            witness_signed_at = CURRENT_TIMESTAMP,
            tx_hash = %s,
            status = 'active'
        WHERE evidence_id = %s
        """,
        (witness_user_id, tx_hash, evidence_id),
    )
    conn.commit()
    conn.close()


def seal_evidence(evidence_id, sealed_by):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE evidence
        SET is_sealed = TRUE,
            sealed_by = %s,
            sealed_at = CURRENT_TIMESTAMP,
            status = 'sealed'
        WHERE evidence_id = %s
        """,
        (sealed_by, evidence_id),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def get_user_witness_candidates(exclude_user_id=None):
    conn = get_db()
    cursor = conn.cursor()
    if exclude_user_id is None:
        cursor.execute(
            """
            SELECT id, name, email, role
            FROM users
            WHERE is_active = TRUE AND role IN ('investigator', 'analyst', 'police')
            ORDER BY name ASC
            """
        )
    else:
        cursor.execute(
            """
            SELECT id, name, email, role
            FROM users
            WHERE is_active = TRUE
              AND role IN ('investigator', 'analyst', 'police')
              AND id <> %s
            ORDER BY name ASC
            """,
            (exclude_user_id,),
        )
    rows = cursor.fetchall()
    conn.close()
    return rows


def create_access_request(evidence_id, requester_id, owner_id, reason):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO access_requests (evidence_id, requester_id, owner_id, reason)
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """,
        (evidence_id, requester_id, owner_id, reason),
    )
    row = cursor.fetchone()
    conn.commit()
    conn.close()
    return row["id"] if row else None


def has_approved_access(evidence_id, requester_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id
        FROM access_requests
        WHERE evidence_id = %s
          AND requester_id = %s
          AND status = 'approved'
        ORDER BY reviewed_at DESC NULLS LAST
        LIMIT 1
        """,
        (evidence_id, requester_id),
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None


def get_access_requests_for_owner(owner_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT ar.*, ru.name AS requester_name, ru.role AS requester_role
        FROM access_requests ar
        LEFT JOIN users ru ON ru.id = ar.requester_id
        WHERE ar.owner_id = %s
        ORDER BY ar.created_at DESC
        """,
        (owner_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_access_request_by_id(request_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM access_requests WHERE id = %s", (request_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None


def review_access_request(request_id, status, reviewed_by):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE access_requests
        SET status = %s,
            reviewed_by = %s,
            reviewed_at = CURRENT_TIMESTAMP
        WHERE id = %s
        """,
        (status, reviewed_by, request_id),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def create_verification_link(token_hash, evidence_id, created_by, expires_at):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO verification_links (token_hash, evidence_id, created_by, expires_at)
        VALUES (%s, %s, %s, %s)
        """,
        (token_hash, evidence_id, created_by, expires_at),
    )
    conn.commit()
    conn.close()


def consume_verification_link(token_hash):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT *
        FROM verification_links
        WHERE token_hash = %s
          AND used_at IS NULL
          AND expires_at > CURRENT_TIMESTAMP
        LIMIT 1
        """,
        (token_hash,),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    cursor.execute(
        """
        UPDATE verification_links
        SET used_at = CURRENT_TIMESTAMP
        WHERE id = %s
        """,
        (row["id"],),
    )
    conn.commit()
    conn.close()
    return row


def create_admin_action(action_type, target_user_id, requested_by, reason):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO admin_actions (action_type, target_user_id, requested_by, reason)
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """,
        (action_type, target_user_id, requested_by, reason),
    )
    row = cursor.fetchone()
    conn.commit()
    conn.close()
    return row["id"] if row else None


def get_pending_admin_actions():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT aa.*,
               tu.name AS target_name,
               tu.role AS target_role,
               ru.name AS requested_by_name
        FROM admin_actions aa
        LEFT JOIN users tu ON tu.id = aa.target_user_id
        LEFT JOIN users ru ON ru.id = aa.requested_by
        WHERE aa.status = 'pending'
        ORDER BY aa.created_at DESC
        """
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def create_police_access_token(evidence_id, token_hash, issued_by, note, expires_at, max_uses=1):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO police_access_tokens (evidence_id, token_hash, issued_by, note, expires_at, max_uses)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (evidence_id, token_hash, issued_by, note, expires_at, max_uses),
    )
    row = cursor.fetchone()
    conn.commit()
    conn.close()
    return row["id"] if row else None


def use_police_access_token(evidence_id, token_hash):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT *
        FROM police_access_tokens
        WHERE evidence_id = %s
          AND token_hash = %s
          AND expires_at > CURRENT_TIMESTAMP
          AND uses_count < max_uses
        LIMIT 1
        """,
        (evidence_id, token_hash),
    )
    token_row = cursor.fetchone()
    if not token_row:
        conn.close()
        return None

    cursor.execute(
        """
        UPDATE police_access_tokens
        SET uses_count = uses_count + 1
        WHERE id = %s
        """,
        (token_row["id"],),
    )
    conn.commit()
    conn.close()
    return token_row


def add_police_access_grant(evidence_id, grantee_id, token_id, granted_by, note, tx_hash=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO police_access_grants (evidence_id, grantee_id, token_id, granted_by, note, tx_hash)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (evidence_id, grantee_id, token_id, granted_by, note, tx_hash),
    )
    conn.commit()
    conn.close()


def has_police_access_grant(evidence_id, grantee_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id
        FROM police_access_grants
        WHERE evidence_id = %s
          AND grantee_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (evidence_id, grantee_id),
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None


def add_access_entry(evidence_id, user_id, source, note=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO access_entries (evidence_id, user_id, source, note)
        VALUES (%s, %s, %s, %s)
        """,
        (evidence_id, user_id, source, note),
    )
    conn.commit()
    conn.close()


def has_access_entry(evidence_id, user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id
        FROM access_entries
        WHERE evidence_id = %s
          AND user_id = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (evidence_id, user_id),
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None


def get_touched_evidence_ids(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT evidence_id
        FROM custody_logs
        WHERE user_id = %s
        UNION
        SELECT evidence_id
        FROM evidence
        WHERE uploaded_by = %s
        """,
        (user_id, user_id),
    )
    rows = cursor.fetchall()
    conn.close()
    return [row["evidence_id"] for row in rows]


def add_system_log(user_id, event_type, message, metadata=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO system_logs (user_id, event_type, message, metadata)
        VALUES (%s, %s, %s, %s)
        """,
        (user_id, event_type, message, metadata),
    )
    conn.commit()
    conn.close()


def get_system_logs_for_user(user_id, limit=200):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT *
        FROM system_logs
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (user_id, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_recent_activity_for_touched_files(user_id, limit=20):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT cl.*, u.name as actor_name, u.role as actor_role
        FROM custody_logs cl
        LEFT JOIN users u ON cl.user_id = u.id
        WHERE cl.evidence_id IN (
            SELECT evidence_id FROM custody_logs WHERE user_id = %s
            UNION
            SELECT evidence_id FROM evidence WHERE uploaded_by = %s
        )
        ORDER BY cl.created_at DESC
        LIMIT %s
        """,
        (user_id, user_id, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def user_touched_evidence(evidence_id, user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT 1
        FROM evidence
        WHERE evidence_id = %s
          AND uploaded_by = %s
        LIMIT 1
        """,
        (evidence_id, user_id),
    )
    row = cursor.fetchone()
    if row:
        conn.close()
        return True

    cursor.execute(
        """
        SELECT 1
        FROM custody_logs
        WHERE evidence_id = %s
          AND user_id = %s
        LIMIT 1
        """,
        (evidence_id, user_id),
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None


def get_admin_timeline_by_user(limit=200):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT cl.*, u.name as actor_name, u.role as actor_role
        FROM custody_logs cl
        LEFT JOIN users u ON cl.user_id = u.id
        ORDER BY cl.created_at DESC
        LIMIT %s
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_admin_action_by_id(action_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_actions WHERE id = %s", (action_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None


def approve_admin_action(action_id, approver_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE admin_actions
        SET status = 'approved',
            approved_by = %s,
            approved_at = CURRENT_TIMESTAMP
        WHERE id = %s
          AND status = 'pending'
        """,
        (approver_id, action_id),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


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
    cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_active = TRUE")
    active_users = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_active = FALSE")
    disabled_users = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM custody_logs")
    logs = cursor.fetchone()["c"]
    conn.close()
    return {
        "total_evidence": total,
        "verified": verified,
        "tampered": tampered,
        "total_users": users,
        "active_users": active_users,
        "disabled_users": disabled_users,
        "total_logs": logs
    }


def get_user_stats(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE uploaded_by = %s", (user_id,))
    total = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE uploaded_by = %s AND status='verified'", (user_id,))
    verified = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE uploaded_by = %s AND status='tampered'", (user_id,))
    tampered = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) as c FROM custody_logs WHERE user_id = %s", (user_id,))
    logs = cursor.fetchone()["c"]
    conn.close()
    return {
        "total_evidence": total,
        "verified": verified,
        "tampered": tampered,
        "total_users": None,
        "total_logs": logs,
    }


def get_recent_activity(limit=20, user_id=None):
    conn = get_db()
    cursor = conn.cursor()
    if user_id is None:
        cursor.execute(
            """
            SELECT cl.*, u.name as actor_name, u.role as actor_role
            FROM custody_logs cl
            LEFT JOIN users u ON cl.user_id = u.id
            ORDER BY cl.created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
    else:
        cursor.execute(
            """
            SELECT cl.*, u.name as actor_name, u.role as actor_role
            FROM custody_logs cl
            LEFT JOIN users u ON cl.user_id = u.id
            WHERE cl.user_id = %s
            ORDER BY cl.created_at DESC
            LIMIT %s
            """,
            (user_id, limit),
        )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_suspicious_activity(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM (
            SELECT
                'tampered_evidence' AS type,
                e.evidence_id,
                COALESCE(u.name, 'Unknown') AS actor_name,
                COALESCE(u.role, 'unknown') AS actor_role,
                'Evidence status marked as tampered' AS details,
                e.created_at AS created_at
            FROM evidence e
            LEFT JOIN users u ON e.uploaded_by = u.id
            WHERE e.status = 'tampered'

            UNION ALL

            SELECT
                'tamper_detected_log' AS type,
                cl.evidence_id,
                COALESCE(u.name, 'Unknown') AS actor_name,
                COALESCE(u.role, 'unknown') AS actor_role,
                COALESCE(cl.note, cl.action) AS details,
                cl.created_at AS created_at
            FROM custody_logs cl
            LEFT JOIN users u ON cl.user_id = u.id
            WHERE cl.action = 'Tamper Detected'

            UNION ALL

            SELECT
                'offline_blockchain_fallback' AS type,
                cl.evidence_id,
                COALESCE(u.name, 'Unknown') AS actor_name,
                COALESCE(u.role, 'unknown') AS actor_role,
                'Blockchain offline fallback transaction recorded' AS details,
                cl.created_at AS created_at
            FROM custody_logs cl
            LEFT JOIN users u ON cl.user_id = u.id
            WHERE cl.tx_hash LIKE 'OFFLINE-%'
        ) suspicious
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


# ── Password Reset & Security ──────────────────────────────────────────────

def set_password_reset_token(email, token, expiry_hours=1):
    """Set password reset token for user"""
    conn = get_db()
    try:
        cursor = conn.cursor()
        from datetime import datetime, timedelta
        expiry = datetime.now() + timedelta(hours=expiry_hours)
        cursor.execute("""
            UPDATE users SET password_reset_token = %s, password_reset_expiry = %s
            WHERE email = %s
        """, (token, expiry, email))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def verify_reset_token(email, token):
    """Verify password reset token is valid"""
    from datetime import datetime
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM users 
            WHERE email = %s AND password_reset_token = %s 
            AND password_reset_expiry > %s
        """, (email, token, datetime.now()))
        return cursor.fetchone() is not None
    finally:
        conn.close()


def reset_password(email, new_password_hash):
    """Reset user password and clear reset token"""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET password = %s, password_reset_token = NULL, 
            password_reset_expiry = NULL
            WHERE email = %s
        """, (new_password_hash, email))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def update_last_login(user_id):
    """Update last login timestamp for user"""
    conn = get_db()
    try:
        from datetime import datetime
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET last_login = %s WHERE id = %s
        """, (datetime.now(), user_id))
        conn.commit()
    finally:
        conn.close()


def prevent_modify_immutable():
    """Placeholder - immutability removed"""
    return True
