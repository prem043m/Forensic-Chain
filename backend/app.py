import hashlib
import hmac
import mimetypes
import os
import shutil
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
import importlib

import jwt
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

if __package__:
    from . import database as db
    from .blockchain import blockchain
else:
    import database as db
    from blockchain import blockchain


FRONTEND_DIR = "../frontend"
ERR_INVALID_REQUEST_BODY = "Invalid request body"
ERR_USER_NOT_FOUND = "User not found"
ERR_EVIDENCE_NOT_FOUND = "Evidence not found"
ERR_EVIDENCE_ID_REQUIRED = "evidence_id required"
BCRYPT_AVAILABLE = importlib.util.find_spec("bcrypt") is not None


def now_utc():
    return datetime.now(timezone.utc)


APP_STARTED_AT = now_utc()


# App setup
app = Flask(__name__, static_folder=FRONTEND_DIR, template_folder=FRONTEND_DIR)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

MAX_EVIDENCE_FILE_SIZE_MB = int(os.environ.get("MAX_EVIDENCE_FILE_SIZE_MB", 25))
MAX_EVIDENCE_FILE_SIZE_BYTES = MAX_EVIDENCE_FILE_SIZE_MB * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_EVIDENCE_FILE_SIZE_BYTES

CORS(app, supports_credentials=True)


# Email configuration
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "noreply@forensicchain.com")
APP_URL = os.environ.get("APP_URL", "http://localhost:5000")
EMAILS_ENABLED = bool(SMTP_USERNAME and SMTP_PASSWORD)


# JWT configuration
JWT_SECRET = os.environ.get("JWT_SECRET", app.secret_key)
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", 8))


# Upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "evidence_storage")
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "pcap", "log",
    "zip", "tar", "gz", "img", "dd", "e01", "csv", "json", "xml"
}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg"}
PDF_EXTENSIONS = {"pdf"}
TEXT_EXTENSIONS = {"txt", "log", "csv", "json", "xml"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Init services
REQUIRE_DB = os.environ.get("REQUIRE_DB", "true").lower() == "true"

try:
    db.init_db()
except Exception:
    app.logger.exception("Database initialization failed. Check DATABASE_URL and PostgreSQL availability.")
    if REQUIRE_DB:
        raise

try:
    blockchain.connect()
except Exception:
    app.logger.exception("Blockchain initialization failed. App will continue in degraded mode.")


# Helpers

def send_email(recipient_email, subject, html_body):
    if not EMAILS_ENABLED:
        app.logger.warning("Email disabled. Would send to %s: %s", recipient_email, subject)
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

        return True
    except Exception as exc:
        app.logger.error("Failed to send email: %s", str(exc))
        return False


def send_login_notification(user_email, user_name):
    subject = "ForensicChain - Login Notification"
    html_body = f"""
    <html>
        <body>
            <h2>Login Alert</h2>
            <p>Hi {user_name},</p>
            <p>Your account was logged in at <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong>.</p>
            <p>If this wasn't you, please reset your password immediately.</p>
            <p>Best regards,<br>ForensicChain Team</p>
        </body>
    </html>
    """
    return send_email(user_email, subject, html_body)


def send_password_reset_email(user_email, reset_token):
    reset_link = f"{APP_URL}/reset-password.html?token={reset_token}&email={user_email}"
    subject = "ForensicChain - Password Reset Request"
    html_body = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password.</p>
            <p><a href=\"{reset_link}\" style=\"background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;\">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, you can ignore this email.</p>
            <p>Best regards,<br>ForensicChain Team</p>
        </body>
    </html>
    """
    return send_email(user_email, subject, html_body)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_extension(filename):
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def infer_preview_kind(filename):
    ext = get_extension(filename)
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in PDF_EXTENSIONS:
        return "pdf"
    if ext in TEXT_EXTENSIONS:
        return "text"
    return "none"


def can_preview(filename):
    return infer_preview_kind(filename) != "none"


def candidate_storage_names(evidence):
    candidates = []
    raw_name = (evidence.get("file_path") or "").strip()
    if raw_name:
        candidates.extend([raw_name, os.path.basename(raw_name)])

    original_name = (evidence.get("file_name") or "").strip()
    if original_name:
        candidates.append(original_name)
    return candidates, original_name


def find_existing_storage_file(candidates):
    seen = set()
    for name in candidates:
        normalized = (name or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)

        abs_path = os.path.join(UPLOAD_FOLDER, normalized)
        if os.path.exists(abs_path):
            return normalized, abs_path
    return None, None


def find_storage_file_by_suffix(original_name):
    if not original_name or not os.path.isdir(UPLOAD_FOLDER):
        return None, None

    lowered_original = original_name.lower()
    for entry in os.listdir(UPLOAD_FOLDER):
        entry_l = entry.lower()
        if entry_l == lowered_original or entry_l.endswith("_" + lowered_original):
            abs_path = os.path.join(UPLOAD_FOLDER, entry)
            if os.path.exists(abs_path):
                return entry, abs_path
    return None, None


def resolve_storage_file(evidence):
    """Resolve file path from DB to an existing file in storage.

    Returns tuple: (storage_name, absolute_path). When not found, returns (None, None).
    """
    candidates, original_name = candidate_storage_names(evidence)
    storage_name, abs_path = find_existing_storage_file(candidates)
    if abs_path:
        return storage_name, abs_path
    return find_storage_file_by_suffix(original_name)


def extract_upload_form_fields():
    return {
        "case_id": request.form.get("case_id", "").strip(),
        "warrant_number": request.form.get("warrant_number", "").strip(),
        "source_gps": request.form.get("source_gps", "").strip(),
        "source_device_id": request.form.get("source_device_id", "").strip(),
        "witness_user_id": request.form.get("witness_user_id", "").strip(),
        "is_private": parse_bool(request.form.get("is_private"), default=False),
        "description": request.form.get("description", ""),
    }


def validate_seizure_form_fields(form_fields):
    validations = {
        "case_id": "case_id is required for legal seizure protocol",
        "warrant_number": "warrant_number is required for legal seizure protocol",
        "source_gps": "source_gps is required for legal seizure protocol",
        "source_device_id": "source_device_id is required for legal seizure protocol",
        "witness_user_id": "witness_user_id is required for two-factor seizure",
    }
    for field, message in validations.items():
        if not form_fields.get(field):
            return jsonify({"error": message}), 400
    return None


def load_witness_or_error(witness_user_id, uploader_id):
    try:
        witness_user_id_int = int(witness_user_id)
    except ValueError:
        return None, None, (jsonify({"error": "witness_user_id must be a valid user id"}), 400)

    witness = db.get_user_by_id(witness_user_id_int)
    if not witness or not witness.get("is_active", True):
        return None, None, (jsonify({"error": "Selected witness is invalid or inactive"}), 400)
    if witness["id"] == uploader_id:
        return None, None, (jsonify({"error": "Witness must be a different user"}), 400)
    return witness_user_id_int, witness, None


def resolve_verify_input_or_error():
    if "file" in request.files:
        file = request.files["file"]
        evidence_id = request.form.get("evidence_id")
        if not evidence_id:
            return None, None, (jsonify({"error": ERR_EVIDENCE_ID_REQUIRED}), 400)
        return evidence_id, generate_hash_from_bytes(file.read()), None

    body = request.get_json()
    if not body:
        return None, None, (jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400)

    evidence_id = body.get("evidence_id")
    if not evidence_id:
        return None, None, (jsonify({"error": ERR_EVIDENCE_ID_REQUIRED}), 400)

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return None, None, (jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404)

    storage_name, file_path = resolve_storage_file(evidence)
    if not file_path:
        return None, None, (jsonify({"error": "Evidence file missing from storage"}), 404)

    if storage_name != (evidence.get("file_path") or ""):
        db.update_evidence_file_path(evidence_id, storage_name)

    return evidence_id, generate_file_hash(file_path), None


def db_fallback_verify_result(evidence_id, current_hash):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return None, (jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404)
    stored_hash = evidence["file_hash"]
    return {
        "intact": stored_hash.lower() == current_hash.lower(),
        "stored_hash": stored_hash,
        "current_hash": current_hash,
        "evidence_id": evidence_id,
        "source": "database",
    }, None


def append_system_timeline_events(timeline, system_logs, evidence_created_at):
    evidence_day = evidence_created_at.date() if evidence_created_at else None
    for entry in system_logs:
        ts = entry.get("created_at")
        if evidence_day and ts and ts.date() != evidence_day:
            continue
        timeline.append(
            {
                "type": "system",
                "label": entry.get("event_type") or "SYSTEM_EVENT",
                "message": entry.get("message") or "System event",
                "timestamp": ts,
            }
        )


def append_evidence_timeline_events(timeline, evidence_logs):
    for entry in evidence_logs:
        timeline.append(
            {
                "type": "evidence",
                "label": entry.get("action") or "Evidence Action",
                "message": entry.get("note") or "",
                "timestamp": entry.get("created_at"),
                "tx_hash": entry.get("tx_hash"),
                "actor_name": entry.get("actor_name"),
            }
        )


def append_blockchain_timeline_item(timeline, label, tx_meta, fallback_ts):
    if not tx_meta:
        return
    timestamp = datetime.fromtimestamp(tx_meta["timestamp"]) if tx_meta.get("timestamp") else fallback_ts
    timeline.append(
        {
            "type": "blockchain",
            "label": label,
            "message": f"Status={tx_meta.get('status')} Block={tx_meta.get('block_number')}",
            "timestamp": timestamp,
            "tx_hash": tx_meta.get("tx_hash"),
        }
    )


def iter_unique_custody_tx_hashes(evidence_logs, seen_txs):
    for entry in evidence_logs:
        tx_hash = entry.get("tx_hash")
        if not tx_hash or tx_hash in seen_txs:
            continue
        seen_txs.add(tx_hash)
        yield entry, tx_hash


def append_blockchain_timeline_events(timeline, evidence, evidence_logs):
    seen_txs = set()
    if evidence.get("tx_hash"):
        initial_hash = evidence["tx_hash"]
        seen_txs.add(initial_hash)
        tx_meta, _ = blockchain.get_transaction_info(initial_hash)
        append_blockchain_timeline_item(timeline, "Initial Registration", tx_meta, evidence.get("created_at"))

    for entry, tx_hash in iter_unique_custody_tx_hashes(evidence_logs, seen_txs):
        tx_meta, _ = blockchain.get_transaction_info(tx_hash)
        label = f"Blockchain: {entry.get('action') or 'Event'}"
        append_blockchain_timeline_item(timeline, label, tx_meta, entry.get("created_at"))


def generate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_hash_from_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol


def hash_password(password: str) -> str:
    if BCRYPT_AVAILABLE:
        bcrypt = importlib.import_module("bcrypt")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    return generate_password_hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    if BCRYPT_AVAILABLE:
        bcrypt = importlib.import_module("bcrypt")
        if hashed_password.startswith("$2"):
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    return check_password_hash(hashed_password, password)


def generate_jwt_token(user_id, role):
    try:
        issued_at = now_utc()
        payload = {
            "user_id": user_id,
            "role": role,
            "iat": issued_at,
            "exp": issued_at + timedelta(hours=JWT_EXPIRATION_HOURS),
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    except Exception as exc:
        app.logger.error("JWT generation failed: %s", str(exc))
        return None


def verify_jwt_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_jwt_from_request():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get("access_token")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "Authentication required"}), 401
            user = db.get_user_by_id(session["user_id"])
            if not user or user["role"] not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)

        return decorated

    return decorator


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_jwt_from_request()
        if not token:
            return jsonify({"error": "Missing authentication token"}), 401

        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        request.user_id = payload.get("user_id")
        request.user_role = payload.get("role")
        return f(*args, **kwargs)

    return decorated


def jwt_role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = get_jwt_from_request()
            if not token:
                return jsonify({"error": "Missing authentication token"}), 401

            payload = verify_jwt_token(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401

            user_role = payload.get("role")
            if user_role not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403

            request.user_id = payload.get("user_id")
            request.user_role = user_role
            return f(*args, **kwargs)

        return decorated

    return decorator


def build_preview_metadata(evidence_id, file_name, storage_name=None):
    kind = infer_preview_kind(file_name)
    storage_available = True
    if storage_name is not None:
        normalized_storage = str(storage_name).strip()
        storage_available = bool(normalized_storage) and os.path.exists(
            os.path.join(UPLOAD_FOLDER, normalized_storage)
        )

    preview_supported = kind != "none" and storage_available
    return {
        "supported": preview_supported,
        "kind": kind,
        "storage_available": storage_available,
        "url": f"/api/evidence/{evidence_id}/file" if preview_supported else None,
    }


def offline_tx_meta():
    return {
        "tx_hash": "OFFLINE-" + uuid.uuid4().hex[:16],
        "block_number": None,
        "timestamp": None,
        "status": "offline",
        "source": "fallback",
    }


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def user_can_access_evidence(user, evidence):
    if user["role"] in {"admin", "court_authority"}:
        return True

    if user["role"] == "police":
        # Police can always access their own uploads; cross-department access requires token grant.
        if int(evidence.get("uploaded_by") or 0) == int(user["id"]):
            return True
        return db.has_police_access_grant(evidence["evidence_id"], user["id"])

    if user["role"] in {"investigator", "analyst"}:
        if int(evidence.get("uploaded_by") or 0) == int(user["id"]):
            return True
        return db.has_approved_access(evidence["evidence_id"], user["id"])

    if not evidence.get("is_private"):
        return True

    if int(evidence.get("uploaded_by") or 0) == int(user["id"]):
        return True

    return db.has_approved_access(evidence["evidence_id"], user["id"])


def evidence_is_sealed(evidence):
    return bool(evidence and evidence.get("is_sealed"))


def get_system_health_snapshot():
    stats = db.get_stats()

    conn = None
    db_connected = False
    db_error = None
    try:
        conn = db.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_connected = True
    except Exception as exc:
        db_error = str(exc)
    finally:
        if conn is not None:
            conn.close()

    total_storage_bytes = 0
    if os.path.isdir(UPLOAD_FOLDER):
        for root, _, files in os.walk(UPLOAD_FOLDER):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    total_storage_bytes += os.path.getsize(file_path)
                except OSError:
                    continue

    disk_info = shutil.disk_usage(UPLOAD_FOLDER)
    uptime_seconds = int((now_utc() - APP_STARTED_AT).total_seconds())

    return {
        "status": "healthy" if db_connected else "degraded",
        "uptime_seconds": uptime_seconds,
        "database": {
            "connected": db_connected,
            "error": db_error,
        },
        "blockchain": {
            "connected": bool(blockchain.is_connected),
            "contract_address": blockchain.contract_address,
        },
        "users": {
            "total": stats.get("total_users", 0),
            "active": stats.get("active_users", 0),
            "disabled": stats.get("disabled_users", 0),
        },
        "evidence": {
            "total": stats.get("total_evidence", 0),
            "verified": stats.get("verified", 0),
            "tampered": stats.get("tampered", 0),
        },
        "storage": {
            "evidence_bytes": total_storage_bytes,
            "disk_total_bytes": disk_info.total,
            "disk_free_bytes": disk_info.free,
        },
    }


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(
        {
            "error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB",
            "max_size_mb": MAX_EVIDENCE_FILE_SIZE_MB,
        }
    ), 413


# Frontend routes
@app.route("/", methods=["GET"])
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>", methods=["GET"])
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/health", methods=["GET"])
def health():
    db_ok = False
    db_error = None

    conn = None
    try:
        conn = db.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_ok = True
    except Exception as exc:
        db_error = str(exc)
    finally:
        if conn is not None:
            conn.close()

    payload = {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "error",
        "blockchain_connected": bool(blockchain.is_connected),
    }
    if db_error:
        payload["database_error"] = db_error

    return jsonify(payload), 200 if db_ok else 503


# Auth API
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    required = ["name", "email", "password", "password_confirm", "role"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    valid_roles = ["investigator", "police", "analyst", "court_authority"]
    if data["role"] == "admin":
        return jsonify({"error": "Admin registration is disabled. Configure one private admin via environment variables."}), 403
    if data["role"] not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400

    if data["password"] != data["password_confirm"]:
        return jsonify({"error": "Passwords do not match"}), 400

    if not is_strong_password(data["password"]):
        return jsonify({"error": "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol"}), 400

    hashed = hash_password(data["password"])
    success = db.create_user(
        data["name"], data["email"], hashed, data["role"], data.get("wallet_address", "")
    )
    if not success:
        return jsonify({"error": "Email already registered"}), 409

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/api/users/witness-candidates", methods=["GET"])
@login_required
def witness_candidates():
    users = db.get_user_witness_candidates(exclude_user_id=session["user_id"])
    return jsonify(users)


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400

    user = db.get_user_by_email(data["email"])
    if not user or not verify_password(data["password"], user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.get("is_active", True):
        return jsonify({"error": "Account disabled. Contact administrator."}), 403

    session.permanent = True
    session["user_id"] = user["id"]
    session["role"] = user["role"]

    db.update_last_login(user["id"])
    db.add_system_log(
        user["id"],
        "USER_LOGIN",
        f"User logged in: {user['email']}",
        f"role={user['role']}",
    )
    send_login_notification(user["email"], user["name"])

    jwt_token = generate_jwt_token(user["id"], user["role"])
    if not jwt_token:
        return jsonify({"error": "Failed to generate authentication token"}), 500

    return jsonify(
        {
            "message": "Login successful",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "wallet_address": user["wallet_address"],
            },
            "token": jwt_token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
        }
    )


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        try:
            db.add_system_log(session["user_id"], "USER_LOGOUT", "User logged out", "")
        except Exception:
            app.logger.exception("Failed to persist logout system log")
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Email required"}), 400

    email = data["email"]
    user = db.get_user_by_email(email)

    if not user:
        return jsonify({"message": "If this email exists, a reset link has been sent"}), 200

    reset_token = secrets.token_urlsafe(32)
    if not db.set_password_reset_token(email, reset_token):
        return jsonify({"error": "Failed to initiate password reset"}), 500

    send_password_reset_email(email, reset_token)
    return jsonify({"message": "If this email exists, a reset link has been sent"}), 200


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password_confirm():
    data = request.get_json()
    if not data or "email" not in data or "token" not in data or "password" not in data:
        return jsonify({"error": "Email, token, and password required"}), 400

    email = data["email"]
    token = data["token"]
    password = data["password"]

    if not db.verify_reset_token(email, token):
        return jsonify({"error": "Invalid or expired reset token"}), 401

    if not is_strong_password(password):
        return jsonify({"error": "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol"}), 400

    hashed = hash_password(password)
    if not db.reset_password(email, hashed):
        return jsonify({"error": "Failed to reset password"}), 500

    return jsonify({"message": "Password reset successful"}), 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    return jsonify(
        {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "wallet_address": user["wallet_address"],
        }
    )


@app.route("/api/auth/validate-token", methods=["POST"])
@jwt_required
def validate_token():
    user = db.get_user_by_id(request.user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    return jsonify(
        {
            "valid": True,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
            },
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
        }
    )


@app.route("/api/auth/refresh-token", methods=["POST"])
@jwt_required
def refresh_token():
    new_token = generate_jwt_token(request.user_id, request.user_role)
    if not new_token:
        return jsonify({"error": "Failed to generate new token"}), 500

    return jsonify(
        {
            "token": new_token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
        }
    )


# Evidence API
@app.route("/api/upload_evidence", methods=["POST"])
@login_required
def upload_evidence():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    if user["role"] not in ["investigator", "police"]:
        return jsonify({"error": "Only police/investigator roles can initiate legal seizure uploads"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    original_filename = secure_filename(file.filename)
    if not original_filename:
        return jsonify({"error": "Invalid filename"}), 400

    file_bytes = file.read()
    file_size = len(file_bytes)
    if file_size > MAX_EVIDENCE_FILE_SIZE_BYTES:
        return jsonify({"error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB"}), 413

    file_hash = generate_hash_from_bytes(file_bytes)
    duplicate = db.get_evidence_by_hash(file_hash)
    if duplicate:
        return jsonify(
            {
                "error": "Duplicate evidence detected",
                "duplicate_evidence": {
                    "evidence_id": duplicate["evidence_id"],
                    "file_name": duplicate["file_name"],
                    "uploaded_at": duplicate["created_at"],
                    "case_id": duplicate.get("case_id"),
                },
            }
        ), 409

    form_fields = extract_upload_form_fields()
    form_error = validate_seizure_form_fields(form_fields)
    if form_error:
        return form_error

    witness_user_id_int, witness, witness_error = load_witness_or_error(
        form_fields["witness_user_id"],
        user["id"],
    )
    if witness_error:
        return witness_error

    evidence_id = "EV-" + uuid.uuid4().hex[:8].upper()
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
    stored_filename = timestamp_prefix + original_filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    with open(file_path, "wb") as out:
        out.write(file_bytes)

    tx_hash = "PENDING-WITNESS-" + uuid.uuid4().hex[:16]

    db.save_evidence(
        evidence_id,
        original_filename,
        stored_filename,
        file_size,
        file_hash,
        form_fields["case_id"],
        form_fields["description"],
        session["user_id"],
        tx_hash,
        warrant_number=form_fields["warrant_number"],
        source_gps=form_fields["source_gps"],
        source_device_id=form_fields["source_device_id"],
        is_private=form_fields["is_private"],
        witness_required_id=witness_user_id_int,
    )

    db.add_custody_log(
        evidence_id,
        "Seizure Initiated",
        session["user_id"],
        f"Seizure initiated under warrant {form_fields['warrant_number']}. Awaiting witness signature.",
        tx_hash,
    )

    return jsonify(
        {
            "message": "Seizure initiated. Awaiting witness attestation.",
            "evidence_id": evidence_id,
            "file_hash": file_hash,
            "tx_hash": tx_hash,
            "status": "pending_witness",
            "witness_required_id": witness_user_id_int,
            "witness_required_name": witness["name"],
            "seizure_metadata": {
                "case_id": form_fields["case_id"],
                "warrant_number": form_fields["warrant_number"],
                "source_gps": form_fields["source_gps"],
                "source_device_id": form_fields["source_device_id"],
                "is_private": form_fields["is_private"],
            },
            "preview": build_preview_metadata(evidence_id, original_filename),
            "max_size_mb": MAX_EVIDENCE_FILE_SIZE_MB,
        }
    ), 202


@app.route("/api/seizure/attest", methods=["POST"])
@login_required
def attest_seizure():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    evidence_id = data.get("evidence_id", "").strip()
    note = data.get("note", "").strip()
    if not evidence_id:
        return jsonify({"error": ERR_EVIDENCE_ID_REQUIRED}), 400

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if evidence.get("status") != "pending_witness":
        return jsonify({"error": "Evidence is not awaiting witness attestation"}), 409
    if int(evidence.get("witness_required_id") or 0) != int(session["user_id"]):
        return jsonify({"error": "Only the designated witness can attest this seizure"}), 403

    tx_meta, bc_err = blockchain.add_evidence(
        evidence_id,
        evidence["file_hash"],
        evidence["file_name"],
        evidence.get("case_id") or "CASE-UNKNOWN",
    )
    if bc_err:
        app.logger.warning("Witness attestation blockchain registration failed: %s", bc_err)
        tx_meta = offline_tx_meta()

    tx_hash = tx_meta["tx_hash"]
    db.mark_evidence_witness_signed(evidence_id, session["user_id"], tx_hash)

    tx_meta_transfer, bc_err_transfer = blockchain.transfer_evidence(
        evidence_id,
        "Witness Attested",
        note or "Witness attested seizure handshake",
    )
    if bc_err_transfer:
        tx_meta_transfer = offline_tx_meta()

    db.add_custody_log(
        evidence_id,
        "Witness Attested",
        session["user_id"],
        note or "Two-factor seizure handshake completed",
        tx_meta_transfer["tx_hash"],
    )

    return jsonify(
        {
            "message": "Witness attestation completed. Evidence is now on-chain.",
            "evidence_id": evidence_id,
            "tx_hash": tx_hash,
            "tx_metadata": tx_meta,
            "attestation_tx_metadata": tx_meta_transfer,
            "blockchain_registered": bc_err is None,
            "blockchain_error": bc_err,
        }
    )


@app.route("/api/evidence", methods=["GET"])
@login_required
def list_evidence():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    if user["role"] == "admin":
        evidence_list = db.get_all_evidence()
    else:
        evidence_list = db.get_evidence_by_uploader(user["id"])

    enriched = []
    for item in evidence_list:
        row = dict(item)
        row["preview"] = build_preview_metadata(row["evidence_id"], row["file_name"], row.get("file_path"))
        enriched.append(row)
    return jsonify(enriched)


@app.route("/api/evidence/<evidence_id>", methods=["GET"])
@login_required
def get_evidence(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not user_can_access_evidence(user, evidence):
        return jsonify({"error": "Access denied. Submit access request with legal reason."}), 403

    custody = db.get_custody_logs(evidence_id)
    bc_data, bc_err = blockchain.get_evidence(evidence_id)

    payload = dict(evidence)
    payload["preview"] = build_preview_metadata(evidence_id, payload["file_name"], payload.get("file_path"))
    tx_meta, tx_err = blockchain.get_transaction_info(payload.get("tx_hash") or "")
    payload["tx_metadata"] = tx_meta if tx_meta else {
        "tx_hash": payload.get("tx_hash"),
        "block_number": None,
        "timestamp": None,
        "status": "unknown",
        "source": "database",
        "error": tx_err,
    }

    custody_enriched = []
    for log in custody:
        row = dict(log)
        log_tx_meta, _ = blockchain.get_transaction_info(row.get("tx_hash") or "")
        if log_tx_meta:
            row["tx_metadata"] = log_tx_meta
        custody_enriched.append(row)

    return jsonify(
        {
            "evidence": payload,
            "custody_logs": custody_enriched,
            "blockchain": bc_data if bc_data else {"error": bc_err},
        }
    )


@app.route("/api/evidence/<evidence_id>/file", methods=["GET"])
@login_required
def serve_evidence_file(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not user_can_access_evidence(user, evidence):
        return jsonify({"error": "Access denied. Submit access request with legal reason."}), 403

    if not can_preview(evidence["file_name"]):
        return jsonify({"error": "Preview not supported for this file type"}), 415

    storage_name, abs_path = resolve_storage_file(evidence)
    if not abs_path:
        return jsonify({"error": "Evidence file missing from storage"}), 404

    # Auto-heal stale/dirty DB paths so next access is direct.
    if storage_name != (evidence.get("file_path") or ""):
        db.update_evidence_file_path(evidence_id, storage_name)

    mime_type, _ = mimetypes.guess_type(evidence["file_name"])
    response = send_from_directory(
        UPLOAD_FOLDER,
        storage_name,
        as_attachment=False,
        mimetype=mime_type or "application/octet-stream",
    )
    response.headers["Content-Disposition"] = f'inline; filename="{secure_filename(evidence["file_name"])}"'
    return response


@app.route("/api/verify_evidence", methods=["POST"])
@login_required
def verify_evidence():
    evidence_id, current_hash, input_error = resolve_verify_input_or_error()
    if input_error:
        return input_error

    result, err = blockchain.verify_evidence(evidence_id, current_hash)
    if err:
        result, fallback_error = db_fallback_verify_result(evidence_id, current_hash)
        if fallback_error:
            return fallback_error
    else:
        result["source"] = "blockchain"

    evidence = db.get_evidence_by_id(evidence_id)
    if evidence_is_sealed(evidence):
        result["sealed"] = True
    else:
        new_status = "verified" if result["intact"] else "tampered"
        db.update_evidence_status(evidence_id, new_status)
        db.add_custody_log(
            evidence_id,
            "Verified" if result["intact"] else "Tamper Detected",
            session["user_id"],
            f"Hash verification: {'PASSED' if result['intact'] else 'FAILED'}",
        )

    return jsonify(result)


@app.route("/api/transfer_evidence", methods=["POST"])
@login_required
def transfer_evidence():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    required = ["evidence_id", "action", "note"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400

    valid_actions = [
        "Collected",
        "Analyzed",
        "Transferred",
        "Verified",
        "Presented",
        "Stored",
        "Released",
        "Destroyed",
    ]
    if data["action"] not in valid_actions:
        return jsonify({"error": f"Invalid action. Use: {', '.join(valid_actions)}"}), 400

    evidence = db.get_evidence_by_id(data["evidence_id"])
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if evidence_is_sealed(evidence):
        return jsonify({"error": "Evidence is court-sealed and immutable"}), 423

    tx_meta, bc_err = blockchain.transfer_evidence(data["evidence_id"], data["action"], data["note"])
    if bc_err:
        tx_meta = offline_tx_meta()

    tx_hash = tx_meta["tx_hash"]

    db.add_custody_log(data["evidence_id"], data["action"], session["user_id"], data["note"], tx_hash)

    return jsonify(
        {
            "message": "Custody record added",
            "tx_hash": tx_hash,
            "blockchain_recorded": bc_err is None,
            "blockchain_mode": "online" if bc_err is None else "fallback",
            "blockchain_error": bc_err,
            "tx_metadata": tx_meta,
        }
    )


@app.route("/api/evidence/branch", methods=["POST"])
@role_required("analyst")
def branch_evidence():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    parent_evidence_id = request.form.get("parent_evidence_id", "").strip()
    if not parent_evidence_id:
        return jsonify({"error": "parent_evidence_id required"}), 400

    parent = db.get_evidence_by_id(parent_evidence_id)
    if not parent:
        return jsonify({"error": "Parent evidence not found"}), 404
    if evidence_is_sealed(parent):
        return jsonify({"error": "Parent evidence is sealed; no derived evidence can be created"}), 423

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    original_filename = secure_filename(file.filename)
    file_bytes = file.read()
    file_size = len(file_bytes)
    if file_size > MAX_EVIDENCE_FILE_SIZE_BYTES:
        return jsonify({"error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB"}), 413

    child_hash = generate_hash_from_bytes(file_bytes)
    child_id = "EV-" + uuid.uuid4().hex[:8].upper()
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
    stored_filename = timestamp_prefix + original_filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)
    with open(file_path, "wb") as out:
        out.write(file_bytes)

    tx_meta_add, bc_err_add = blockchain.add_evidence(
        child_id,
        child_hash,
        original_filename,
        parent.get("case_id") or "CASE-UNKNOWN",
    )
    if bc_err_add:
        tx_meta_add = offline_tx_meta()

    tx_meta_link, bc_err_link = blockchain.transfer_evidence(
        child_id,
        "Derived",
        f"ParentEvidence={parent_evidence_id};ParentHash={parent['file_hash']}",
    )
    if bc_err_link:
        tx_meta_link = offline_tx_meta()

    db.save_evidence(
        child_id,
        original_filename,
        stored_filename,
        file_size,
        child_hash,
        parent.get("case_id"),
        request.form.get("description", "Derived evidence artifact"),
        session["user_id"],
        tx_meta_add["tx_hash"],
        warrant_number=parent.get("warrant_number") or "",
        source_gps=parent.get("source_gps") or "",
        source_device_id=parent.get("source_device_id") or "",
        is_private=bool(parent.get("is_private")),
        parent_evidence_id=parent_evidence_id,
        witness_signed_by=session["user_id"],
    )

    db.add_custody_log(
        child_id,
        "Derived Evidence Created",
        session["user_id"],
        f"Derived from parent {parent_evidence_id} without altering original evidence",
        tx_meta_link["tx_hash"],
    )

    return jsonify(
        {
            "message": "Derived evidence branch created",
            "child_evidence_id": child_id,
            "parent_evidence_id": parent_evidence_id,
            "file_hash": child_hash,
            "tx_metadata": {
                "add": tx_meta_add,
                "link": tx_meta_link,
            },
            "blockchain_errors": {
                "add": bc_err_add,
                "link": bc_err_link,
            },
        }
    ), 201


@app.route("/api/evidence/<evidence_id>/request-access", methods=["POST"])
@login_required
def request_private_access(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not evidence.get("is_private"):
        return jsonify({"error": "Evidence is not private; no subpoena request needed"}), 400
    if int(evidence.get("uploaded_by") or 0) == int(user["id"]):
        return jsonify({"error": "Owner already has access"}), 400

    data = request.get_json() or {}
    reason = (data.get("reason") or "").strip()
    if len(reason) < 12:
        return jsonify({"error": "reason must be at least 12 characters"}), 400

    request_id = db.create_access_request(
        evidence_id,
        user["id"],
        evidence["uploaded_by"],
        reason,
    )

    db.add_custody_log(
        evidence_id,
        "Private Access Requested",
        user["id"],
        reason,
    )

    return jsonify({"message": "Access request submitted", "request_id": request_id}), 201


@app.route("/api/evidence/access-requests", methods=["GET"])
@login_required
def list_access_requests():
    return jsonify(db.get_access_requests_for_owner(session["user_id"]))


@app.route("/api/evidence/access-requests/<int:request_id>/review", methods=["POST"])
@login_required
def review_access_request(request_id):
    req = db.get_access_request_by_id(request_id)
    if not req:
        return jsonify({"error": "Access request not found"}), 404
    if int(req["owner_id"]) != int(session["user_id"]):
        return jsonify({"error": "Only evidence owner can review this request"}), 403
    if req["status"] != "pending":
        return jsonify({"error": "Request already reviewed"}), 409

    body = request.get_json() or {}
    decision = (body.get("decision") or "").strip().lower()
    if decision not in {"approved", "rejected"}:
        return jsonify({"error": "decision must be approved or rejected"}), 400

    db.review_access_request(request_id, decision, session["user_id"])
    db.add_custody_log(
        req["evidence_id"],
        "Private Access " + ("Approved" if decision == "approved" else "Rejected"),
        session["user_id"],
        req["reason"],
    )

    return jsonify({"message": f"Request {decision}"})


@app.route("/api/evidence/<evidence_id>/seal", methods=["POST"])
@role_required("court_authority")
def seal_evidence(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if evidence_is_sealed(evidence):
        return jsonify({"error": "Evidence already sealed"}), 409

    tx_meta, bc_err = blockchain.transfer_evidence(
        evidence_id,
        "Sealed",
        "Court-sealed final legal record",
    )
    if bc_err:
        tx_meta = offline_tx_meta()

    sealed = db.seal_evidence(evidence_id, session["user_id"])
    if not sealed:
        return jsonify({"error": "Failed to seal evidence"}), 500

    db.add_custody_log(
        evidence_id,
        "Sealed by Court",
        session["user_id"],
        "Evidence record is now immutable",
        tx_meta["tx_hash"],
    )

    return jsonify(
        {
            "message": "Evidence sealed",
            "evidence_id": evidence_id,
            "tx_metadata": tx_meta,
            "blockchain_error": bc_err,
        }
    )


@app.route("/api/evidence/<evidence_id>/verification-link", methods=["POST"])
@role_required("court_authority")
def create_public_verification_link(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    body = request.get_json() or {}
    expires_minutes = body.get("expires_minutes", 30)
    try:
        expires_minutes = int(expires_minutes)
    except ValueError:
        expires_minutes = 30
    expires_minutes = max(5, min(expires_minutes, 120))

    token = secrets.token_urlsafe(32)
    token_h = hash_token(token)
    expires_at = now_utc() + timedelta(minutes=expires_minutes)
    db.create_verification_link(token_h, evidence_id, session["user_id"], expires_at)

    return jsonify(
        {
            "verification_link": f"{APP_URL}/api/public/verify?token={token}",
            "expires_at": expires_at.isoformat() + "Z",
            "one_time": True,
            "evidence_id": evidence_id,
        }
    )


@app.route("/api/public/verify", methods=["GET", "POST"])
def public_verify_with_link():
    if request.method == "GET":
        token = (request.args.get("token") or "").strip()
    else:
        body = request.get_json(silent=True) or {}
        token = (body.get("token") or "").strip()

    if not token:
        return jsonify({"error": "token required"}), 400

    token_h = hash_token(token)
    link_row = db.consume_verification_link(token_h)
    if not link_row:
        return jsonify({"error": "Invalid, expired, or already-used token"}), 401

    evidence = db.get_evidence_by_id(link_row["evidence_id"])
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    if "file" in request.files:
        candidate_hash = generate_hash_from_bytes(request.files["file"].read())
    else:
        data = request.get_json(silent=True) or {}
        candidate_hash = (data.get("file_hash") or "").strip().lower()
        if not candidate_hash:
            return jsonify({"error": "Provide either a file upload or file_hash in JSON body"}), 400

    stored_hash = (evidence["file_hash"] or "").lower()
    intact = hmac.compare_digest(stored_hash, candidate_hash.lower())

    return jsonify(
        {
            "verified": intact,
            "evidence_id": evidence["evidence_id"],
            "case_id": evidence.get("case_id"),
            "note": "One-time verification completed",
        }
    )


@app.route("/api/evidence_history/<evidence_id>", methods=["GET"])
@login_required
def evidence_history(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    # Personal audit model for analyst/police/investigator: only files they touched.
    if user["role"] in {"analyst", "police", "investigator"} and not db.user_touched_evidence(evidence_id, user["id"]):
        return jsonify({"error": "Access denied. Personal audit scope only."}), 403

    logs = db.get_custody_logs(evidence_id)
    bc_chain, _ = blockchain.get_custody_chain(evidence_id)
    return jsonify({"evidence_id": evidence_id, "db_logs": logs, "blockchain_logs": bc_chain})


@app.route("/api/dashboard/stats", methods=["GET"])
@login_required
def dashboard_stats():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    if user["role"] == "admin":
        stats = db.get_stats()
        stats["scope"] = "global"
    else:
        stats = db.get_user_stats(user["id"])
        stats["scope"] = "personal"

    stats["role"] = user["role"]
    return jsonify(stats)


@app.route("/api/dashboard/activity", methods=["GET"])
@login_required
def dashboard_activity():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    limit_raw = request.args.get("limit", "12")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 12
    limit = max(1, min(limit, 50))

    if user["role"] in {"analyst", "police", "investigator"}:
        logs = db.get_recent_activity_for_touched_files(user["id"], limit=limit)
        scope = "personal"
    else:
        logs = db.get_recent_activity(limit=limit, user_id=None)
        scope = "global"

    return jsonify({
        "scope": scope,
        "role": user["role"],
        "logs": logs,
    })


@app.route("/api/evidence/<evidence_id>/access-token", methods=["POST"])
@role_required("admin", "court_authority")
def issue_police_access_token(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    body = request.get_json() or {}
    expires_minutes = body.get("expires_minutes", 30)
    max_uses = body.get("max_uses", 1)
    note = (body.get("note") or "Token-gated police access").strip()
    try:
        expires_minutes = int(expires_minutes)
    except ValueError:
        expires_minutes = 30
    try:
        max_uses = int(max_uses)
    except ValueError:
        max_uses = 1

    expires_minutes = max(5, min(expires_minutes, 240))
    max_uses = max(1, min(max_uses, 10))

    token = secrets.token_urlsafe(24)
    token_h = hash_token(token)
    expires_at = now_utc() + timedelta(minutes=expires_minutes)
    token_id = db.create_police_access_token(
        evidence_id,
        token_h,
        session["user_id"],
        note,
        expires_at,
        max_uses=max_uses,
    )
    if not token_id:
        return jsonify({"error": "Failed to issue access token"}), 500

    return jsonify(
        {
            "message": "Access token issued",
            "evidence_id": evidence_id,
            "token": token,
            "expires_at": expires_at.isoformat() + "Z",
            "max_uses": max_uses,
            "note": note,
        }
    ), 201


@app.route("/api/evidence/<evidence_id>/use-token", methods=["POST"])
@role_required("police")
def use_police_token(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    if int(evidence.get("uploaded_by") or 0) == int(session["user_id"]):
        return jsonify({"message": "Own evidence does not require token"}), 200

    body = request.get_json() or {}
    token = (body.get("token") or "").strip()
    if not token:
        return jsonify({"error": "token required"}), 400

    token_row = db.use_police_access_token(evidence_id, hash_token(token))
    if not token_row:
        return jsonify({"error": "Invalid/expired/exhausted token"}), 401

    note = token_row.get("note") or "Police token-gate access"
    tx_meta, bc_err = blockchain.transfer_evidence(
        evidence_id,
        "GrantAccess",
        f"PoliceTokenAccess by user={session['user_id']}; reason={note}",
    )
    if bc_err:
        tx_meta = offline_tx_meta()

    db.add_police_access_grant(
        evidence_id,
        session["user_id"],
        token_row["id"],
        token_row.get("issued_by"),
        note,
        tx_meta["tx_hash"],
    )

    db.add_custody_log(
        evidence_id,
        "GrantAccess",
        session["user_id"],
        f"Token-gate access granted: {note}",
        tx_meta["tx_hash"],
    )

    return jsonify(
        {
            "message": "Token accepted. Access granted.",
            "evidence_id": evidence_id,
            "tx_metadata": tx_meta,
            "blockchain_error": bc_err,
        }
    )


@app.route("/api/admin/timeline-by-user", methods=["GET"])
@role_required("admin")
def admin_timeline_by_user():
    limit_raw = request.args.get("limit", "200")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 200
    limit = max(20, min(limit, 500))

    logs = db.get_admin_timeline_by_user(limit=limit)
    grouped = {}
    for row in logs:
        actor_id = str(row.get("user_id") or "system")
        actor_key = f"{actor_id}:{row.get('actor_name') or 'System'}"
        if actor_key not in grouped:
            grouped[actor_key] = {
                "actor_id": row.get("user_id"),
                "actor_name": row.get("actor_name") or "System",
                "actor_role": row.get("actor_role") or "unknown",
                "events": [],
            }
        grouped[actor_key]["events"].append(dict(row))

    return jsonify({"groups": list(grouped.values()), "total_events": len(logs)})


@app.route("/api/admin/super-view/users", methods=["GET"])
@role_required("admin")
def admin_super_view_users():
    return jsonify(db.get_non_admin_users())


@app.route("/api/admin/super-view/<int:user_id>/folders", methods=["GET"])
@role_required("admin")
def admin_super_view_folders(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence_rows = db.get_evidence_by_uploader(user_id)
    tree = {}
    for item in evidence_rows:
        created = item.get("created_at")
        if created is None:
            continue
        year = f"{created.year:04d}"
        month = f"{created.month:02d}"
        day = f"{created.day:02d}"
        tree.setdefault(year, {})
        tree[year].setdefault(month, {})
        tree[year][month].setdefault(day, [])
        tree[year][month][day].append(
            {
                "evidence_id": item["evidence_id"],
                "file_name": item["file_name"],
                "status": item.get("status"),
                "created_at": item.get("created_at"),
            }
        )

    return jsonify({
        "user": {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"],
        },
        "folders": tree,
        "total_evidence": len(evidence_rows),
    })


@app.route("/api/admin/super-view/evidence/<evidence_id>/timeline", methods=["GET"])
@role_required("admin")
def admin_super_view_evidence_timeline(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    uploader_id = evidence.get("uploaded_by")
    system_logs = db.get_system_logs_for_user(uploader_id, limit=200) if uploader_id else []
    evidence_logs = db.get_custody_logs(evidence_id)

    timeline = []
    append_system_timeline_events(timeline, system_logs, evidence.get("created_at"))
    append_evidence_timeline_events(timeline, evidence_logs)
    append_blockchain_timeline_events(timeline, evidence, evidence_logs)

    timeline.sort(key=lambda x: x.get("timestamp") or datetime.min)

    return jsonify(
        {
            "evidence": {
                "evidence_id": evidence.get("evidence_id"),
                "file_name": evidence.get("file_name"),
                "uploaded_by": evidence.get("uploader_name"),
                "created_at": evidence.get("created_at"),
                "status": evidence.get("status"),
            },
            "timeline": timeline,
        }
    )


# Admin API
@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def admin_users():
    return jsonify(db.get_all_users())


@app.route("/api/admin/users/<int:user_id>/disable", methods=["POST"])
@role_required("admin")
def admin_disable_user(user_id):
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if len(reason) < 12:
        return jsonify({"error": "A detailed reason (min 12 chars) is required for deactivation request"}), 400

    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Admin account cannot be disabled"}), 400
    if user["role"] != "investigator":
        return jsonify({"error": "Multi-sig deactivation endpoint is restricted to investigator accounts"}), 400
    if user["id"] == session.get("user_id"):
        return jsonify({"error": "You cannot disable your own account"}), 400

    action_id = db.create_admin_action("deactivate_user", user_id, session["user_id"], reason)
    if not action_id:
        return jsonify({"error": "Failed to create admin action request"}), 500

    return jsonify(
        {
            "message": "Deactivation request created. Second admin approval required.",
            "action_id": action_id,
            "status": "pending",
        }
    ), 202


@app.route("/api/admin/users/<int:user_id>/enable", methods=["POST"])
@role_required("admin")
def admin_enable_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    updated = db.set_user_active(user_id, True)
    if not updated:
        return jsonify({"error": "Failed to enable user"}), 500
    return jsonify({"message": "User enabled"})


@app.route("/api/admin/actions/pending", methods=["GET"])
@role_required("admin")
def list_pending_admin_actions():
    return jsonify(db.get_pending_admin_actions())


@app.route("/api/admin/actions/<int:action_id>/approve", methods=["POST"])
@role_required("admin")
def approve_admin_action(action_id):
    action = db.get_admin_action_by_id(action_id)
    if not action:
        return jsonify({"error": "Admin action not found"}), 404
    if action["status"] != "pending":
        return jsonify({"error": "Action is no longer pending"}), 409
    if int(action["requested_by"]) == int(session["user_id"]):
        return jsonify({"error": "Requester cannot self-approve admin action"}), 403

    if action["action_type"] == "deactivate_user":
        target = db.get_user_by_id(action["target_user_id"])
        if not target:
            return jsonify({"error": "Target user not found"}), 404
        if target["role"] != "investigator":
            return jsonify({"error": "Target is no longer an investigator"}), 409

        updated = db.set_user_active(action["target_user_id"], False)
        if not updated:
            return jsonify({"error": "Failed to deactivate target user"}), 500
    else:
        return jsonify({"error": "Unsupported admin action type"}), 400

    approved = db.approve_admin_action(action_id, session["user_id"])
    if not approved:
        return jsonify({"error": "Failed to mark action as approved"}), 500

    return jsonify({"message": "Admin action approved and executed"})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@role_required("admin")
def admin_delete_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Admin account cannot be deleted"}), 400
    if user["id"] == session.get("user_id"):
        return jsonify({"error": "You cannot delete your own account"}), 400

    can_delete, evidence_count, logs_count = db.can_delete_user(user_id)
    if not can_delete:
        return jsonify({
            "error": "Cannot delete user with linked evidence or custody records. Disable instead.",
            "linked_evidence": evidence_count,
            "linked_logs": logs_count,
        }), 409

    deleted = db.delete_user(user_id)
    if not deleted:
        return jsonify({"error": "Failed to delete user"}), 500
    return jsonify({"message": "User deleted"})


@app.route("/api/admin/stats", methods=["GET"])
@role_required("admin")
def stats():
    return jsonify(db.get_stats())


@app.route("/api/admin/logs", methods=["GET"])
@role_required("admin")
def all_logs():
    return jsonify(db.get_all_custody_logs())


@app.route("/api/admin/suspicious-activity", methods=["GET"])
@role_required("admin")
def admin_suspicious_activity():
    limit_raw = request.args.get("limit", "50")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))
    return jsonify(db.get_suspicious_activity(limit=limit))


@app.route("/api/admin/system-health", methods=["GET"])
@role_required("admin")
def admin_system_health():
    return jsonify(get_system_health_snapshot())


@app.route("/api/blockchain/info", methods=["GET"])
@login_required
def blockchain_info():
    return jsonify(blockchain.get_network_info())


@app.route("/api/blockchain/deploy", methods=["POST"])
@role_required("admin")
def deploy_contract():
    address, err = blockchain.deploy_contract()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"message": "Contract deployed", "address": address})


@app.route("/api/blockchain/set_address", methods=["POST"])
@role_required("admin")
def set_contract_address():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400
    if "address" not in data:
        return jsonify({"error": "address required"}), 400

    success = blockchain.set_contract_address(data["address"])
    if not success:
        return jsonify({"error": "Invalid address"}), 400

    return jsonify({"message": "Contract address updated"})


if __name__ == "__main__":
    print("=" * 60)
    print("  ForensicChain - Blockchain Evidence Management System")
    print("=" * 60)
    print("  Server:     http://localhost:5000")
    print(f"  Blockchain: {blockchain.is_connected and 'Connected' or 'Not connected (offline mode)'}")
    print(f"  Contract:   {blockchain.contract_address or 'Not deployed'}")
    print("=" * 60)

    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        host=host,
        port=port,
    )
