import hashlib
import mimetypes
import os
import shutil
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

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


APP_STARTED_AT = datetime.utcnow()


# App setup
app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
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


def generate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_hash_from_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol


def hash_password(password: str) -> str:
    try:
        import bcrypt

        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    except Exception:
        return generate_password_hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        import bcrypt

        if hashed_password.startswith("$2"):
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        return check_password_hash(hashed_password, password)
    except Exception:
        return check_password_hash(hashed_password, password)


def generate_jwt_token(user_id, role):
    try:
        payload = {
            "user_id": user_id,
            "role": role,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
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


def build_preview_metadata(evidence_id, file_name):
    kind = infer_preview_kind(file_name)
    return {
        "supported": kind != "none",
        "kind": kind,
        "url": f"/api/evidence/{evidence_id}/file" if kind != "none" else None,
    }


def offline_tx_meta():
    return {
        "tx_hash": "OFFLINE-" + uuid.uuid4().hex[:16],
        "block_number": None,
        "timestamp": None,
        "status": "offline",
        "source": "fallback",
    }


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
    uptime_seconds = int((datetime.utcnow() - APP_STARTED_AT).total_seconds())

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
@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("../frontend", filename)


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
        return jsonify({"error": "Invalid request body"}), 400

    required = ["name", "email", "password", "password_confirm", "role"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    valid_roles = ["investigator", "analyst", "court_authority"]
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
        return jsonify({"error": "User not found"}), 404

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
        return jsonify({"error": "User not found"}), 404

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

    case_id = request.form.get("case_id", "CASE-UNKNOWN")
    description = request.form.get("description", "")

    evidence_id = "EV-" + uuid.uuid4().hex[:8].upper()
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
    stored_filename = timestamp_prefix + original_filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    with open(file_path, "wb") as out:
        out.write(file_bytes)

    tx_meta, bc_err = blockchain.add_evidence(evidence_id, file_hash, original_filename, case_id)
    if bc_err:
        app.logger.warning("Blockchain registration failed: %s", bc_err)
        tx_meta = offline_tx_meta()

    tx_hash = tx_meta["tx_hash"]

    db.save_evidence(
        evidence_id,
        original_filename,
        stored_filename,
        file_size,
        file_hash,
        case_id,
        description,
        session["user_id"],
        tx_hash,
    )

    db.add_custody_log(
        evidence_id,
        "Collected",
        session["user_id"],
        "Initial evidence upload and registration",
        tx_hash,
    )

    return jsonify(
        {
            "message": "Evidence uploaded successfully",
            "evidence_id": evidence_id,
            "file_hash": file_hash,
            "tx_hash": tx_hash,
            "blockchain_registered": bc_err is None,
            "blockchain_mode": "online" if bc_err is None else "fallback",
            "blockchain_error": bc_err,
            "tx_metadata": tx_meta,
            "preview": build_preview_metadata(evidence_id, original_filename),
            "max_size_mb": MAX_EVIDENCE_FILE_SIZE_MB,
        }
    ), 201


@app.route("/api/evidence", methods=["GET"])
@login_required
def list_evidence():
    evidence_list = db.get_all_evidence()
    enriched = []
    for item in evidence_list:
        row = dict(item)
        row["preview"] = build_preview_metadata(row["evidence_id"], row["file_name"])
        enriched.append(row)
    return jsonify(enriched)


@app.route("/api/evidence/<evidence_id>", methods=["GET"])
@login_required
def get_evidence(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": "Evidence not found"}), 404

    custody = db.get_custody_logs(evidence_id)
    bc_data, bc_err = blockchain.get_evidence(evidence_id)

    payload = dict(evidence)
    payload["preview"] = build_preview_metadata(evidence_id, payload["file_name"])
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
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": "Evidence not found"}), 404

    if not can_preview(evidence["file_name"]):
        return jsonify({"error": "Preview not supported for this file type"}), 415

    storage_name = evidence["file_path"]
    abs_path = os.path.join(UPLOAD_FOLDER, storage_name)
    if not os.path.exists(abs_path):
        return jsonify({"error": "Evidence file missing from storage"}), 404

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
    if "file" in request.files:
        file = request.files["file"]
        evidence_id = request.form.get("evidence_id")
        if not evidence_id:
            return jsonify({"error": "evidence_id required"}), 400
        data = file.read()
        current_hash = generate_hash_from_bytes(data)
    else:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid request body"}), 400
        evidence_id = body.get("evidence_id")
        if not evidence_id:
            return jsonify({"error": "evidence_id required"}), 400

        evidence = db.get_evidence_by_id(evidence_id)
        if not evidence:
            return jsonify({"error": "Evidence not found"}), 404

        file_path = os.path.join(UPLOAD_FOLDER, evidence["file_path"])
        if not os.path.exists(file_path):
            return jsonify({"error": "Evidence file missing from storage"}), 404

        current_hash = generate_file_hash(file_path)

    result, err = blockchain.verify_evidence(evidence_id, current_hash)
    if err:
        evidence = db.get_evidence_by_id(evidence_id)
        if not evidence:
            return jsonify({"error": "Evidence not found"}), 404
        stored_hash = evidence["file_hash"]
        intact = stored_hash.lower() == current_hash.lower()
        result = {
            "intact": intact,
            "stored_hash": stored_hash,
            "current_hash": current_hash,
            "evidence_id": evidence_id,
            "source": "database",
        }
    else:
        result["source"] = "blockchain"

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
        return jsonify({"error": "Invalid request body"}), 400

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
        return jsonify({"error": "Evidence not found"}), 404

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


@app.route("/api/evidence_history/<evidence_id>", methods=["GET"])
@login_required
def evidence_history(evidence_id):
    logs = db.get_custody_logs(evidence_id)
    bc_chain, _ = blockchain.get_custody_chain(evidence_id)
    return jsonify({"evidence_id": evidence_id, "db_logs": logs, "blockchain_logs": bc_chain})


@app.route("/api/dashboard/stats", methods=["GET"])
@login_required
def dashboard_stats():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

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
        return jsonify({"error": "User not found"}), 404

    limit_raw = request.args.get("limit", "12")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 12
    limit = max(1, min(limit, 50))

    if user["role"] == "admin":
        logs = db.get_recent_activity(limit=limit, user_id=None)
        scope = "global"
    else:
        logs = db.get_recent_activity(limit=limit, user_id=user["id"])
        scope = "personal"

    return jsonify({
        "scope": scope,
        "role": user["role"],
        "logs": logs,
    })


# Admin API
@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def admin_users():
    return jsonify(db.get_all_users())


@app.route("/api/admin/users/<int:user_id>/disable", methods=["POST"])
@role_required("admin")
def admin_disable_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Admin account cannot be disabled"}), 400
    if user["id"] == session.get("user_id"):
        return jsonify({"error": "You cannot disable your own account"}), 400

    updated = db.set_user_active(user_id, False)
    if not updated:
        return jsonify({"error": "Failed to disable user"}), 500
    return jsonify({"message": "User disabled"})


@app.route("/api/admin/users/<int:user_id>/enable", methods=["POST"])
@role_required("admin")
def admin_enable_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    updated = db.set_user_active(user_id, True)
    if not updated:
        return jsonify({"error": "Failed to enable user"}), 500
    return jsonify({"message": "User enabled"})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@role_required("admin")
def admin_delete_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
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
        return jsonify({"error": "Invalid request body"}), 400
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
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        host="0.0.0.0",
        port=port,
    )
