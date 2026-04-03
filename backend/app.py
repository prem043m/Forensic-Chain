import os
import uuid
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, request, jsonify, session,
                   send_from_directory, render_template_string)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    from . import database as db
    from .blockchain import blockchain
except ImportError:
    import database as db
    from blockchain import blockchain

# ── App Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
CORS(app, supports_credentials=True)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "evidence_storage")
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "pcap", "log",
    "zip", "tar", "gz", "img", "dd", "e01", "csv", "json", "xml"
}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Init ───────────────────────────────────────────────────────────────────
db.init_db()
blockchain.connect()


# ── Helpers ────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_hash_from_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


# ── Frontend Routes ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("../frontend", filename)


# ── Auth API ───────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    required = ["name", "email", "password", "role"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    valid_roles = ["investigator", "analyst", "court_authority"]
    if data["role"] == "admin":
        current_user = db.get_user_by_id(session["user_id"]) if "user_id" in session else None
        if not current_user or current_user["role"] != "admin":
            return jsonify({"error": "Admin accounts can only be created by an existing admin"}), 403
        valid_roles.append("admin")
    if data["role"] not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400

    hashed = generate_password_hash(data["password"])
    success = db.create_user(
        data["name"], data["email"], hashed,
        data["role"], data.get("wallet_address", "")
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
    if not user or not check_password_hash(user["password"], data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    session.permanent = True
    session["user_id"] = user["id"]
    session["role"] = user["role"]

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "wallet_address": user["wallet_address"]
        }
    })


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "wallet_address": user["wallet_address"]
    })


# ── Evidence API ───────────────────────────────────────────────────────────

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

    case_id = request.form.get("case_id", "CASE-UNKNOWN")
    description = request.form.get("description", "")

    # Generate unique evidence ID
    evidence_id = "EV-" + uuid.uuid4().hex[:8].upper()
    filename = secure_filename(file.filename)
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
    stored_filename = timestamp_prefix + filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    file.save(file_path)
    file_size = os.path.getsize(file_path)
    file_hash = generate_file_hash(file_path)

    # Register on blockchain
    tx_hash, bc_err = blockchain.add_evidence(
        evidence_id, file_hash, filename, case_id
    )
    if bc_err:
        app.logger.warning(f"Blockchain registration failed: {bc_err}")
        tx_hash = "OFFLINE-" + uuid.uuid4().hex[:16]

    # Save to DB
    db.save_evidence(
        evidence_id, filename, stored_filename, file_size,
        file_hash, case_id, description, session["user_id"], tx_hash
    )

    # Add initial custody log
    db.add_custody_log(
        evidence_id, "Collected", session["user_id"],
        "Initial evidence upload and registration", tx_hash
    )

    return jsonify({
        "message": "Evidence uploaded successfully",
        "evidence_id": evidence_id,
        "file_hash": file_hash,
        "tx_hash": tx_hash,
        "blockchain_registered": bc_err is None
    }), 201


@app.route("/api/evidence", methods=["GET"])
@login_required
def list_evidence():
    evidence_list = db.get_all_evidence()
    return jsonify(evidence_list)


@app.route("/api/evidence/<evidence_id>", methods=["GET"])
@login_required
def get_evidence(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": "Evidence not found"}), 404

    custody = db.get_custody_logs(evidence_id)

    # Fetch from blockchain too
    bc_data, bc_err = blockchain.get_evidence(evidence_id)

    return jsonify({
        "evidence": evidence,
        "custody_logs": custody,
        "blockchain": bc_data if bc_data else {"error": bc_err}
    })


@app.route("/api/verify_evidence", methods=["POST"])
@login_required
def verify_evidence():
    """Verify evidence integrity by comparing hash with blockchain."""
    if "file" in request.files:
        # Verify by re-uploading file
        file = request.files["file"]
        evidence_id = request.form.get("evidence_id")
        if not evidence_id:
            return jsonify({"error": "evidence_id required"}), 400

        data = file.read()
        current_hash = generate_hash_from_bytes(data)
    else:
        # Verify stored file
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

    # Compare with blockchain
    result, err = blockchain.verify_evidence(evidence_id, current_hash)
    if err:
        # Fall back to DB comparison
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
            "source": "database"
        }
    else:
        result["source"] = "blockchain"

    # Update status
    new_status = "verified" if result["intact"] else "tampered"
    db.update_evidence_status(evidence_id, new_status)
    db.add_custody_log(
        evidence_id,
        "Verified" if result["intact"] else "Tamper Detected",
        session["user_id"],
        f"Hash verification: {'PASSED' if result['intact'] else 'FAILED'}"
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

    valid_actions = ["Collected", "Analyzed", "Transferred", "Verified",
                     "Presented", "Stored", "Released", "Destroyed"]
    if data["action"] not in valid_actions:
        return jsonify({"error": f"Invalid action. Use: {', '.join(valid_actions)}"}), 400

    evidence = db.get_evidence_by_id(data["evidence_id"])
    if not evidence:
        return jsonify({"error": "Evidence not found"}), 404

    tx_hash, bc_err = blockchain.transfer_evidence(
        data["evidence_id"], data["action"], data["note"]
    )
    if bc_err:
        tx_hash = "OFFLINE-" + uuid.uuid4().hex[:16]

    db.add_custody_log(
        data["evidence_id"], data["action"],
        session["user_id"], data["note"], tx_hash
    )

    return jsonify({
        "message": "Custody record added",
        "tx_hash": tx_hash,
        "blockchain_recorded": bc_err is None
    })


@app.route("/api/evidence_history/<evidence_id>", methods=["GET"])
@login_required
def evidence_history(evidence_id):
    logs = db.get_custody_logs(evidence_id)
    bc_chain, _ = blockchain.get_custody_chain(evidence_id)
    return jsonify({
        "evidence_id": evidence_id,
        "db_logs": logs,
        "blockchain_logs": bc_chain
    })


# ── Admin API ──────────────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def admin_users():
    return jsonify(db.get_all_users())


@app.route("/api/admin/stats", methods=["GET"])
@role_required("admin")
def stats():
    return jsonify(db.get_stats())


@app.route("/api/admin/logs", methods=["GET"])
@role_required("admin")
def all_logs():
    return jsonify(db.get_all_custody_logs())


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


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  ForensicChain — Blockchain Evidence Management System")
    print("=" * 60)
    print(f"  Server:     http://localhost:5000")
    print(f"  Blockchain: {blockchain.is_connected and 'Connected' or 'Not connected (offline mode)'}")
    print(f"  Contract:   {blockchain.contract_address or 'Not deployed'}")
    print("=" * 60)
    port = int(os.environ.get("PORT", 5000))
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        host="0.0.0.0",
        port=port,
    )
