# ForensicChain — Blockchain-Based Digital Forensics Evidence Management

A full-stack system for managing digital forensic evidence with tamper detection,
chain of custody tracking, and distributed blockchain verification using Ethereum (Ganache).

---

## Project Structure

```
forensic-blockchain/
│
├── contracts/
│   ├── Evidence.sol            # Solidity smart contract
│   └── Evidence_abi.json       # Generated ABI (after deploy)
│
├── backend/
│   ├── app.py                  # Flask REST API (main entry point)
│   ├── blockchain.py           # Web3.py blockchain interaction layer
│   ├── database.py             # PostgreSQL database helpers
│   ├── requirements.txt        # Python dependencies
│   └── contract_address.txt    # Deployed contract address
│
├── frontend/
│   ├── index.html              # Login / Register page
│   └── dashboard.html          # Full dashboard (evidence, verify, custody)
│
├── evidence_storage/           # Uploaded evidence files stored here
│
└── migrations/
    └── deploy.py               # Contract compile + deploy script
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.9+ | https://python.org |
| Node.js | (optional, for Ganache CLI) | https://nodejs.org |
| Ganache | Desktop or CLI | https://trufflesuite.com/ganache/ |
| pip | latest | included with Python |

---

## Step 1 — Install Python Dependencies

```bash
cd forensic-blockchain/backend
pip install -r requirements.txt
```

This installs:
- `flask` — web framework
- `flask-cors` — cross-origin support
- `web3` — Ethereum Python library
- `werkzeug` — security utilities
- `py-solc-x` — Solidity compiler (for deployment)

---

## Step 2 — Start Ganache 

### Option A: Ganache Desktop (Recommended)
1. Download from https://trufflesuite.com/ganache/
2. Create a new **Quickstart** workspace
3. Default RPC: `http://127.0.0.1:7545`
4. Keep it running

### Option B: Ganache CLI
```bash
npm install -g ganache
ganache --port 7545
```

---

## Step 3 — Deploy Smart Contract

```bash
cd forensic-blockchain
python migrations/deploy.py
```

This will:
1. Compile `contracts/Evidence.sol` using solc 0.8.0
2. Deploy to Ganache at `http://127.0.0.1:7545`
3. Save the contract address to `backend/contract_address.txt`
4. Save the ABI to `contracts/Evidence_abi.json`

Expected output:
```
[1/4] Connecting to Ganache at http://127.0.0.1:7545...
  Connected! Block #0
  Using account: 0xYourAddress...
[2/4] Compiling Evidence.sol...
  Compiled successfully.
[3/4] Deploying contract...
  Deployed at: 0xContractAddress...
[4/4] Saving artifacts...
Deployment complete!
```

---

## Step 4 — Start the Backend Server

```bash
cd forensic-blockchain/backend
python app.py
```

Server starts at: **http://localhost:5000**

On first run it will:
- Connect to PostgreSQL using `DATABASE_URL`
- Create all tables
- Seed one private admin account only when `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set

---

## Step 5 — Open the Application

Open your browser to: **http://localhost:5000**

### Private Admin Setup
Set a private admin identity in environment variables before first run:

| Variable | Description |
|----------|-------------|
| `ADMIN_NAME` | Admin display name (optional, default: `System Admin`) |
| `ADMIN_EMAIL` | Private admin login email |
| `ADMIN_PASSWORD` | Private admin password |

Notes:
- Only one admin account is allowed.
- Admin registration from the public register API is disabled.

---

## Demo Scenario (Tamper Detection)

Follow these steps to demonstrate the full tamper detection workflow:

**Step 1 — Login**
Login as admin at http://localhost:5000

**Step 2 — Upload Evidence**
- Go to **Upload Evidence**
- Select any file (e.g., a `.txt` or `.log` file)
- Enter a Case ID like `CASE-2024-001`
- Click **Register on Blockchain & Upload**
- Note the **Evidence ID** (e.g., `EV-A1B2C3D4`)

**Step 3 — Verify (Should Pass)**
- Go to **Verify Evidence**
- Enter the Evidence ID
- Click **Verify Stored File**
- Result: ✓ Evidence Intact — hashes match

**Step 4 — Tamper the File**
- Navigate to `evidence_storage/`
- Open the stored file and modify its contents (add a character, etc.)
- Save the file

**Step 5 — Verify Again (Should Fail)**
- Go to **Verify Evidence**
- Enter the same Evidence ID
- Click **Verify Stored File**
- Result: ✗ Tamper Detected — hash mismatch

The blockchain hash never changed — only the file changed. This proves the
tamper detection is working correctly.

---

## API Reference

All endpoints require session authentication (login first).

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Get current user |

### Evidence
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload_evidence` | Upload file, register on blockchain |
| GET | `/api/evidence` | List all evidence |
| GET | `/api/evidence/<id>` | Get evidence detail + custody logs |
| POST | `/api/verify_evidence` | Verify hash integrity |
| POST | `/api/transfer_evidence` | Add custody action |
| GET | `/api/evidence_history/<id>` | Full custody chain |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | All users (admin only) |
| GET | `/api/admin/stats` | System statistics |
| GET | `/api/admin/logs` | All custody logs |

### Blockchain
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/blockchain/info` | Network status |
| POST | `/api/blockchain/deploy` | Deploy contract (admin) |
| POST | `/api/blockchain/set_address` | Set contract address (admin) |

### Health
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Deployment health check (DB connectivity + blockchain flag) |

---

## User Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access, user management, contract deployment |
| `investigator` | Upload, verify, view all evidence |
| `analyst` | View, verify evidence |
| `court_authority` | View evidence and custody chain |

---

## Smart Contract Functions

```solidity
// Register new evidence on blockchain
addEvidence(evidenceId, fileHash, fileName, caseId)

// Record custody action (transfer, analyze, etc.)
transferEvidence(evidenceId, action, note)

// Read evidence from blockchain
getEvidence(evidenceId) → (fileHash, fileName, caseId, owner, timestamp)

// Get custody record count
getCustodyCount(evidenceId) → uint256

// Get individual custody record
getCustodyRecord(evidenceId, index) → (action, actor, note, timestamp)

// Check if evidence exists
evidenceExists(evidenceId) → bool
```

---

## Offline Mode

If Ganache is not running, the system operates in **offline mode**:
- Evidence files are still uploaded and hashed
- Metadata is saved to PostgreSQL
- TX hashes are prefixed with `OFFLINE-`
- Verification compares against the DB hash (not blockchain)

This allows the system to function even without blockchain connectivity,
while blockchain verification remains available when Ganache is connected.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://postgres:postgres@localhost:5432/forensic_chain` | PostgreSQL connection URL |
| `ADMIN_NAME` | `System Admin` | Optional private admin display name |
| `ADMIN_EMAIL` | (none) | Private admin login email used for first admin seed |
| `ADMIN_PASSWORD` | (none) | Private admin password used for first admin seed |
| `GANACHE_URL` | `http://127.0.0.1:7545` | Ganache RPC endpoint |
| `SECRET_KEY` | `forensic-chain-secret-2024` | Flask session secret |

Set them before running:
```bash
export GANACHE_URL=http://127.0.0.1:7545
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/forensic_chain
export ADMIN_NAME="Forensic Root"
export ADMIN_EMAIL=private-admin@agency.gov
export ADMIN_PASSWORD='ChangeThisToAStrongOne!'
export SECRET_KEY=your-secure-secret
python backend/app.py
```

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Blockchain | Ethereum (Ganache local testnet) |
| Smart Contract | Solidity 0.8.0 |
| Backend | Python 3.9+, Flask 3.0 |
| Blockchain SDK | Web3.py 6.x |
| Database | PostgreSQL (via psycopg2) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Hashing | SHA-256 (hashlib) |
| Auth | Flask sessions + Werkzeug password hashing |

---

## Common Issues

## Common Mistakes (Avoid These)

- Forgetting `conn.commit()` after INSERT/UPDATE/DELETE operations.
- Not setting `DATABASE_URL` in environment or `.env`.
- Leaving old SQLite code paths in `backend/database.py`.
- Using an invalid PostgreSQL connection string format.
- Not installing `psycopg2-binary` in the active environment.

**"Cannot connect to Ganache"**
- Make sure Ganache Desktop is open with a Quickstart workspace
- Check that RPC server is on port 7545 (Settings → Server)
- Or run: `ganache --port 7545`

**"Contract not deployed"**
- Run `python migrations/deploy.py` first
- Or paste contract address manually in the Blockchain panel of the dashboard

**"py-solc-x" compile error**
- The first compile downloads solc 0.8.0 (~50MB), requires internet
- If behind a proxy: `export HTTPS_PROXY=your_proxy`

**Port 5000 already in use**
- On macOS: AirPlay Receiver uses port 5000. Change Flask port:
  ```python
  app.run(port=5001)
  ```
