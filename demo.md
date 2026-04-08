# ForensicChain Demo

## Project Objective
Build a blockchain-backed digital forensics evidence management system that supports:
- Tamper-evident evidence registration
- Chain-of-custody tracking
- Role-based access for forensic stakeholders
- Practical verification workflows for investigation and legal review

## Objective Aspects of the Project

### 1. Functional Objective
Create an end-to-end workflow where a user can upload evidence, generate a cryptographic hash, anchor metadata on blockchain, and verify integrity later.

### 2. Security Objective
Protect access and data handling using authentication, authorization, hashed passwords, and session controls.

### 3. Forensic Objective
Maintain traceability of who handled evidence, what action was performed, and when it occurred.

### 4. System Objective
Deliver a working full-stack prototype (smart contract + backend + frontend + storage) that can run locally for demonstration.

## Evidence That These Objectives Exist in This Repository

| Objective Area | What is Implemented | Where It Is Demonstrated |
|----------------|---------------------|--------------------------|
| Blockchain evidence anchoring | Smart contract with evidence registration and custody functions | [contracts/Evidence.sol](contracts/Evidence.sol) |
| Deployment flow | Contract compile + deploy script and generated artifacts | [migrations/deploy.py](migrations/deploy.py), [contracts/Evidence_abi.json](contracts/Evidence_abi.json), [backend/contract_address.txt](backend/contract_address.txt) |
| Backend API workflow | Upload, verify, custody, auth, admin, blockchain endpoints | [backend/app.py](backend/app.py) |
| Blockchain integration layer | Web3 connection, on-chain read/write operations | [backend/blockchain.py](backend/blockchain.py) |
| Persistence and audit data | Database helpers for users, evidence, custody logs | [backend/database.py](backend/database.py) |
| User-facing demonstration UI | Login, dashboard, upload, verify, custody pages | [frontend/index.html](frontend/index.html), [frontend/dashboard.html](frontend/dashboard.html), [frontend/reset-password.html](frontend/reset-password.html) |
| Local evidence handling | Stored uploaded evidence files directory | [evidence_storage](evidence_storage) |
| Documented feature scope | Feature and stack overview | [PROJECT_FEATURES_AND_STACK.md](PROJECT_FEATURES_AND_STACK.md) |
| Documented security scope | Security capabilities and controls | [SECURITY.md](SECURITY.md) |
| Documented risk awareness | Risks, known issues, and mitigation priorities | [RISKS_AND_BUGS.md](RISKS_AND_BUGS.md) |

## Demo Use-Case (Objective Validation)
1. Start Ganache and deploy the contract.
2. Start backend service.
3. Log in to the web application.
4. Upload an evidence file with case ID.
5. Verify evidence integrity (expected: pass).
6. Modify the stored evidence file in local storage.
7. Verify the same evidence again (expected: tamper detected).

This validates that the project objective is not only conceptual, but operational in a reproducible demo flow.

## Deliverables Summary
- Smart contract for evidence and custody records
- Flask API for auth, evidence, verification, and admin operations
- PostgreSQL-backed metadata and custody persistence
- Web frontend for interactive workflows
- Local storage for uploaded evidence files
- Deployment and setup documentation

## One-Line Abstract
ForensicChain is a working prototype that combines blockchain immutability with forensic process tracking to make digital evidence handling more transparent, verifiable, and auditable.

## Full Functional Architecture

### 1. System Goal
ForensicChain is built to manage digital evidence end-to-end with integrity checks and custody traceability:
1. Accept evidence files from authenticated users.
2. Compute SHA-256 hashes for integrity.
3. Register evidence and custody actions on blockchain when available.
4. Store operational metadata and logs in PostgreSQL.
5. Provide role-based workflows in a web dashboard.

### 2. Layered Architecture

#### 2.1 Presentation Layer
Responsible files:
1. [frontend/index.html](frontend/index.html)
2. [frontend/dashboard.html](frontend/dashboard.html)
3. [frontend/reset-password.html](frontend/reset-password.html)

Responsibilities:
1. User sign-in, registration, and password reset UI.
2. Evidence upload, verification, and custody action forms.
3. Admin screens for users, stats, logs, and blockchain controls.
4. Rendering blockchain status, transaction metadata, and alerts.

#### 2.2 API and Application Layer
Responsible file:
1. [backend/app.py](backend/app.py)

Responsibilities:
1. Exposes REST endpoints for auth, evidence, custody, admin, and blockchain operations.
2. Enforces session and JWT authentication.
3. Enforces role-based access control.
4. Coordinates calls between database and blockchain manager.
5. Handles fallback behavior when blockchain is unavailable.

#### 2.3 Service and Integration Layer
Responsible files:
1. [backend/database.py](backend/database.py)
2. [backend/blockchain.py](backend/blockchain.py)

Responsibilities:
1. Database service handles users, evidence metadata, and custody logs.
2. Blockchain service manages RPC connection, contract load, transaction submission, and receipt parsing.
3. Network safety checks validate contract bytecode exists on active chain.
4. Transaction logic handles nonce and fee strategy for live networks.

#### 2.4 Persistence Layer
Components:
1. PostgreSQL database
2. Local file storage in [evidence_storage](evidence_storage)
3. Ethereum compatible chain via RPC

Responsibilities:
1. PostgreSQL stores app-level records and audit logs.
2. Local storage keeps uploaded binary evidence files.
3. Blockchain stores immutable evidence and custody records.

### 3. Tool and Technology Mapping
1. Flask: API server, routing, sessions, request handling.
2. Flask-CORS: credentialed cross-origin support for browser requests.
3. psycopg2 and PostgreSQL: relational storage for users, evidence, and custody logs.
4. Web3.py: smart contract calls, transaction sending, receipt reads.
5. Solidity: smart contract implementation in [contracts/Evidence.sol](contracts/Evidence.sol).
6. py-solc-x: contract compilation from Python deployment flow.
7. Deployment script in [migrations/deploy.py](migrations/deploy.py): compile and deploy contract, save ABI and address.
8. Environment config in [.env](.env): RPC, key, DB, secrets, feature settings.

### 4. Functional Workflow, Step by Step

#### 4.1 Authentication Workflow
1. User submits credentials from UI.
2. API validates user record and password hash.
3. Session is established and JWT token is generated.
4. Role context is attached for access checks.
5. Protected endpoints verify authentication and role before execution.

#### 4.2 Evidence Upload Workflow
1. Browser sends multipart request with file and case data.
2. API validates extension and size policy.
3. API computes SHA-256 and checks duplicate hashes.
4. File is saved to local storage directory.
5. Blockchain manager attempts addEvidence transaction.
6. On success, tx hash and block metadata are captured.
7. On failure, fallback metadata is generated and marked offline.
8. Evidence row and first custody event are stored in PostgreSQL.

#### 4.3 Verification Workflow
1. User verifies by stored file or re-uploaded file.
2. API computes current file hash.
3. API attempts on-chain comparison against contract hash.
4. If on-chain read fails, API compares against database hash.
5. Evidence status becomes verified or tampered.
6. A verification custody log is recorded.

#### 4.4 Custody Transfer Workflow
1. User submits evidence ID, action, and note.
2. API validates action and evidence existence.
3. Blockchain manager attempts transferEvidence transaction.
4. Resulting tx metadata or fallback marker is attached.
5. Custody record is persisted in PostgreSQL.

#### 4.5 Admin and Operations Workflow
1. Admin reads system stats, logs, and user data through protected endpoints.
2. Admin deploys contract or updates contract address from dashboard tools.
3. UI pulls chain connectivity and contract state from blockchain info endpoint.

### 5. Smart Contract Responsibilities
Contract file: [contracts/Evidence.sol](contracts/Evidence.sol)

1. addEvidence: immutable registration of evidence ID, hash, file data, and case ID.
2. transferEvidence: immutable custody action logging.
3. getEvidence: retrieval of canonical on-chain evidence state.
4. getCustodyCount and getCustodyRecord: custody timeline reconstruction.
5. evidenceExists: existence checks for integrity of workflow.

### 6. Relationship Between Components
1. Frontend only talks to backend API.
2. Backend API talks to database and blockchain manager.
3. Blockchain manager talks to configured RPC endpoint.
4. Contract address is loaded from environment or address file.
5. UI renders online or fallback mode from API responses.

### 7. Runtime Modes
1. Online mode: blockchain connected, contract loaded, transactions confirmed.
2. Fallback mode: blockchain unavailable or tx fails, app continues with local and DB records.

### 8. Deployment and Startup Sequence
1. Install dependencies from [requirements.txt](requirements.txt).
2. Configure [.env](.env) with RPC, key, DB, and secrets.
3. Deploy contract and generate artifacts with [migrations/deploy.py](migrations/deploy.py).
4. Confirm contract address in [.env](.env) and [backend/contract_address.txt](backend/contract_address.txt).
5. Start backend service from [backend/app.py](backend/app.py).
6. Access frontend pages and run evidence workflows.

### 9. Traceability Summary
1. File-level evidence is stored locally.
2. Metadata and operational events are stored in PostgreSQL.
3. Integrity-critical events are anchored on blockchain.
4. Combined view in dashboard gives tamper visibility and custody history.
