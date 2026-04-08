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
