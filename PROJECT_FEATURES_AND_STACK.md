# ForensicChain Project Overview

## What It Does
ForensicChain is a blockchain-backed digital evidence management system. It lets authenticated users upload evidence files, compute SHA-256 hashes, record evidence metadata on Ethereum/Ganache, verify file integrity later, and maintain a chain-of-custody log in SQLite.

## Tech Stack And What Each Part Is Used For
- Flask in backend/app.py for the HTTP API, session auth, and serving the frontend pages.
- Web3.py in backend/blockchain.py for Ganache/Ethereum connectivity, contract calls, and network status.
- SQLite in backend/database.py for users, evidence metadata, and custody logs.
- Solidity in contracts/Evidence.sol for on-chain evidence registration and custody history.
- py-solc-x in migrations/deploy.py for compiling and deploying the smart contract.
- HTML, CSS, and vanilla JavaScript in frontend/index.html and frontend/dashboard.html for login, upload, verification, custody, and admin views.
- Werkzeug password hashing for credential storage.
- Flask-CORS for cross-origin session support.

## Main Features Present Today
- User registration and login with role-based access control.
- Evidence upload with file hashing and secure filename handling.
- Blockchain registration for evidence hashes and custody actions.
- Offline fallback when Ganache or the contract is unavailable.
- Evidence verification by stored file or by re-uploaded file.
- Evidence detail view with chain-of-custody history.
- Admin dashboard features for users, stats, logs, and contract deployment.

## Potential Feature Directions
- Restrict admin-only actions more strictly and add approval flows for privileged accounts.
- Add CSRF protection and stronger session hardening.
- Add upload size limits, file type scanning, and retention controls.
- Add evidence search, filtering, pagination, and export to PDF/CSV.
- Add immutable audit exports and signature support for custody events.
- Add encrypted evidence storage at rest.
- Add multi-network support beyond local Ganache.
- Add richer verification history and tamper alerts.

## High-Level Architecture
1. The browser sends requests to the Flask API.
2. Flask stores users and metadata in SQLite.
3. Evidence files are written to evidence_storage/.
4. The blockchain layer records hashes and custody events on-chain when available.
5. The dashboard reads both database data and blockchain data to show integrity status.