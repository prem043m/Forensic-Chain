# ForensicChain — Features & Enhancements

## 📋 What The Project Does

**ForensicChain** is a blockchain-based digital evidence management system that helps law enforcement, forensic labs, and courts manage digital evidence with tamper detection and chain of custody tracking.

### Core Functionality:

✅ **Evidence Upload** - Upload digital evidence files (images, logs, logs, pcaps, etc.)  
✅ **Blockchain Registration** - Store evidence metadata on Ethereum blockchain  
✅ **Tamper Detection** - SHA-256 hash comparison detects any file modifications  
✅ **Chain of Custody** - Track every action on evidence (upload, transfer, analysis)  
✅ **Role-Based Access** - Different permissions for investigators, analysts, court authorities  
✅ **Offline Mode** - Works even when blockchain is unavailable  
✅ **PostgreSQL Database** - Persistent storage of evidence and metadata  

---

## 🎯 New Features Added (April 5, 2026)

### 1. **Email Authentication & Notifications**

### 0. **JWT Token Authentication** ⭐ NEW

- JWT (JSON Web Tokens) for stateless API authentication
- Supports both Bearer token and session-based auth
- Tokens include `user_id` and `role` claims
- Auto-expiration based on `JWT_EXPIRATION_HOURS` (default: 8 hours)
- Token refresh endpoint available
- **Endpoints**:
    - `POST /api/auth/validate-token` — Validate token + get user info
    - `POST /api/auth/refresh-token` — Generate new token
- **Usage**: Include in header: `Authorization: Bearer <token>`

### 5. **Session Timeout Management** ⭐ ENHANCED

- Session timeout: **8 hours** (configurable via `PERMANENT_SESSION_LIFETIME`)
- `SESSION_COOKIE_HTTPONLY=true` — Prevents JavaScript access to cookies
- `SESSION_COOKIE_SAMESITE=Lax` — CSRF protection
- `SESSION_COOKIE_SECURE=false` — Set to `true` in production with HTTPS
- Sessions automatically tracked with `last_login` timestamp
- **Configuration**:
    ```env
    PERMANENT_SESSION_LIFETIME=28800  # 8 hours in seconds
    JWT_EXPIRATION_HOURS=8
    ```


### 6. **Role-Based Access Control (RBAC) Middleware** ⭐ ENHANCED

- **Session-based RBAC**: `@role_required("admin")` decorator
- **JWT-based RBAC**: `@jwt_role_required("admin")` decorator
- Four roles with different permissions:
    - `admin` — Full system access, user management, contract deployment
    - `investigator` — Upload evidence, transfer custody, view all
    - `analyst` — View and verify evidence
    - `court_authority` — View evidence and custody chain (read-only)
- Automatic route protection and permission checking
- Returns HTTP 403 if user lacks required role
### 0.5 **Enhanced Password Security** ⭐ NEW

- Bcrypt password hashing (12 rounds) instead of Werkzeug weak hashing
- Automatic fallback to Werkzeug for compatibility
- Backward compatible with existing hashed passwords
- Stronger password strength validation (12+ chars, uppercase, lowercase, number, symbol)
- Password verification works with both bcrypt and Werkzeug formats

#### Password Reset via Email
- Users can request password reset from login page
- Email link with secure token expires in 1 hour
- New password confirmation page: `frontend/reset-password.html`
- **API**: `POST /api/auth/forgot-password`
- **API**: `POST /api/auth/reset-password`

#### Login Notifications
- Every login sends email to user's registered email address
- Includes login timestamp
- Security alert if unusual activity detected
- **Triggered on**: `POST /api/auth/login`

### 2. **Password Confirmation in Registration**

- Registration form now has TWO password fields
- Both passwords must match exactly before submission
- Client-side and server-side validation
- Prevents accidental typos during registration
- **Field Added**: `Confirm Password` input in frontend/index.html

### 3. **Enhanced Database Schema**

New columns added to `users` table:
```sql
password_reset_token VARCHAR(255)
password_reset_expiry TIMESTAMP
last_login TIMESTAMP
```

### 4. **Email Configuration**

Update `.env` file with SMTP settings:
```
# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SENDER_EMAIL=noreply@forensicchain.com
APP_URL=http://localhost:5000
```

**For Gmail**: Generate [App Password](https://myaccount.google.com/apppasswords) (not your regular password)

---

## 🔐 User Authentication Flow (Updated)

### Registration
```
1. Enter Full Name
2. Enter Email
3. Enter Password (12+ chars, uppercase, lowercase, number, symbol)
4. Confirm Password (must match)
5. Select Role (investigator, analyst, court_authority)
6. Submit → Account created
```

### Login
```
1. Enter Email
2. Enter Password
3. Submit → Login successful
4. ✉️ Email notification sent with login timestamp
5. Redirect to dashboard
```

### Password Recovery
```
1. Click "Forgot Password" tab on login page
2. Enter your email
3. ✉️ Email received with reset link
4. Click reset link (expires in 1 hour)
5. New page opens: reset-password.html
6. Enter new password (12+ chars, uppercase, lowercase, number, symbol)
7. Confirm password (must match)
8. Submit → Password reset successful
9. Redirect to login
```

---

## 📝 Admin Account Setup

Your admin account is configured in `.env`:
```
ADMIN_EMAIL=043mkamble8752@gmail.com
ADMIN_PASSWORD=043m@Secure23
ADMIN_NAME=Prem Kamble
```

**Admin Capabilities:**
- Full evidence management access
- User management panel
- System statistics dashboard
- Smart contract deployment control
- View all custody logs

---

## 🛠️ API Reference (Updated)

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user (with password confirmation) |
| POST | `/api/auth/login` | Login (triggers email notification) |
| POST | `/api/auth/logout` | Logout |
| POST | `/api/auth/forgot-password` | Request password reset email |
| POST | `/api/auth/reset-password` | Confirm password reset with token |
| GET | `/api/auth/me` | Get current user info |

| POST | `/api/auth/validate-token` | Validate JWT token (requires Bearer token) |
| POST | `/api/auth/refresh-token` | Refresh JWT token (get new token) |
### Evidence Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload_evidence` | Upload file, register on blockchain |
| GET | `/api/evidence` | List all evidence |
| GET | `/api/evidence/<id>` | Get evidence detail + custody logs |
| POST | `/api/verify_evidence` | Verify hash integrity |
| POST | `/api/transfer_evidence` | Add custody action |
| GET | `/api/evidence_history/<id>` | Full custody chain |

### Admin Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | All users (admin only) |
| GET | `/api/admin/stats` | System statistics |
| GET | `/api/admin/logs` | All custody logs |

---

## 💾 Database Schema Changes

### Users Table (Enhanced)
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'investigator',
    wallet_address VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expiry TIMESTAMP,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Auto-Migration
On app startup, new columns are automatically added to existing databases if they don't exist, with proper transaction handling to prevent errors.

---

## 🚀 How to Start

### 1. Install Dependencies
```bash
cd forensic-blockchain/backend
pip install -r requirements.txt
```

### 2. Configure Environment
Create `.env` file in project root:
```bash
DATABASE_URL=postgresql://...
ADMIN_EMAIL=043mkamble8752@gmail.com
ADMIN_PASSWORD=043m@Secure23
ADMIN_NAME=Prem Kamble
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SENDER_EMAIL=noreply@forensicchain.com
APP_URL=http://localhost:5000
```

### 3. Start Ganache
```bash
ganache --port 7545
```

### 4. Deploy Smart Contract
```bash
cd forensic-blockchain
python migrations/deploy.py
```

### 5. Start Backend Server
```bash
cd backend
python app.py
```

### 6. Open Application
Navigate to: **http://localhost:5000**

---

## ✅ New Features Testing Checklist

- [ ] Register new user with password confirmation
- [ ] Try mismatched passwords → should show error
- [ ] Login → check email for login notification
- [ ] Click "Forgot Password" → enter email
- [ ] Check email for reset link
- [ ] Open reset link → should open reset-password.html
- [ ] Try reset with weak password → should show error
- [ ] Reset with strong password → success message
- [ ] Login with new password → success
- [ ] Admin login → check email notification
- [ ] Test password reset for admin account → should work

---

## 📧 Email System Requirements

For email features to work:
- SMTP credentials configured in `.env`
- Gmail: Use [App Password](https://myaccount.google.com/apppasswords) (not regular password)
- Other providers: Use SMTP credentials provided by email service

If email is not configured:
- App logs warnings but continues to work
- Password reset tokens are still generated
- Users simply won't receive emails

---

## 🔧 File Changes Summary

### Backend Files Modified:
- `backend/app.py` — Added email endpoints, login notifications, password reset
- `backend/database.py` — New columns, password reset functions, auto-migration
- `backend/blockchain.py` — Web3.py 7.x compatibility fixes

### Frontend Files Modified:
- `frontend/index.html` — Added password confirmation field, forgot password tab
- `frontend/reset-password.html` — **NEW** — Password reset form

### Configuration Files:
- `.env` — Email configuration added

---

## 📚 Dependencies Added

```
Flask==3.0.0
Flask-Cors==4.0.0
web3==6.15.1
Werkzeug==3.0.1
psycopg2-binary==2.9.11
python-dotenv==1.0.1
gunicorn==25.3.0
py-solc-x==2.0.5
```

---

## 🎯 Next Steps / Future Enhancements

- [ ] Two-factor authentication (2FA)
- [ ] API rate limiting
- [ ] Audit logging dashboard
- [ ] Email templates (custom branding)
- [ ] SMS notifications option
- [ ] Password expiration policy
- [ ] Login history viewer
- [ ] Device recognition / alerts

---

**Last Updated:** April 5, 2026  
**Version:** 2.1 (With Email & Password Recovery)

---

## 🔐 Security Features Checklist (Complete)

✅ **JWT Token Authentication** — Stateless API auth with Bearer tokens  
✅ **Session Timeout** — 8 hours default, configurable  
✅ **Password Hashing** — Bcrypt 12 rounds (with Werkzeug fallback)  
✅ **Role-Based Middleware** — Session + JWT role protection  
✅ **Email Verification** — Login notifications + password reset  
✅ **Password Confirmation** — Prevent registration typos  
✅ **Token Validation Endpoint** — Check token validity  
✅ **Token Refresh Endpoint** — Generate new tokens  
✅ **Security Headers** — HttpOnly + SameSite cookies  
✅ **Strong Password Policy** — 12+ chars, mixed case, numbers, symbols  

---

## 🛠️ How to Use JWT Tokens

### 1. Login and Get Token
```javascript
const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email, password})
});

const {token, expires_in} = await response.json();
localStorage.setItem('token', token);  // Save token
```

### 2. Use Token in Requests
```javascript
const token = localStorage.getItem('token');
fetch('/api/evidence', {
    headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    }
});
```

### 3. Validate Token
```javascript
const isValid = await fetch('/api/auth/validate-token', {
    method: 'POST',
    headers: {'Authorization': `Bearer ${token}`}
});
```

### 4. Refresh Expired Token
```javascript
const newTokenResponse = await fetch('/api/auth/refresh-token', {
    method: 'POST',
    headers: {'Authorization': `Bearer ${oldToken}`}
});

const {token} = await newTokenResponse.json();
localStorage.setItem('token', token);  // Update token
```
