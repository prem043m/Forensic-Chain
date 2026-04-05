# ForensicChain Security Features

## 🔐 Complete Security Implementation

This document outlines all security features implemented in ForensicChain.

---

## 1. JWT Token Authentication ✅

### What It Does
- Generates secure JWT tokens upon login
- Tokens expire automatically (default: 8 hours)
- Can be used for stateless API authentication
- Allows both Bearer token and session-based access

### How to Use

**Login to get token:**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@agency.gov",
    "password": "SecurePass@123"
  }'
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "user": { "id": 1, "name": "User", "email": "...", "role": "investigator" }
}
```

**Use token in requests:**
```bash
curl -X GET http://localhost:5000/api/evidence \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Token Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/auth/login` | POST | Login and get JWT token |
| `/api/auth/validate-token` | POST | Check if token is valid |
| `/api/auth/refresh-token` | POST | Get a new token before expiry |

### Configuration

```env
JWT_SECRET=your-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=8
```

---

## 2. Session Timeout Management ✅

### What It Does
- Sessions expire automatically after 8 hours
- Prevents unauthorized access after user closes tab
- Re-authentication required when sessions timeout

### Configuration

```env
PERMANENT_SESSION_LIFETIME=28800  # 8 hours in seconds
SESSION_COOKIE_HTTPONLY=true      # Prevent JavaScript access
SESSION_COOKIE_SAMESITE=Lax       # CSRF protection
SESSION_COOKIE_SECURE=false       # Set true in production with HTTPS
```

### How It Works
1. User logs in → session created with 8-hour expiry
2. Session stored in browser cookies (HttpOnly flag prevents JavaScript access)
3. After 8 hours → session automatically invalidates
4. Next API call → returns 401 Unauthorized
5. User redirected to login page

---

## 3. Password Hashing with Bcrypt ✅

### What It Does
- Hashes passwords using bcrypt (12 rounds) — much stronger than plain MD5/SHA1
- Automatically falls back to Werkzeug hashing for compatibility
- Verifies passwords against both bcrypt and Werkzeug hashes

### Password Strength Requirements
✅ Minimum 12 characters  
✅ At least one uppercase letter (A-Z)  
✅ At least one lowercase letter (a-z)  
✅ At least one digit (0-9)  
✅ At least one symbol (!@#$%^&*, etc.)

### Example Valid Passwords
```
✓ MyForensic@Password123
✓ SecurityLab#2026
✓ Evidence_Chain$Secure
✗ password  (too short, no uppercase, no symbol)
✗ PASSWORD123  (no lowercase, no symbol)
✗ MyPassword (no digit, no symbol)
```

### How to Verify Passwords

**During Login:**
```python
def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies password against bcrypt or werkzeug hash"""
    try:
        import bcrypt
        if hashed_password.startswith('$2'):  # bcrypt hash
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        else:  # werkzeug format
            return check_password_hash(hashed_password, password)
    except:
        return check_password_hash(hashed_password, password)
```

### Database

Passwords stored in PostgreSQL `users.password` column:
```
bcrypt hash example: $2b$12$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jKMUm
```

---

## 4. Role-Based Access Control (RBAC) Middleware ✅

### What It Does
- Protects routes with role requirements
- Automatically checks user permissions before processing requests
- Returns 403 Forbidden if user lacks required role

### Available Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full system access, user management, contract deployment |
| `investigator` | Upload evidence, transfer custody, view all evidence |
| `analyst` | View evidence, run verification |
| `court_authority` | View evidence and custody logs (read-only) |

### Session-Based Protection

```python
@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def get_all_users():
    """Only admin can access this"""
    return jsonify(db.get_all_users())
```

### JWT-Based Protection

```python
@app.route("/api/evidence", methods=["GET"])
@jwt_role_required("investigator", "admin")  # Multiple roles
def get_evidence():
    """Investigators and admins can access this"""
    return jsonify(db.get_all_evidence())
```

### How It Works
1. Request sent to protected route with JWT token
2. Middleware extracts token from `Authorization: Bearer <token>` header
3. Token is decoded and role is checked
4. If role matches → request proceeds
5. If role doesn't match → 403 Forbidden returned

### Usage in JavaScript

```javascript
// Admin function - requires admin token
async function deleteUser(userId) {
  const token = localStorage.getItem('token');
  
  const response = await fetch(`/api/admin/users/${userId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (response.status === 403) {
    console.error('Admin access required');
  }
  return response.json();
}
```

---

## 5. Password Reset & Email Verification ✅

### What It Does
- Users can reset forgotten passwords via email
- Reset links expire after 1 hour
- Email verification on every login
- Login notifications sent to registered email

### Password Reset Flow

**Step 1: Request Reset**
```bash
curl -X POST http://localhost:5000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@agency.gov"}'
```

**Step 2: Email Received**
- Email contains reset link with secure token
- Link format: `http://localhost:5000/reset-password.html?token=<token>&email=<email>`
- Token expires in 1 hour

**Step 3: Set New Password**
```bash
curl -X POST http://localhost:5000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@agency.gov",
    "token": "<reset_token_from_email>",
    "password": "NewSecure@Pass2026"
  }'
```

### Login Notifications
- Every login triggers email notification
- Email includes login timestamp
- Used to alert users of unauthorized access attempts

### Email Configuration

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SENDER_EMAIL=noreply@forensicchain.com
APP_URL=http://localhost:5000
```

**For Gmail:**
1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Generate App Password (not your regular password)
3. Use generated password in `SMTP_PASSWORD`

---

## 6. Secure Cookie Configuration ✅

### What It Does
- Session cookies configured with security best practices
- Prevents common web vulnerabilities

### Settings

```python
app.config["SESSION_COOKIE_HTTPONLY"] = True    # JS cannot access cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
app.config["SESSION_COOKIE_SECURE"] = False     # Set True in production with HTTPS
```

### Why These Matter

| Setting | Purpose | Protection |
|---------|---------|-----------|
| `HttpOnly` | Prevent JavaScript access | XSS attacks |
| `SameSite` | Prevent cross-site requests | CSRF attacks |
| `Secure` | Only send over HTTPS | Man-in-the-middle attacks |

---

## 7. Strong Password Policy ✅

### Requirements
```python
def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False  # Too short
    has_upper = any(c.isupper() for c in password)  # Need uppercase
    has_lower = any(c.islower() for c in password)  # Need lowercase
    has_digit = any(c.isdigit() for c in password)  # Need digit
    has_symbol = any(not c.isalnum() for c in password)  # Need symbol
    return has_upper and has_lower and has_digit and has_symbol
```

### Testing Passwords
- `p@ssword` → ❌ (too common, only 8 chars)
- `Password123` → ❌ (no symbol)
- `Pass@123word` → ✅ (12+ chars, uppercase, lowercase, digit, symbol)

---

## 8. Database Security Measures ✅

### Connection Security
- PostgreSQL connection uses environment variables (not hardcoded)
- Connection string encrypted in `.env` file
- Database URL pattern: `postgresql://user:password@host:port/database`

### User Table Encryption
- Passwords stored as bcrypt hashes (one-way encryption)
- Reset tokens stored temporarily, cleared after use
- Email addresses indexed for fast lookups
- Creation timestamps tracked for audit

### SQL Injection Prevention
- Parameterized queries using `psycopg2` placeholders
- No string concatenation in SQL statements
- Example: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`

---

## 9. Audit Logging ✅

### What Gets Logged
- User login timestamp (`last_login` column)
- Password reset requests with tokens
- Admin actions (user creation, deletion)
- Evidence uploads and transfers (chain of custody)

### Database Columns
```sql
-- Users table
id          SERIAL PRIMARY KEY
email       VARCHAR(255) UNIQUE
password    TEXT (bcrypt hash)
last_login  TIMESTAMP  -- updated on every login
created_at  TIMESTAMP
password_reset_token     VARCHAR(255)
password_reset_expiry    TIMESTAMP

-- Custody logs table
evidence_id     VARCHAR(64)
action          VARCHAR(100)  -- 'upload', 'transfer', 'verify'
user_id         INTEGER       -- which user performed action
created_at      TIMESTAMP     -- when action happened
```

---

## 10. Testing Security Features

### Test JWT Token Flow
```bash
# 1. Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"043mkamble8752@gmail.com","password":"043m@Secure23"}' \
  | jq '.token' > token.txt

# 2. Use token
TOKEN=$(cat token.txt | tr -d '"')
curl -X GET http://localhost:5000/api/evidence \
  -H "Authorization: Bearer $TOKEN"

# 3. Validate token
curl -X POST http://localhost:5000/api/auth/validate-token \
  -H "Authorization: Bearer $TOKEN"

# 4. Token should fail after 8 hours
# (or after JWT_EXPIRATION_HOURS)
```

### Test Role-Based Access
```bash
# Login as investigator
INVESTIGATOR_TOKEN=$(...)

# Try to access admin endpoint (should fail with 403)
curl -X GET http://localhost:5000/api/admin/users \
  -H "Authorization: Bearer $INVESTIGATOR_TOKEN"
# Response: 403 Forbidden - Insufficient permissions
```

### Test Session Timeout
```bash
# Session timeout: 8 hours
# After 8 hours, session cookie expires
# Next request returns 401 Unauthorized
```

### Test Password Strength
```bash
# Register with weak password (should fail)
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name":"User",
    "email":"user@test.com",
    "password":"weak",
    "password_confirm":"weak",
    "role":"investigator"
  }'
# Response: 400 Bad Request - Password must be at least 12 characters...
```

---

## 🛠️ Deployment Checklist

Before deploying to production:

- [ ] Set `JWT_SECRET` to a secure random value
- [ ] Set `SECRET_KEY` to a secure random value
- [ ] Set `SESSION_COOKIE_SECURE=true` (requires HTTPS)
- [ ] Set `APP_URL` to production domain
- [ ] Configure email provider credentials (Gmail, SendGrid, etc.)
- [ ] Enable HTTPS/TLS certificate
- [ ] Set up PostgreSQL with strong password
- [ ] Configure firewall to only allow authorized ports
- [ ] Enable database backups
- [ ] Set up monitoring/alerting for failed logins
- [ ] Review and update password expiration policy
- [ ] Consider adding 2FA for admin accounts

---

## 📚 References

- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
- [Bcrypt Python Library](https://github.com/pyca/bcrypt)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.3.x/security/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/sql-security.html)

---

**Last Updated:** April 5, 2026  
**Security Version:** 2.2 (JWT + Bcrypt + RBAC)
