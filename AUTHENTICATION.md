# SecureZim Authentication Guide

This document describes the production-ready authentication system for SecureZim.

## Overview

SecureZim now includes:
- **User Registration & Login** with secure password hashing (bcrypt)
- **JWT Token-Based Authentication** for stateless API access
- **Multi-Tenant Data Isolation** - users can only access their company's data
- **Protected Endpoints** - all asset, scan, and finding endpoints require authentication
- **Environment-Based Configuration** - secrets managed via environment variables

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Update the values in `.env`:

```env
# Use a strong random secret key in production
SECRET_KEY=<generate-with-python-secrets>

# JWT token expiration time
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database URL (SQLite by default)
DATABASE_URL=sqlite:///./securezim.db
```

**Generate a secure SECRET_KEY:**

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Database Setup

Tables are automatically created on first run. The new `User` table links users to companies.

```
users
├── id (PK)
├── company_id (FK) → companies
├── email (unique, indexed)
├── hashed_password
├── full_name
├── is_active
├── created_at
└── updated_at

companies (updated with users relationship)
├── id (PK)
├── name
├── users (relationship)
└── assets (relationship)
```

## API Endpoints

### Authentication (Public)

#### Register a New User

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@company.com",
  "password": "SecurePassword123",
  "full_name": "John Doe",
  "company_name": "Acme Corp"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user_id": 1,
  "company_id": 1
}
```

#### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@company.com",
  "password": "SecurePassword123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user_id": 1,
  "company_id": 1
}
```

### Protected Endpoints

All protected endpoints require the `Authorization` header:

```http
Authorization: Bearer <access_token>
```

#### Get Current User Info

```http
GET /api/users/me
Authorization: Bearer <token>
```

#### Get Company Info

```http
GET /api/companies/me
Authorization: Bearer <token>
```

#### Create Asset (Company-Isolated)

```http
POST /api/assets
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "example.com",
  "authorized": true
}
```

#### List Assets (Company-Isolated)

```http
GET /api/assets
Authorization: Bearer <token>
```

#### Start Scan (Company-Isolated)

```http
POST /api/scans/{asset_id}
Authorization: Bearer <token>
```

#### List Scans (Company-Isolated)

```http
GET /api/scans
Authorization: Bearer <token>
```

#### Get Scan Findings (Company-Isolated)

```http
GET /api/scans/{scan_id}/findings
Authorization: Bearer <token>
```

#### List All Findings (Company-Isolated)

```http
GET /api/findings
Authorization: Bearer <token>
```

## Security Features

### 1. Password Security
- Passwords are hashed using **bcrypt** with automatic salt generation
- Passwords are never stored in plaintext
- Minimum password length: 8 characters

### 2. JWT Tokens
- Tokens include user ID and company ID
- Tokens are signed with a secret key (HS256)
- Tokens automatically expire after `ACCESS_TOKEN_EXPIRE_MINUTES`
- Token validation verifies both signature and company_id

### 3. Multi-Tenant Isolation
- Every authenticated endpoint verifies the user's company_id
- Users can only access assets, scans, and findings from their own company
- No cross-company data leakage is possible

### 4. Active User Checks
- Inactive users cannot obtain tokens
- Inactive users are rejected even with valid tokens

## Usage Examples

### cURL

```bash
# Register
curl -X POST "http://localhost:8000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@mycompany.com",
    "password": "SecurePass123",
    "full_name": "Admin User",
    "company_name": "My Company"
  }'

# Login
RESPONSE=$(curl -s -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@mycompany.com",
    "password": "SecurePass123"
  }')

TOKEN=$(echo $RESPONSE | jq -r '.access_token')

# Use token
curl -X GET "http://localhost:8000/api/assets" \
  -H "Authorization: Bearer $TOKEN"
```

### Python

```python
import requests
from requests.auth import HTTPBearer

BASE_URL = "http://localhost:8000"

# Register
register_response = requests.post(
    f"{BASE_URL}/api/auth/register",
    json={
        "email": "user@company.com",
        "password": "SecurePassword123",
        "full_name": "John Doe",
        "company_name": "Acme Corp"
    }
)

token = register_response.json()["access_token"]

# Get assets with authentication
headers = {"Authorization": f"Bearer {token}"}
assets = requests.get(
    f"{BASE_URL}/api/assets",
    headers=headers
)
print(assets.json())
```

## Production Deployment

### Environment Variables (Required)

```env
SECRET_KEY=<strong-random-key>
DATABASE_URL=postgresql://user:password@prod-db:5432/securezim
ACCESS_TOKEN_EXPIRE_MINUTES=30
DEBUG=False
```

### Important Security Notes

1. **Change SECRET_KEY** - Do NOT use the default. Generate a new one:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Use PostgreSQL/MySQL** - SQLite is not suitable for production:
   ```env
   DATABASE_URL=postgresql://user:password@localhost/securezim
   ```

3. **Enable HTTPS** - Always use HTTPS in production
   - Use a reverse proxy (nginx, Caddy)
   - Configure TLS/SSL certificates

4. **Secure Cookies** - For frontend applications:
   - Set `SameSite=Strict`
   - Use `Secure` flag
   - Use `HttpOnly` flag

5. **Token Expiration** - Adjust based on security requirements:
   - Short-lived (15-30 min) for sensitive operations
   - Consider refresh tokens for long sessions

6. **Rate Limiting** - Implement rate limiting on auth endpoints:
   - Login endpoint
   - Register endpoint
   - Consider using FastAPI middleware or reverse proxy

## Backward Compatibility

All existing scanner functionality is preserved:
- ✅ Scanner continues to work unchanged
- ✅ Security score calculations unchanged
- ✅ All finding detection logic unchanged
- ✅ Existing database schema extended (not modified)

The only breaking change is that protected endpoints now require authentication headers.

## Migration Path

If you have existing data in SQLite:

1. Backup your database
2. Update requirements.txt and install dependencies
3. Run the application - new `users` table will be created
4. Existing `companies`, `assets`, `scans`, and `findings` data remain intact
5. Create users and link them to existing companies via database updates

## Troubleshooting

### "Invalid token"
- Token may have expired - re-authenticate
- SECRET_KEY may have changed - regenerate tokens
- Token format incorrect - ensure `Authorization: Bearer <token>`

### "User not found or inactive"
- User doesn't exist in database
- User has `is_active = False` flag
- User belongs to different company than token claims

### "Email already registered"
- Email is already in the system
- Use login endpoint instead

### "Invalid email or password"
- Email doesn't exist or password is incorrect
- Check email for typos
- Verify password is correct
