# SecureZim

SecureZim is a FastAPI-based cybersecurity monitoring application for authorized asset scanning, security findings, and company-level data isolation.

## Features

- Authorized target scanning with DNS, TCP, HTTP security-header, and TLS checks
- Security-score calculation from scan findings
- SQLAlchemy persistence with SQLite by default and PostgreSQL support
- User registration and JWT login
- Bcrypt password hashing
- Company-scoped access to assets, scans, and findings
- OpenAPI documentation at `/docs`

## Authentication

Authentication endpoints:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/users/me`

Registration creates a company and its first user. Login returns a bearer access token. Use it for protected endpoints:

```http
Authorization: Bearer <access_token>
```

Protected resource endpoints include:

- `GET /api/companies/me`
- `GET /api/companies`
- `POST /api/assets`
- `GET /api/assets`
- `GET /api/assets/{asset_id}`
- `POST /api/scans/{asset_id}`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/findings`

Every resource query is constrained to the authenticated user's `company_id`; IDs from another company are not accessible.

## Configuration

Copy `.env.example` to `.env` and set a strong secret:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set the generated value as `SECRET_KEY`. Do not commit `.env` or production secrets. Configure `DATABASE_URL` for the deployment database and optionally set `ACCESS_TOKEN_EXPIRE_MINUTES`.

> The application intentionally fails at startup if `SECRET_KEY` is not configured.

## Installation and startup

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and provide SECRET_KEY
uvicorn app.main:app --reload
```

The default database is `sqlite:///./securezim.db`. For production, use a managed PostgreSQL database, HTTPS, a secrets manager, and a migration workflow such as Alembic. `Base.metadata.create_all()` creates missing tables but does not migrate existing tables.

## Example flow

Register:

```bash
curl -X POST http://localhost:8000/api/auth/register \\
  -H 'Content-Type: application/json' \\
  -d '{"email":"owner@example.com","password":"a-strong-password","full_name":"Company Owner","company_name":"Example Company"}'
```

Login and use the token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \\
  -H 'Content-Type: application/json' \\
  -d '{"email":"owner@example.com","password":"a-strong-password"}' | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl http://localhost:8000/api/assets -H "Authorization: Bearer $TOKEN"
```

Create an authorized asset before scanning it:

```bash
curl -X POST http://localhost:8000/api/assets \\
  -H "Authorization: Bearer $TOKEN" \\
  -H 'Content-Type: application/json' \\
  -d '{"target":"example.com","authorized":true}'
```

Only scan targets for which you have explicit authorization.

## Project structure

- `app/main.py` — FastAPI application and protected routes
- `app/auth.py` — password hashing, JWT creation/validation, current-user dependency
- `app/models.py` — SQLAlchemy models and relationships
- `app/schemas.py` — request and response schemas
- `app/db.py` — database engine and session dependency
- `app/scanner.py` — existing scanner and score calculation
- `AUTHENTICATION.md` — authentication API and deployment notes

## Security notes

- Store only password hashes; never log or persist plaintext passwords.
- Use a unique, high-entropy `SECRET_KEY` per environment.
- Run behind HTTPS in production.
- Add rate limiting and account-recovery controls before exposing authentication publicly.
- Use database migrations for schema changes in deployed environments.
- Scan only assets that are explicitly authorized.
