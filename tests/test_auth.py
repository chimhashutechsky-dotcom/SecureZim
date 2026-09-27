from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import Company, User, Asset, Scan, Finding
from app.auth import hash_password

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_securezim.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def create_company(db, name="Acme Corp"):
    company = Company(name=name)
    db.add(company)
    db.commit()
    db.refresh(company)
    return company


def create_user(db, company, email="admin@example.com", password="Password123"):
    user = User(
        company_id=company.id,
        email=email,
        hashed_password=hash_password(password),
        full_name="Admin User",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_asset(db, company, target="example.com"):
    asset = Asset(company_id=company.id, target=target, authorized=True)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def create_scan(db, asset):
    scan = Scan(asset_id=asset.id, status="completed", security_score=90)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def create_finding(db, scan):
    finding = Finding(
        scan_id=scan.id,
        severity="high",
        title="Test finding",
        description="Example vulnerability",
        evidence="Example evidence",
        remediation="Fix the issue",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def test_register_user_creates_company_and_returns_token():
    reset_db()
    payload = {
        "email": "owner@example.com",
        "password": "Password123",
        "full_name": "Owner User",
        "company_name": "Example Company",
    }

    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    assert body["company_id"] is not None


def test_login_returns_token_for_valid_credentials():
    reset_db()
    db = TestingSessionLocal()
    company = create_company(db, name="Test Co")
    create_user(db, company, email="user@testco.com", password="Password123")
    db.close()

    response = client.post(
        "/api/auth/login",
        json={"email": "user@testco.com", "password": "Password123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["user_id"] > 0
    assert body["company_id"] == company.id


def test_protected_assets_are_company_scoped():
    reset_db()
    db = TestingSessionLocal()
    company_a = create_company(db, name="Company A")
    company_b = create_company(db, name="Company B")
    user_a = create_user(db, company_a, email="a@example.com", password="Password123")
    create_user(db, company_b, email="b@example.com", password="Password123")
    asset_a = create_asset(db, company_a, target="alpha.example.com")
    create_asset(db, company_b, target="beta.example.com")
    db.close()

    token = client.post(
        "/api/auth/login",
        json={"email": "a@example.com", "password": "Password123"},
    ).json()["access_token"]

    response = client.get("/api/assets", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["target"] == asset_a.target
    assert payload[0]["company_id"] == company_a.id


def test_protected_scan_and_findings_are_company_scoped():
    reset_db()
    db = TestingSessionLocal()
    company_a = create_company(db, name="Company A")
    company_b = create_company(db, name="Company B")
    create_user(db, company_a, email="a@example.com", password="Password123")
    create_user(db, company_b, email="b@example.com", password="Password123")
    asset_a = create_asset(db, company_a, target="alpha.example.com")
    asset_b = create_asset(db, company_b, target="beta.example.com")
    scan_a = create_scan(db, asset_a)
    scan_b = create_scan(db, asset_b)
    create_finding(db, scan_a)
    create_finding(db, scan_b)
    db.close()

    token = client.post(
        "/api/auth/login",
        json={"email": "a@example.com", "password": "Password123"},
    ).json()["access_token"]

    response = client.get("/api/scans", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    scans = response.json()
    assert len(scans) == 1
    assert scans[0]["asset_id"] == asset_a.id

    findings_response = client.get(
        f"/api/scans/{scan_a.id}/findings",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert findings_response.status_code == 200
    assert len(findings_response.json()) == 1

    unauthorized_scan = client.get(
        f"/api/scans/{scan_b.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert unauthorized_scan.status_code == 404


def test_invalid_token_is_rejected():
    response = client.get(
        "/api/assets",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert response.status_code == 401


def test_user_cannot_login_with_wrong_password():
    reset_db()
    db = TestingSessionLocal()
    company = create_company(db, name="Test Co")
    create_user(db, company, email="user@testco.com", password="Password123")
    db.close()

    response = client.post(
        "/api/auth/login",
        json={"email": "user@testco.com", "password": "WrongPassword"},
    )
    assert response.status_code == 401
