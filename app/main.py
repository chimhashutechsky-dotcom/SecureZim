from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session, joinedload
from .db import Base, engine, get_db
from .models import Company, User, Asset, Scan, Finding
from .scanner import scan_target, calculate_score
from .auth import (
    get_current_user,
    get_current_company_id,
    hash_password,
    verify_password,
    create_access_token,
)
from .schemas import (
    UserRegister,
    UserLogin,
    TokenResponse,
    UserResponse,
    CompanyIn,
    CompanyResponse,
    AssetIn,
    AssetResponse,
    ScanResponse,
    FindingResponse,
)

Base.metadata.create_all(bind=engine)
app = FastAPI(title="SecureZim API", version="0.2.0")


# ============================================================================
# Authentication Endpoints (Public)
# ============================================================================

@app.post("/api/auth/register", response_model=TokenResponse)
def register(data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user and create their company."""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # Create company
    company = Company(name=data.company_name)
    db.add(company)
    db.flush()
    
    # Create user
    user = User(
        company_id=company.id,
        email=data.email,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create access token
    access_token = create_access_token(user.id, company.id)
    
    return TokenResponse(
        access_token=access_token,
        user_id=user.id,
        company_id=company.id,
    )


@app.post("/api/auth/login", response_model=TokenResponse)
def login(data: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    
    access_token = create_access_token(user.id, user.company_id)
    
    return TokenResponse(
        access_token=access_token,
        user_id=user.id,
        company_id=user.company_id,
    )


# ============================================================================
# Dashboard (Public)
# ============================================================================

@app.get("/", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db)):
    """Public dashboard showing overall statistics."""
    companies = db.query(Company).count()
    assets = db.query(Asset).count()
    scans = db.query(Scan).count()
    findings = db.query(Finding).count()
    return f'''<!doctype html>
<html><head><meta charset="utf-8"><title>SecureZim</title>
<style>
body{{font-family:Arial;margin:0;background:#f4f6f8;color:#17202a}}
header{{background:#101820;color:white;padding:22px 35px}}
main{{padding:30px;max-width:1100px;margin:auto}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}}
.card{{background:white;padding:22px;border-radius:12px;box-shadow:0 2px 10px #0001}}
.number{{font-size:32px;font-weight:bold;margin-top:8px}}
.action{{margin-top:25px;background:white;padding:22px;border-radius:12px}}
a{{color:#0b63ce}}
</style></head><body>
<header><h1>SecureZim</h1><div>Business Cybersecurity Monitoring — MVP</div></header>
<main><div class="grid">
<div class="card">Companies<div class="number">{companies}</div></div>
<div class="card">Assets<div class="number">{assets}</div></div>
<div class="card">Scans<div class="number">{scans}</div></div>
<div class="card">Findings<div class="number">{findings}</div></div>
</div>
<div class="action"><h2>Getting Started</h2>
<p>1. Register: <code>POST /api/auth/register</code> to create your account and company</p>
<p>2. Login: <code>POST /api/auth/login</code> to get your JWT token</p>
<p>3. Manage Assets: Use the token to create and scan assets for your company</p>
<p><a href="/docs">Open interactive API documentation →</a></p></div></main>
</body></html>'''


# ============================================================================
# User Endpoints (Protected)
# ============================================================================

@app.get("/api/users/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get the current authenticated user's information."""
    return current_user


# ============================================================================
# Company Endpoints (Protected)
# ============================================================================

@app.get("/api/companies/me", response_model=CompanyResponse)
def get_company(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get the current user's company information."""
    company = db.query(Company).filter(Company.id == current_user.company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return company


@app.get("/api/companies", response_model=list[CompanyResponse])
def list_companies(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all users in the current user's company."""
    company = db.query(Company).filter(Company.id == current_user.company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return [company]


# ============================================================================
# Asset Endpoints (Protected)
# ============================================================================

@app.post("/api/assets", response_model=AssetResponse)
def create_asset(
    data: AssetIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create an asset for the current user's company."""
    if not data.authorized:
        raise HTTPException(400, "Asset authorization must be confirmed")
    
    asset = Asset(
        company_id=current_user.company_id,
        target=data.target,
        authorized=True,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@app.get("/api/assets", response_model=list[AssetResponse])
def list_assets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all assets for the current user's company."""
    assets = db.query(Asset).filter(Asset.company_id == current_user.company_id).all()
    return assets


@app.get("/api/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific asset (must belong to current user's company)."""
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.company_id == current_user.company_id,
    ).first()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


# ============================================================================
# Scan Endpoints (Protected)
# ============================================================================

@app.post("/api/scans/{asset_id}", response_model=ScanResponse)
async def start_scan(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start a security scan on an asset (must belong to current user's company)."""
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.company_id == current_user.company_id,
    ).first()
    
    if not asset:
        raise HTTPException(404, "Asset not found")
    
    if not asset.authorized:
        raise HTTPException(403, "Asset is not authorized for scanning")
    
    scan = Scan(
        asset_id=asset.id,
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    try:
        results = await scan_target(asset.target)
        for item in results:
            db.add(Finding(scan_id=scan.id, **item))
        
        scan.security_score = calculate_score(results)
        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)
        
        return scan
    except Exception as exc:
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise HTTPException(500, f"Scan failed: {exc}")


@app.get("/api/scans", response_model=list[ScanResponse])
def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all scans for assets in the current user's company."""
    scans = db.query(Scan).join(Asset).filter(
        Asset.company_id == current_user.company_id
    ).options(joinedload(Scan.asset)).order_by(Scan.id.desc()).all()
    
    return [
        ScanResponse(
            id=s.id,
            asset_id=s.asset_id,
            target=s.asset.target,
            status=s.status,
            security_score=s.security_score,
            started_at=s.started_at,
            finished_at=s.finished_at,
        )
        for s in scans
    ]


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific scan (must belong to current user's company)."""
    scan = db.query(Scan).join(Asset).filter(
        Scan.id == scan_id,
        Asset.company_id == current_user.company_id,
    ).first()
    
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    return ScanResponse(
        id=scan.id,
        asset_id=scan.asset_id,
        target=scan.asset.target,
        status=scan.status,
        security_score=scan.security_score,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


# ============================================================================
# Finding Endpoints (Protected)
# ============================================================================

@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingResponse])
def scan_findings(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all findings for a specific scan (must belong to current user's company)."""
    scan = db.query(Scan).join(Asset).filter(
        Scan.id == scan_id,
        Asset.company_id == current_user.company_id,
    ).first()
    
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return findings


@app.get("/api/findings", response_model=list[FindingResponse])
def list_findings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all findings for the current user's company."""
    findings = db.query(Finding).join(Scan).join(Asset).filter(
        Asset.company_id == current_user.company_id
    ).all()
    return findings
