from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

from .db import Base, engine, get_db
from .models import Asset, Company, Finding, Scan
from .scanner import calculate_score, scan_target

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecureZim API",
    version="1.0.0",
    description="Defensive cybersecurity monitoring for authorized assets.",
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class CompanyIn(BaseModel):
    name: str


class AssetIn(BaseModel):
    company_id: int
    target: str
    authorized: bool


@app.get("/", include_in_schema=False)
def website():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "securezim-api"}


@app.get("/api/summary")
def summary(db: Session = Depends(get_db)):
    return {
        "companies": db.query(Company).count(),
        "assets": db.query(Asset).count(),
        "scans": db.query(Scan).count(),
        "findings": db.query(Finding).count(),
    }


@app.post("/api/companies")
def create_company(data: CompanyIn, db: Session = Depends(get_db)):
    company = Company(name=data.name.strip())
    if not company.name:
        raise HTTPException(400, "Company name is required")
    db.add(company)
    db.commit()
    db.refresh(company)
    return {"id": company.id, "name": company.name}


@app.get("/api/companies")
def list_companies(db: Session = Depends(get_db)):
    return db.query(Company).order_by(Company.name).all()


@app.post("/api/assets")
def create_asset(data: AssetIn, db: Session = Depends(get_db)):
    if not db.get(Company, data.company_id):
        raise HTTPException(404, "Company not found")
    if not data.authorized:
        raise HTTPException(400, "Asset authorization must be confirmed")
    asset = Asset(company_id=data.company_id, target=data.target.strip(), authorized=True)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {"id": asset.id, "target": asset.target, "authorized": True}


@app.get("/api/assets")
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.id.desc()).all()


@app.post("/api/scans/{asset_id}")
async def start_scan(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if not asset.authorized:
        raise HTTPException(403, "Asset is not authorized for scanning")

    scan = Scan(asset_id=asset.id, status="running", started_at=datetime.utcnow())
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
        return {"scan_id": scan.id, "status": scan.status, "security_score": scan.security_score, "findings": results}
    except Exception as exc:
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise HTTPException(500, f"Scan failed: {exc}") from exc


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).options(joinedload(Scan.asset)).order_by(Scan.id.desc()).all()
    return [
        {
            "id": scan.id,
            "asset_id": scan.asset_id,
            "target": scan.asset.target,
            "status": scan.status,
            "security_score": scan.security_score,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
        }
        for scan in scans
    ]


@app.get("/api/scans/{scan_id}/findings")
def scan_findings(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    return db.query(Finding).filter(Finding.scan_id == scan_id).all()
