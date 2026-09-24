from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from .db import Base, engine, get_db
from .models import Company, Asset, Scan, Finding
from .scanner import scan_target, calculate_score

Base.metadata.create_all(bind=engine)
app = FastAPI(title="SecureZim API", version="0.1.0")

class CompanyIn(BaseModel):
    name: str

class AssetIn(BaseModel):
    company_id: int
    target: str
    authorized: bool

@app.get("/", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db)):
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
<div class="action"><h2>Next action</h2>
<p>Create an authorized company asset and start a scan through the API.</p>
<p><a href="/docs">Open interactive API documentation →</a></p></div></main>
</body></html>'''

@app.post("/api/companies")
def create_company(data: CompanyIn, db: Session = Depends(get_db)):
    company = Company(name=data.name)
    db.add(company); db.commit(); db.refresh(company)
    return {"id": company.id, "name": company.name}

@app.get("/api/companies")
def list_companies(db: Session = Depends(get_db)):
    return db.query(Company).all()

@app.post("/api/assets")
def create_asset(data: AssetIn, db: Session = Depends(get_db)):
    if not db.get(Company, data.company_id):
        raise HTTPException(404, "Company not found")
    if not data.authorized:
        raise HTTPException(400, "Asset authorization must be confirmed")
    asset = Asset(company_id=data.company_id, target=data.target, authorized=True)
    db.add(asset); db.commit(); db.refresh(asset)
    return {"id": asset.id, "target": asset.target, "authorized": True}

@app.get("/api/assets")
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).all()

@app.post("/api/scans/{asset_id}")
async def start_scan(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if not asset.authorized:
        raise HTTPException(403, "Asset is not authorized for scanning")
    scan = Scan(asset_id=asset.id, status="running", started_at=datetime.utcnow())
    db.add(scan); db.commit(); db.refresh(scan)
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
        scan.status = "failed"; scan.finished_at = datetime.utcnow(); db.commit()
        raise HTTPException(500, f"Scan failed: {exc}")

@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).options(joinedload(Scan.asset)).order_by(Scan.id.desc()).all()
    return [{"id":s.id,"asset_id":s.asset_id,"target":s.asset.target,"status":s.status,
             "security_score":s.security_score,"started_at":s.started_at,"finished_at":s.finished_at} for s in scans]

@app.get("/api/scans/{scan_id}/findings")
def scan_findings(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    return db.query(Finding).filter(Finding.scan_id == scan_id).all()
