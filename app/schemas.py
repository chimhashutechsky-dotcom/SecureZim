from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str
    company_name: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    company_id: int


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    company_id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class CompanyIn(BaseModel):
    name: str


class CompanyResponse(BaseModel):
    id: int
    name: str
    created_at: datetime

    class Config:
        from_attributes = True


class AssetIn(BaseModel):
    target: str
    authorized: bool


class AssetResponse(BaseModel):
    id: int
    company_id: int
    target: str
    authorized: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: int
    asset_id: int
    target: str
    status: str
    security_score: int | None
    started_at: datetime | None
    finished_at: datetime | None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    severity: str
    title: str
    description: str
    evidence: str
    remediation: str

    class Config:
        from_attributes = True
