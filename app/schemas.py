"""
Pydantic schemas for API request/response validation.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, HttpUrl, validator


# Company schemas
class CompanyBase(BaseModel):
    """Base company schema."""
    name: str = Field(..., min_length=1, max_length=200, description="Company name")


class CompanyIn(CompanyBase):
    """Company creation request."""
    pass


class CompanyOut(CompanyBase):
    """Company response."""
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


# Asset schemas
class AssetBase(BaseModel):
    """Base asset schema."""
    target: str = Field(..., min_length=1, max_length=255, description="Target IP, domain, or URL")
    authorized: bool = Field(..., description="Authorization confirmation")


class AssetIn(AssetBase):
    """Asset creation request."""
    company_id: int = Field(..., gt=0, description="Company ID")
    
    @validator('target')
    def validate_target(cls, v):
        """Validate target format."""
        # Basic validation - could be enhanced
        if not v or len(v.strip()) == 0:
            raise ValueError('Target cannot be empty')
        return v.strip()


class AssetOut(AssetBase):
    """Asset response."""
    id: int
    company_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


# Scan schemas
class ScanBase(BaseModel):
    """Base scan schema."""
    asset_id: int = Field(..., gt=0, description="Asset ID")


class ScanIn(ScanBase):
    """Scan creation request."""
    pass


class ScanOut(BaseModel):
    """Scan response."""
    id: int
    asset_id: int
    target: str
    status: str = Field(..., description="Scan status: queued, running, completed, failed")
    security_score: Optional[int] = Field(None, ge=0, le=100)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# Finding schemas
class FindingBase(BaseModel):
    """Base finding schema."""
    severity: str = Field(..., description="Severity level: critical, high, medium, low, info")
    title: str = Field(..., min_length=1, max_length=255, description="Finding title")
    description: str = Field(..., description="Detailed description")
    evidence: str = Field(default="", description="Evidence of the finding")
    remediation: str = Field(default="", description="Remediation steps")
    
    @validator('severity')
    def validate_severity(cls, v):
        """Validate severity level."""
        valid_levels = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in valid_levels:
            raise ValueError(f"Severity must be one of {valid_levels}")
        return v.lower()


class FindingIn(FindingBase):
    """Finding creation request."""
    scan_id: int = Field(..., gt=0)


class FindingOut(FindingBase):
    """Finding response."""
    id: int
    scan_id: int
    
    class Config:
        from_attributes = True


# Auth schemas
class LoginRequest(BaseModel):
    """Login request."""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    """Token response."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int


class APIKeyResponse(BaseModel):
    """API key response."""
    api_key: str
    key_id: str
    created_at: datetime
    expires_at: Optional[datetime] = None


# Error schemas
class ErrorDetail(BaseModel):
    """Error detail."""
    code: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationError(BaseModel):
    """Validation error response."""
    detail: str
    errors: Optional[List[dict]] = None


# Health check
class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    environment: str
