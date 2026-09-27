"""
Authentication module for SecureZim API.
Supports JWT tokens and API keys.
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from .config import get_settings
from .db import get_db


# Pydantic models for auth
class TokenData(BaseModel):
    """JWT token payload."""
    sub: str
    company_id: int
    exp: datetime
    iat: datetime
    type: str = "access"


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
    last_used: Optional[datetime] = None


class UserCredentials(BaseModel):
    """User login credentials."""
    username: str
    password: str


class APIKeyCreate(BaseModel):
    """Create API key request."""
    name: str
    expires_in_days: Optional[int] = None


# Security scheme
security = HTTPBearer()


class AuthenticationError(Exception):
    """Authentication error."""
    pass


class JWTHandler:
    """JWT token handler."""
    
    def __init__(self, settings=None):
        self.settings = settings or get_settings()
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.settings.secret_key,
            algorithm=self.settings.algorithm
        )
        return encoded_jwt
    
    def create_refresh_token(self, data: dict) -> str:
        """Create JWT refresh token."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(
            days=self.settings.refresh_token_expire_days
        )
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.settings.secret_key,
            algorithm=self.settings.algorithm
        )
        return encoded_jwt
    
    def verify_token(self, token: str) -> TokenData:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.settings.secret_key,
                algorithms=[self.settings.algorithm]
            )
            return TokenData(**payload)
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")


class APIKeyManager:
    """API key management."""
    
    @staticmethod
    def generate_key(prefix: str = "") -> Tuple[str, str]:
        """Generate new API key with prefix."""
        settings = get_settings()
        key_prefix = prefix or settings.api_key_prefix
        random_part = secrets.token_urlsafe(32)
        return f"{key_prefix}{random_part}", secrets.token_hex(16)
    
    @staticmethod
    def hash_key(key: str) -> str:
        """Hash API key for storage (use proper hashing in production)."""
        # In production, use bcrypt or similar
        import hashlib
        return hashlib.sha256(key.encode()).hexdigest()


async def get_current_user(
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Get current authenticated user from JWT or API key."""
    token = credentials.credentials
    settings = get_settings()
    
    # Try JWT first
    if token.startswith("eyJ"):  # JWT header
        try:
            jwt_handler = JWTHandler(settings)
            token_data = jwt_handler.verify_token(token)
            return {
                "username": token_data.sub,
                "company_id": token_data.company_id,
                "type": "jwt"
            }
        except AuthenticationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # Try API key
    if settings.enable_api_keys:
        # This would query the database for API key
        # Implementation depends on your API key storage model
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def optional_auth(
    credentials: Optional[HTTPAuthCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[dict]:
    """Optional authentication - returns None if not provided."""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None
