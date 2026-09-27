"""
Production API configuration with environment-based settings.
Supports dev, staging, and production environments.
"""
import os
from enum import Enum
from pydantic_settings import BaseSettings
from functools import lru_cache


class Environment(str, Enum):
    """Deployment environment."""
    DEV = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings from environment variables."""
    
    # Environment
    environment: Environment = Environment.DEV
    debug: bool = False
    
    # Database
    database_url: str = "sqlite:///./securezim.db"
    
    # API
    api_title: str = "SecureZim API"
    api_version: str = "1.0.0"
    api_description: str = "Defensive cybersecurity monitoring platform"
    
    # Security
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]
    cors_credentials: bool = True
    cors_methods: list[str] = ["*"]
    cors_headers: list[str] = ["*"]
    
    # API Keys
    enable_api_keys: bool = True
    api_key_prefix: str = "szim_"
    
    # Scanning
    scan_timeout: int = int(os.getenv("SCAN_TIMEOUT", "30"))
    max_concurrent_scans: int = 5
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_period: int = 60  # seconds
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == Environment.PRODUCTION
    
    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.environment == Environment.DEV
    
    def get_database_config(self) -> dict:
        """Get database configuration for current environment."""
        config = {
            "url": self.database_url,
            "echo": self.debug,
        }
        
        if "postgresql" in self.database_url:
            config.update({
                "pool_size": 20 if self.is_production else 5,
                "max_overflow": 10 if self.is_production else 5,
                "pool_pre_ping": True,
                "pool_recycle": 3600,
            })
        
        return config


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
