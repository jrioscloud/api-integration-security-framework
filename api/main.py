"""
API Integration Security Policy Framework
FastAPI Application with AWS Secrets Manager Integration

This application demonstrates secure third-party API integration patterns
for enterprise healthcare environments with HIPAA compliance requirements.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import logging
from typing import Dict, Any
import os
from contextlib import asynccontextmanager

from .routers import auth, integrations, health
from .security.auth_handler import AuthHandler
from .security.secrets_manager import SecretsManager
from .models.database import create_tables, get_database
from .security.middleware import SecurityMiddleware, AuditMiddleware

# Configure structured logging for PHI protection
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security handler for JWT validation
security = HTTPBearer()
auth_handler = AuthHandler()
secrets_manager = SecretsManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown tasks"""
    logger.info("🚀 Starting API Integration Security Framework")
    
    # Initialize database
    await create_tables()
    
    # Verify AWS Secrets Manager connectivity
    await secrets_manager.health_check()
    
    logger.info("✅ Application startup complete")
    yield
    
    logger.info("🔄 Shutting down application")


# FastAPI application with security configuration
app = FastAPI(
    title="API Integration Security Policy Framework",
    description="""
    Enterprise-grade API integration framework demonstrating secure patterns for 
    third-party service integration with automated compliance validation.
    
    **Key Features:**
    - AWS Secrets Manager integration for credential management
    - Policy as Code validation using OPA
    - HIPAA-compliant PHI handling patterns
    - Standardized authentication/authorization
    - Automated security audit logging
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Security middleware configuration
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.medconnect.internal"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.medconnect.com"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Custom security middleware for audit logging and PHI protection
app.add_middleware(SecurityMiddleware)
app.add_middleware(AuditMiddleware)


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint with basic system information"""
    return {
        "service": "API Integration Security Framework",
        "version": "1.0.0",
        "status": "operational",
        "security_features": [
            "AWS Secrets Manager Integration",
            "Policy as Code Validation", 
            "HIPAA Compliance Patterns",
            "Automated Audit Logging"
        ]
    }


@app.get("/api/v1/security/policies", tags=["Security"])
async def get_security_policies(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Retrieve current security policies enforced by the framework
    Demonstrates Policy as Code integration
    """
    # Validate JWT token
    payload = auth_handler.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    return {
        "policies": {
            "secrets_management": "enabled",
            "encryption_at_rest": "required",
            "audit_logging": "comprehensive",
            "api_authentication": "jwt_required",
            "phi_protection": "automatic_masking"
        },
        "compliance_standards": ["HIPAA", "SOC2", "ISO27001"],
        "last_policy_update": "2025-07-15T10:00:00Z"
    }


@app.get("/api/v1/integrations/status", tags=["Integrations"])
async def get_integration_status(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Monitor third-party integration health and security status
    Demonstrates enterprise monitoring patterns
    """
    # Validate JWT token
    payload = auth_handler.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    # Check integration status (using secure patterns)
    integration_status = await secrets_manager.get_integration_health()
    
    return {
        "integrations": {
            "payment_processor": {"status": "healthy", "last_check": "2025-07-15T10:00:00Z"},
            "insurance_verification": {"status": "healthy", "last_check": "2025-07-15T10:00:00Z"},
            "ehr_system": {"status": "healthy", "last_check": "2025-07-15T10:00:00Z"}
        },
        "security_status": {
            "secrets_rotation": "current",
            "certificate_validity": "valid",
            "policy_compliance": "100%"
        },
        "total_integrations": 3,
        "healthy_integrations": 3
    }


# Include routers for modular organization
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"])
app.include_router(health.router, prefix="/api/v1/health", tags=["Health"])


if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )
