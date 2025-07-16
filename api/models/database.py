"""
Database Models for API Integration Security Framework

This module defines the database schema for tracking integrations,
audit logs, and user management with encryption and compliance features.
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://user:password@localhost:5432/api_security_framework"
)

# For local development with SQLite
if "pytest" in os.environ.get("_", "") or os.getenv("ENVIRONMENT") == "test":
    DATABASE_URL = "sqlite:///./test_database.db"

Base = declarative_base()


class User(Base):
    """
    User model with authentication and authorization features
    Demonstrates secure user management patterns for enterprise applications
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    roles = Column(JSON, default=lambda: ["user"])  # Store roles as JSON array
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Security fields
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Compliance fields
    terms_accepted_at = Column(DateTime(timezone=True), nullable=True)
    privacy_policy_accepted_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<User(email='{self.email}', active={self.is_active})>"


class Integration(Base):
    """
    Integration model for tracking third-party service configurations
    Demonstrates secure integration management with audit trails
    """
    __tablename__ = "integrations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)  # stripe, auth0, salesforce, etc.
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Configuration
    is_enabled = Column(Boolean, default=True)
    configuration = Column(JSON, default=dict)  # Store integration-specific config
    secrets_path = Column(String(255), nullable=False)  # AWS Secrets Manager path
    
    # Health monitoring
    last_health_check = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(String(50), default="unknown")  # healthy, degraded, failed
    last_error = Column(Text, nullable=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by_user_id = Column(Integer, nullable=True)
    
    # Compliance fields
    compliance_status = Column(String(50), default="pending")  # compliant, non_compliant, pending
    last_compliance_check = Column(DateTime(timezone=True), nullable=True)
    compliance_notes = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Integration(name='{self.name}', enabled={self.is_enabled})>"


class AuditLog(Base):
    """
    Comprehensive audit log model for compliance requirements
    Demonstrates audit trail patterns for HIPAA and SOC2 compliance
    """
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Event identification
    event_type = Column(String(100), nullable=False, index=True)
    event_category = Column(String(50), nullable=False, index=True)  # auth, api, admin, etc.
    event_description = Column(Text, nullable=False)
    
    # Context information
    user_id = Column(Integer, nullable=True, index=True)
    session_id = Column(String(255), nullable=True)
    request_id = Column(String(100), nullable=True, index=True)
    
    # Technical details
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    method = Column(String(10), nullable=True)  # HTTP method
    endpoint = Column(String(500), nullable=True)
    status_code = Column(Integer, nullable=True)
    
    # Data and metadata
    request_data = Column(JSON, nullable=True)  # Sanitized request data
    response_data = Column(JSON, nullable=True)  # Sanitized response data
    event_metadata = Column(JSON, nullable=True)  # Additional context
    
    # Compliance fields
    contains_phi = Column(Boolean, default=False)
    compliance_flags = Column(JSON, default=dict)
    retention_until = Column(DateTime(timezone=True), nullable=True)
    
    # Timing
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    processing_time_ms = Column(Integer, nullable=True)
    
    # Security
    security_level = Column(String(20), default="standard")  # standard, sensitive, critical
    masked_fields = Column(JSON, default=list)  # List of fields that were masked
    
    def __repr__(self):
        return f"<AuditLog(type='{self.event_type}', user_id={self.user_id})>"


class APIKey(Base):
    """
    API key model for service-to-service authentication
    Demonstrates secure API key management patterns
    """
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Key identification
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    key_hash = Column(String(255), nullable=False, unique=True)  # Hashed API key
    key_prefix = Column(String(10), nullable=False)  # First few chars for identification
    
    # Access control
    user_id = Column(Integer, nullable=False, index=True)
    permissions = Column(JSON, default=list)  # List of permissions
    allowed_ips = Column(JSON, default=list)  # IP whitelist
    rate_limit = Column(Integer, default=1000)  # Requests per hour
    
    # Status
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    usage_count = Column(Integer, default=0)
    
    # Lifecycle
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id = Column(Integer, nullable=True)
    revoke_reason = Column(String(255), nullable=True)
    
    def __repr__(self):
        return f"<APIKey(name='{self.name}', active={self.is_active})>"


class PolicyViolation(Base):
    """
    Policy violation tracking for compliance monitoring
    Demonstrates automated policy enforcement patterns
    """
    __tablename__ = "policy_violations"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Violation details
    policy_name = Column(String(255), nullable=False, index=True)
    policy_category = Column(String(100), nullable=False, index=True)
    violation_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    
    # Context
    resource_type = Column(String(100), nullable=True)  # user, integration, api_key, etc.
    resource_id = Column(String(255), nullable=True)
    integration_name = Column(String(100), nullable=True)
    
    # Details
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    violation_data = Column(JSON, nullable=True)
    
    # Resolution
    status = Column(String(50), default="open")  # open, acknowledged, resolved, false_positive
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by_user_id = Column(Integer, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Timing
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    first_occurrence = Column(DateTime(timezone=True), server_default=func.now())
    occurrence_count = Column(Integer, default=1)
    
    def __repr__(self):
        return f"<PolicyViolation(policy='{self.policy_name}', severity='{self.severity}')>"


# Database initialization functions
async def create_tables():
    """Create all database tables"""
    try:
        from sqlalchemy import create_engine
        
        if "sqlite" in DATABASE_URL:
            engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
        else:
            engine = create_engine(DATABASE_URL)
        
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to create database tables: {str(e)}")
        raise


def get_database():
    """Get database session for dependency injection"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    if "sqlite" in DATABASE_URL:
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    else:
        engine = create_engine(DATABASE_URL)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
