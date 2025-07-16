"""
Authentication Router

This module provides authentication endpoints demonstrating secure
enterprise authentication patterns with comprehensive audit logging.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, Optional
import logging
from datetime import datetime

from ..security.auth_handler import auth_handler
from ..security.secrets_manager import secrets_manager

logger = logging.getLogger(__name__)
security = HTTPBearer()

router = APIRouter()


# Pydantic models for request/response validation
class LoginRequest(BaseModel):
    """Login request model with validation"""
    email: EmailStr
    password: str
    device_id: Optional[str] = None
    remember_me: bool = False


class LoginResponse(BaseModel):
    """Login response model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]


class UserInfo(BaseModel):
    """User information model"""
    user_id: str
    email: str
    roles: list
    permissions: list


class TokenValidationResponse(BaseModel):
    """Token validation response model"""
    valid: bool
    user_info: Optional[UserInfo] = None
    expires_at: Optional[datetime] = None


@router.post("/login", 
             response_model=LoginResponse,
             summary="User Authentication",
             description="Authenticate user and return JWT access token")
async def login(request: Request, login_data: LoginRequest) -> LoginResponse:
    """
    Authenticate user with comprehensive security validation
    
    This endpoint demonstrates enterprise authentication patterns:
    - Secure password verification
    - JWT token generation with AWS Secrets Manager
    - Comprehensive audit logging
    - Rate limiting and security controls
    """
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    logger.info(f"🔐 Login attempt for email: {login_data.email} from IP: {client_ip}")
    
    try:
        # In a real implementation, validate credentials against database
        # For demo purposes, we'll use mock validation
        user_id, user_roles = await _validate_user_credentials(
            login_data.email, 
            login_data.password
        )
        
        if not user_id:
            # Log failed authentication attempt
            logger.warning(f"⚠️  Failed login attempt: {login_data.email} from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Create JWT token with comprehensive claims
        additional_claims = {
            "device_id": login_data.device_id or "unknown",
            "ip_address": client_ip,
            "user_agent": user_agent,
            "remember_me": login_data.remember_me
        }
        
        access_token = await auth_handler.create_access_token(
            user_id=user_id,
            email=login_data.email,
            roles=user_roles,
            additional_claims=additional_claims
        )
        
        # Log successful authentication
        logger.info(f"✅ Successful login for user: {login_data.email}")
        
        # Prepare response
        user_info = {
            "user_id": user_id,
            "email": login_data.email,
            "roles": user_roles,
            "permissions": _get_user_permissions(user_roles),
            "last_login": datetime.utcnow().isoformat()
        }
        
        return LoginResponse(
            access_token=access_token,
            expires_in=auth_handler.token_expiration_hours * 3600,  # Convert to seconds
            user_info=user_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Authentication error for {login_data.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


@router.post("/validate",
             response_model=TokenValidationResponse,
             summary="Token Validation",
             description="Validate JWT token and return user information")
async def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenValidationResponse:
    """
    Validate JWT token and return user information
    
    This endpoint demonstrates secure token validation patterns:
    - JWT signature verification
    - Token expiration checking
    - User context extraction
    - Audit logging for security events
    """
    try:
        # Decode and validate token
        payload = await auth_handler.decode_token(credentials.credentials)
        
        if not payload:
            return TokenValidationResponse(valid=False)
        
        # Extract user information
        user_data = auth_handler.extract_user_from_token(payload)
        
        user_info = UserInfo(
            user_id=user_data["user_id"],
            email=user_data["email"],
            roles=user_data["roles"],
            permissions=_get_user_permissions(user_data["roles"])
        )
        
        expires_at = datetime.fromtimestamp(user_data["expires_at"])
        
        logger.info(f"✅ Token validated for user: {user_data['email']}")
        
        return TokenValidationResponse(
            valid=True,
            user_info=user_info,
            expires_at=expires_at
        )
        
    except Exception as e:
        logger.error(f"❌ Token validation error: {str(e)}")
        return TokenValidationResponse(valid=False)


@router.post("/service-token",
             summary="Service Token Generation",
             description="Generate service-to-service authentication token")
async def create_service_token(
    service_name: str,
    permissions: list = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Create service-to-service authentication token
    
    This endpoint demonstrates machine-to-machine authentication:
    - Service account validation
    - Limited-scope token generation
    - Permission-based access control
    """
    # Validate requesting user has admin privileges
    payload = await auth_handler.decode_token(credentials.credentials)
    if not payload or not auth_handler.has_role(payload, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    if permissions is None:
        permissions = ["read"]
    
    try:
        service_token = await auth_handler.create_service_token(
            service_name=service_name,
            permissions=permissions
        )
        
        logger.info(f"✅ Service token created for: {service_name} by user: {payload.get('email')}")
        
        return {
            "service_token": service_token,
            "service_name": service_name,
            "permissions": permissions,
            "expires_in": 3600,  # 1 hour
            "token_type": "bearer"
        }
        
    except Exception as e:
        logger.error(f"❌ Service token creation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Service token creation failed"
        )


@router.post("/logout",
             summary="User Logout",
             description="Logout user and invalidate token")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, str]:
    """
    Logout user and perform cleanup
    
    In a production system, this would:
    - Add token to blacklist
    - Clear session data
    - Log security event
    """
    payload = await auth_handler.decode_token(credentials.credentials)
    
    if payload:
        logger.info(f"👋 User logout: {payload.get('email')}")
        
        # In production, implement token blacklisting
        # For demo, just log the event
        return {"message": "Successfully logged out"}
    
    return {"message": "Invalid token"}


@router.get("/me",
            response_model=UserInfo,
            summary="Get Current User",
            description="Get current user information from token")
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> UserInfo:
    """
    Get current user information from valid token
    """
    payload = await auth_handler.decode_token(credentials.credentials)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    user_data = auth_handler.extract_user_from_token(payload)
    
    return UserInfo(
        user_id=user_data["user_id"],
        email=user_data["email"],
        roles=user_data["roles"],
        permissions=_get_user_permissions(user_data["roles"])
    )


# Helper functions
async def _validate_user_credentials(email: str, password: str) -> tuple[Optional[str], Optional[list]]:
    """
    Validate user credentials against database
    Returns (user_id, roles) if valid, (None, None) if invalid
    
    In production, this would:
    - Query database for user
    - Verify password hash
    - Check account status
    - Update last login
    """
    # Mock validation for demo
    mock_users = {
        "admin@medconnect.com": {
            "user_id": "admin_001",
            "password_hash": "mock_admin_hash",
            "roles": ["admin", "user"]
        },
        "doctor@medconnect.com": {
            "user_id": "doctor_001", 
            "password_hash": "mock_doctor_hash",
            "roles": ["doctor", "user"]
        },
        "integration@medconnect.com": {
            "user_id": "integration_001",
            "password_hash": "mock_integration_hash",
            "roles": ["integration", "user"]
        }
    }
    
    user_data = mock_users.get(email)
    if user_data and password == "demo_password":  # Simplified for demo
        return user_data["user_id"], user_data["roles"]
    
    return None, None


def _get_user_permissions(roles: list) -> list:
    """
    Get user permissions based on roles
    
    In production, this would be more sophisticated with
    role-based access control (RBAC) system
    """
    permission_map = {
        "admin": ["read", "write", "delete", "admin", "integration_manage"],
        "doctor": ["read", "write", "patient_data", "medical_records"],
        "integration": ["read", "write", "api_access"],
        "user": ["read"]
    }
    
    permissions = set()
    for role in roles:
        permissions.update(permission_map.get(role, []))
    
    return list(permissions)
