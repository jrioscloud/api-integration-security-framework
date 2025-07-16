"""
JWT Authentication Handler with AWS Secrets Manager Integration

This module demonstrates enterprise authentication patterns with secure
secret management, addressing requirements for gaming and healthcare
environments with high security standards.
"""

import jwt
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from .secrets_manager import secrets_manager

logger = logging.getLogger(__name__)

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthHandler:
    """
    Enterprise JWT authentication with AWS Secrets Manager integration
    Demonstrates secure token management patterns for third-party integrations
    """
    
    def __init__(self):
        """Initialize authentication handler with secure defaults"""
        self.algorithm = "HS256"
        self.token_expiration_hours = 24
        logger.info("🔐 JWT Authentication handler initialized")
    
    async def get_signing_key(self) -> str:
        """
        Retrieve JWT signing key from AWS Secrets Manager
        Demonstrates secure key management for authentication
        """
        secret_data = await secrets_manager.get_secret("jwt-signing-key")
        
        if not secret_data or 'secret_key' not in secret_data:
            logger.error("❌ JWT signing key not found in secrets manager")
            # In production, this would fail hard. For demo, use a fallback
            return "demo_fallback_key_do_not_use_in_production"
        
        return secret_data['secret_key']
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt for secure storage"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    async def create_access_token(self, 
                                  user_id: str, 
                                  email: str, 
                                  roles: list = None,
                                  additional_claims: Dict[str, Any] = None) -> str:
        """
        Create JWT access token with comprehensive claims
        
        Args:
            user_id: Unique user identifier
            email: User email address
            roles: List of user roles for authorization
            additional_claims: Additional claims for specialized use cases
            
        Returns:
            Encoded JWT token string
        """
        if roles is None:
            roles = ["user"]
        
        if additional_claims is None:
            additional_claims = {}
        
        # Get signing key from secure storage
        signing_key = await self.get_signing_key()
        
        # Create comprehensive token payload
        now = datetime.utcnow()
        payload = {
            # Standard JWT claims
            "sub": user_id,  # Subject (user ID)
            "iat": now,      # Issued at
            "exp": now + timedelta(hours=self.token_expiration_hours),  # Expiration
            "jti": f"{user_id}_{int(now.timestamp())}",  # JWT ID for tracking
            
            # Custom claims for application context
            "email": email,
            "roles": roles,
            "type": "access_token",
            "issuer": "api-integration-security-framework",
            
            # Security metadata
            "auth_method": "password",
            "device_id": additional_claims.get("device_id", "unknown"),
            "ip_address": additional_claims.get("ip_address", "unknown"),
            
            # Additional custom claims
            **additional_claims
        }
        
        try:
            token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
            logger.info(f"✅ JWT token created for user: {email}")
            return token
            
        except Exception as e:
            logger.error(f"❌ Failed to create JWT token: {str(e)}")
            raise Exception("Token creation failed")
    
    async def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and validate JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload if valid, None if invalid
        """
        try:
            # Get signing key from secure storage
            signing_key = await self.get_signing_key()
            
            # Decode token with comprehensive validation
            payload = jwt.decode(
                token, 
                signing_key, 
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "require": ["sub", "exp", "iat"]
                }
            )
            
            # Additional validation for application-specific claims
            if payload.get("type") != "access_token":
                logger.warning("⚠️  Invalid token type")
                return None
            
            if payload.get("issuer") != "api-integration-security-framework":
                logger.warning("⚠️  Invalid token issuer")
                return None
            
            logger.info(f"✅ JWT token validated for user: {payload.get('email')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("⚠️  JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"⚠️  Invalid JWT token: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"❌ JWT token decode error: {str(e)}")
            return None
    
    async def create_service_token(self, 
                                   service_name: str, 
                                   permissions: list = None) -> str:
        """
        Create service-to-service authentication token
        Demonstrates machine-to-machine authentication patterns
        
        Args:
            service_name: Name of the service requesting access
            permissions: List of specific permissions granted
            
        Returns:
            Service authentication token
        """
        if permissions is None:
            permissions = ["read"]
        
        signing_key = await self.get_signing_key()
        
        now = datetime.utcnow()
        payload = {
            "sub": f"service:{service_name}",
            "iat": now,
            "exp": now + timedelta(hours=1),  # Shorter expiration for service tokens
            "type": "service_token",
            "service_name": service_name,
            "permissions": permissions,
            "issuer": "api-integration-security-framework"
        }
        
        try:
            token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
            logger.info(f"✅ Service token created for: {service_name}")
            return token
            
        except Exception as e:
            logger.error(f"❌ Failed to create service token: {str(e)}")
            raise Exception("Service token creation failed")
    
    def extract_user_from_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract user information from validated token payload
        
        Args:
            payload: Validated JWT payload
            
        Returns:
            User information dictionary
        """
        return {
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
            "roles": payload.get("roles", []),
            "auth_method": payload.get("auth_method", "unknown"),
            "expires_at": payload.get("exp"),
            "issued_at": payload.get("iat"),
            "device_id": payload.get("device_id"),
            "ip_address": payload.get("ip_address")
        }
    
    def has_role(self, payload: Dict[str, Any], required_role: str) -> bool:
        """
        Check if user has required role for authorization
        
        Args:
            payload: Validated JWT payload
            required_role: Role required for access
            
        Returns:
            True if user has required role
        """
        user_roles = payload.get("roles", [])
        return required_role in user_roles or "admin" in user_roles
    
    def has_permission(self, payload: Dict[str, Any], required_permission: str) -> bool:
        """
        Check if service token has required permission
        
        Args:
            payload: Validated JWT payload (service token)
            required_permission: Permission required for access
            
        Returns:
            True if service has required permission
        """
        if payload.get("type") != "service_token":
            return False
        
        permissions = payload.get("permissions", [])
        return required_permission in permissions or "admin" in permissions


# Global instance for dependency injection
auth_handler = AuthHandler()
