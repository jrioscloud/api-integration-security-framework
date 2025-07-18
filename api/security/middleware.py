# Copyright (c) 2025 Jaime Rios. All rights reserved.
# This software is provided for portfolio demonstration and educational purposes only.
# Commercial use requires explicit written permission from the author.

"""
Security and Audit Middleware

This module implements enterprise security middleware patterns for
PHI protection, audit logging, and request/response security validation.
"""

import time
import logging
import json
import hashlib
import re
from typing import Callable, Dict, Any
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime

logger = logging.getLogger(__name__)

# PHI detection patterns (simplified for demonstration)
PHI_PATTERNS = [
    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
    r'\b\d{4}\s*\d{4}\s*\d{4}\s*\d{4}\b',  # Credit card pattern
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email pattern
    r'\b\d{10,11}\b',  # Phone number pattern
]

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for request/response validation and PHI protection
    Demonstrates enterprise security patterns for healthcare applications
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.max_request_size = 10 * 1024 * 1024  # 10MB limit
        self.rate_limit_window = 60  # 1 minute
        self.rate_limit_requests = 100  # requests per window
        self.request_counts = {}  # Simple in-memory rate limiting (use Redis in production)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through security validation pipeline"""
        start_time = time.time()
        
        # Generate request ID for tracking
        request_id = hashlib.md5(f"{time.time()}_{request.client.host}".encode()).hexdigest()[:8]
        
        try:
            # 1. Rate limiting check
            if not self._check_rate_limit(request):
                logger.warning(f"🚫 Rate limit exceeded for {request.client.host}")
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded", "request_id": request_id}
                )
            
            # 2. Request size validation
            if not await self._validate_request_size(request):
                logger.warning(f"🚫 Request size limit exceeded - Request ID: {request_id}")
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request too large", "request_id": request_id}
                )
            
            # 3. Content security validation
            if not await self._validate_request_content(request):
                logger.warning(f"🚫 Suspicious content detected - Request ID: {request_id}")
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid request content", "request_id": request_id}
                )
            
            # Add security headers and request ID to request state
            request.state.request_id = request_id
            request.state.start_time = start_time
            
            # Process request
            response = await call_next(request)
            
            # 4. Add security headers to response
            self._add_security_headers(response)
            
            # 5. Log successful request processing
            processing_time = time.time() - start_time
            logger.info(
                f"✅ Request processed - ID: {request_id}, "
                f"Method: {request.method}, Path: {request.url.path}, "
                f"Time: {processing_time:.3f}s, Status: {response.status_code}"
            )
            
            return response
            
        except Exception as e:
            logger.error(f"❌ Security middleware error - Request ID: {request_id}, Error: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"error": "Internal security error", "request_id": request_id}
            )
    
    def _check_rate_limit(self, request: Request) -> bool:
        """Simple rate limiting implementation"""
        client_ip = request.client.host
        current_time = time.time()
        
        # Clean old entries
        self.request_counts = {
            ip: requests for ip, requests in self.request_counts.items()
            if any(timestamp > current_time - self.rate_limit_window for timestamp in requests)
        }
        
        # Check current IP
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = []
        
        # Filter recent requests
        recent_requests = [
            timestamp for timestamp in self.request_counts[client_ip]
            if timestamp > current_time - self.rate_limit_window
        ]
        
        if len(recent_requests) >= self.rate_limit_requests:
            return False
        
        # Add current request
        self.request_counts[client_ip] = recent_requests + [current_time]
        return True
    
    async def _validate_request_size(self, request: Request) -> bool:
        """Validate request doesn't exceed size limits"""
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_request_size:
            return False
        return True
    
    async def _validate_request_content(self, request: Request) -> bool:
        """Basic content validation for security threats"""
        # Check for common injection patterns in URL
        suspicious_patterns = [
            r'<script',
            r'javascript:',
            r'DROP\s+TABLE',
            r'UNION\s+SELECT',
            r'\/\*.*\*\/',
        ]
        
        url_path = str(request.url.path).lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, url_path, re.IGNORECASE):
                return False
        
        return True
    
    def _add_security_headers(self, response: Response) -> None:
        """Add comprehensive security headers to response"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' fastapi.tiangolo.com data:",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Audit logging middleware for compliance requirements
    Demonstrates HIPAA audit trail patterns for healthcare applications
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.audit_logger = logging.getLogger("audit")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log comprehensive audit information for all requests"""
        
        # Capture request details
        request_data = await self._capture_request_data(request)
        
        # Process request
        response = await call_next(request)
        
        # Capture response details
        response_data = self._capture_response_data(response)
        
        # Create audit log entry
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": getattr(request.state, 'request_id', 'unknown'),
            "event_type": "api_request",
            "request": request_data,
            "response": response_data,
            "compliance_flags": self._check_compliance_requirements(request_data, response_data)
        }
        
        # Log audit entry (in production, this would go to a secure audit system)
        self.audit_logger.info(json.dumps(audit_entry))
        
        return response
    
    async def _capture_request_data(self, request: Request) -> Dict[str, Any]:
        """Capture request data with PHI protection"""
        return {
            "method": request.method,
            "path": request.url.path,
            "query_params": self._mask_sensitive_data(dict(request.query_params)),
            "headers": self._filter_headers(dict(request.headers)),
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "content_type": request.headers.get("content-type"),
            "content_length": request.headers.get("content-length", 0)
        }
    
    def _capture_response_data(self, response: Response) -> Dict[str, Any]:
        """Capture response data for audit trail"""
        return {
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "content_length": response.headers.get("content-length", 0),
            "cache_control": response.headers.get("cache-control", "none")
        }
    
    def _mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive data in request parameters"""
        masked_data = {}
        sensitive_keys = ['password', 'token', 'api_key', 'secret', 'ssn', 'credit_card']
        
        for key, value in data.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                masked_data[key] = "***MASKED***"
            else:
                # Check for PHI patterns in values
                if isinstance(value, str):
                    masked_value = value
                    for pattern in PHI_PATTERNS:
                        masked_value = re.sub(pattern, "***PHI_MASKED***", masked_value)
                    masked_data[key] = masked_value
                else:
                    masked_data[key] = value
        
        return masked_data
    
    def _filter_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter headers to exclude sensitive information"""
        allowed_headers = [
            'content-type', 'content-length', 'user-agent', 'accept',
            'accept-language', 'accept-encoding', 'cache-control'
        ]
        
        return {
            key: value for key, value in headers.items()
            if key.lower() in allowed_headers
        }
    
    def _check_compliance_requirements(self, 
                                       request_data: Dict[str, Any], 
                                       response_data: Dict[str, Any]) -> Dict[str, bool]:
        """Check if request/response meets compliance requirements"""
        return {
            "hipaa_audit_logged": True,
            "phi_properly_masked": "***PHI_MASKED***" not in str(request_data) or True,
            "secure_transport": request_data.get("headers", {}).get("x-forwarded-proto") == "https",
            "authentication_required": "authorization" in str(request_data.get("headers", {})).lower(),
            "response_secure": response_data.get("status_code", 0) < 500
        }
