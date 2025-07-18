# Copyright (c) 2025 Jaime Rios. All rights reserved.
# This software is provided for portfolio demonstration and educational purposes only.
# Commercial use requires explicit written permission from the author.

"""
Integrations Router

This module provides endpoints for managing third-party integrations
demonstrating secure API integration patterns with comprehensive monitoring.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

from ..security.auth_handler import auth_handler
from ..integrations.stripe_integration import stripe_integration

logger = logging.getLogger(__name__)
security = HTTPBearer()

router = APIRouter()


# Pydantic models for request/response validation
class PaymentIntentRequest(BaseModel):
    """Payment intent creation request"""
    amount: int  # Amount in cents
    currency: str = "usd"
    customer_id: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None


class PaymentIntentResponse(BaseModel):
    """Payment intent response"""
    id: str
    amount: int
    currency: str
    status: str
    client_secret: str
    created: int


class IntegrationStatus(BaseModel):
    """Integration health status model"""
    name: str
    status: str
    last_check: datetime
    capabilities: Dict[str, bool]
    error_message: Optional[str] = None


class IntegrationListResponse(BaseModel):
    """Response model for integration list"""
    integrations: List[IntegrationStatus]
    total_count: int
    healthy_count: int
    overall_status: str


@router.get("/status",
            response_model=IntegrationListResponse,
            summary="Integration Health Status",
            description="Get health status of all configured integrations")
async def get_integrations_status(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> IntegrationListResponse:
    """
    Get comprehensive health status of all integrations
    
    This endpoint demonstrates enterprise monitoring patterns:
    - Health check aggregation
    - Service dependency monitoring
    - Operational visibility for troubleshooting
    """
    # Validate authentication
    payload = await auth_handler.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    logger.info(f"🔍 Integration status check requested by: {payload.get('email')}")
    
    try:
        # Check all configured integrations
        integrations = []
        
        # Stripe integration health check
        stripe_health = await stripe_integration.health_check()
        integrations.append(IntegrationStatus(
            name="stripe",
            status=stripe_health["status"],
            last_check=datetime.fromisoformat(stripe_health["timestamp"].replace("Z", "+00:00")),
            capabilities=stripe_health["capabilities"],
            error_message=stripe_health.get("error")
        ))
        
        # Mock other integrations for demonstration
        mock_integrations = [
            {
                "name": "auth0",
                "status": "healthy",
                "capabilities": {"authentication": True, "user_management": True},
                "error": None
            },
            {
                "name": "salesforce",
                "status": "healthy", 
                "capabilities": {"crm_sync": True, "lead_management": True},
                "error": None
            }
        ]
        
        for mock_integration in mock_integrations:
            integrations.append(IntegrationStatus(
                name=mock_integration["name"],
                status=mock_integration["status"],
                last_check=datetime.utcnow(),
                capabilities=mock_integration["capabilities"],
                error_message=mock_integration["error"]
            ))
        
        # Calculate overall status
        healthy_count = sum(1 for integration in integrations if integration.status == "healthy")
        total_count = len(integrations)
        
        if healthy_count == total_count:
            overall_status = "healthy"
        elif healthy_count > 0:
            overall_status = "degraded"
        else:
            overall_status = "failed"
        
        logger.info(f"✅ Integration status check completed: {healthy_count}/{total_count} healthy")
        
        return IntegrationListResponse(
            integrations=integrations,
            total_count=total_count,
            healthy_count=healthy_count,
            overall_status=overall_status
        )
        
    except Exception as e:
        logger.error(f"❌ Integration status check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve integration status"
        )


@router.post("/stripe/payment-intent",
             response_model=Dict[str, Any],
             summary="Create Stripe Payment Intent",
             description="Create payment intent using secure Stripe integration")
async def create_payment_intent(
    request: Request,
    payment_data: PaymentIntentRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Create Stripe payment intent with comprehensive security
    
    This endpoint demonstrates secure third-party API integration:
    - Secure credential management via AWS Secrets Manager
    - Comprehensive audit logging for PCI compliance
    - Circuit breaker patterns for resilience
    - Input validation and sanitization
    """
    # Validate authentication and permissions
    payload = await auth_handler.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    # Check user has payment processing permissions
    if not auth_handler.has_role(payload, "admin") and \
       not any(role in ["doctor", "billing"] for role in payload.get("roles", [])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for payment processing"
        )
    
    client_ip = request.client.host
    user_email = payload.get("email")
    
    logger.info(f"💳 Payment intent creation requested by: {user_email} from IP: {client_ip}")
    
    try:
        # Validate amount (basic business logic)
        if payment_data.amount < 50:  # Minimum $0.50
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payment amount too small (minimum $0.50)"
            )
        
        if payment_data.amount > 10000000:  # Maximum $100,000
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payment amount exceeds maximum limit"
            )
        
        # Add audit metadata
        audit_metadata = {
            "created_by": user_email,
            "ip_address": client_ip,
            "request_id": getattr(request.state, 'request_id', 'unknown'),
            "compliance_context": "hipaa_enabled"
        }
        
        if payment_data.metadata:
            audit_metadata.update(payment_data.metadata)
        
        # Create payment intent using secure integration
        result = await stripe_integration.create_payment_intent(
            amount=payment_data.amount,
            currency=payment_data.currency,
            customer_id=payment_data.customer_id,
            metadata=audit_metadata
        )
        
        if not result:
            logger.error(f"❌ Payment intent creation failed for user: {user_email}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Payment service temporarily unavailable"
            )
        
        # Log successful payment intent creation
        logger.info(f"✅ Payment intent created: {result.get('id')} for user: {user_email}")
        
        return {
            "payment_intent_id": result.get("id"),
            "client_secret": result.get("client_secret"),
            "amount": result.get("amount"),
            "currency": result.get("currency"),
            "status": result.get("status"),
            "created": result.get("created"),
            "metadata": result.get("metadata", {})
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Payment intent creation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Payment processing error"
        )


@router.get("/stripe/payment-intent/{payment_intent_id}",
            summary="Retrieve Payment Intent",
            description="Retrieve payment intent details")
async def get_payment_intent(
    payment_intent_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Retrieve payment intent details with security validation
    """
    # Validate authentication
    payload = await auth_handler.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    logger.info(f"🔍 Payment intent retrieval: {payment_intent_id} by: {payload.get('email')}")
    
    try:
        result = await stripe_integration.retrieve_payment_intent(payment_intent_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Payment intent not found"
            )
        
        return {
            "id": result.get("id"),
            "amount": result.get("amount"),
            "currency": result.get("currency"),
            "status": result.get("status"),
            "created": result.get("created"),
            "metadata": result.get("metadata", {})
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Payment intent retrieval error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve payment intent"
        )


@router.post("/test-integration/{service_name}",
             summary="Test Integration Connectivity",
             description="Test connectivity and authentication for specific integration")
async def test_integration(
    service_name: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Test integration connectivity and authentication
    
    This endpoint demonstrates integration testing patterns:
    - Connectivity validation
    - Authentication verification
    - Service capability testing
    """
    # Validate authentication and admin role
    payload = await auth_handler.decode_token(credentials.credentials)
    if not payload or not auth_handler.has_role(payload, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    logger.info(f"🧪 Integration test requested for: {service_name} by: {payload.get('email')}")
    
    try:
        if service_name == "stripe":
            health_result = await stripe_integration.health_check()
            
            return {
                "service": service_name,
                "test_result": "passed" if health_result["status"] == "healthy" else "failed",
                "details": health_result,
                "tested_at": datetime.utcnow().isoformat(),
                "tested_by": payload.get("email")
            }
        
        else:
            # Mock test results for other integrations
            mock_results = {
                "auth0": {"status": "healthy", "response_time_ms": 120},
                "salesforce": {"status": "healthy", "response_time_ms": 350}
            }
            
            if service_name not in mock_results:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Integration '{service_name}' not found"
                )
            
            return {
                "service": service_name,
                "test_result": "passed",
                "details": mock_results[service_name],
                "tested_at": datetime.utcnow().isoformat(),
                "tested_by": payload.get("email")
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Integration test error for {service_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Integration test failed for {service_name}"
        )


@router.get("/audit/recent",
            summary="Recent Integration Activity",
            description="Get recent integration activity for audit purposes")
async def get_recent_integration_activity(
    limit: int = 50,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Get recent integration activity for audit and monitoring
    
    This endpoint demonstrates audit trail patterns for compliance
    """
    # Validate authentication
    payload = await auth_handler.decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    
    # Check audit access permissions
    if not auth_handler.has_role(payload, "admin") and \
       not any(role in ["auditor", "compliance"] for role in payload.get("roles", [])):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for audit data"
        )
    
    try:
        # In production, this would query the audit log database
        # For demo, return mock audit data
        mock_activities = [
            {
                "timestamp": "2025-07-15T10:30:00Z",
                "event_type": "payment_intent_created",
                "integration": "stripe",
                "user": "doctor@medconnect.com",
                "details": {"amount": 5000, "currency": "usd"},
                "status": "success"
            },
            {
                "timestamp": "2025-07-15T10:25:00Z",
                "event_type": "health_check",
                "integration": "auth0",
                "user": "system",
                "details": {"response_time_ms": 120},
                "status": "success"
            },
            {
                "timestamp": "2025-07-15T10:20:00Z",
                "event_type": "credential_rotation",
                "integration": "salesforce",
                "user": "system",
                "details": {"rotation_type": "automatic"},
                "status": "success"
            }
        ]
        
        return {
            "activities": mock_activities[:limit],
            "total_count": len(mock_activities),
            "retrieved_at": datetime.utcnow().isoformat(),
            "retrieved_by": payload.get("email")
        }
        
    except Exception as e:
        logger.error(f"❌ Audit data retrieval error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit data"
        )
