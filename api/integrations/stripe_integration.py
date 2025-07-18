# Copyright (c) 2025 Jaime Rios. All rights reserved.
# This software is provided for portfolio demonstration and educational purposes only.
# Commercial use requires explicit written permission from the author.

"""
Stripe Payment Integration Module

This module demonstrates secure third-party API integration patterns
for payment processing, showcasing the security and compliance patterns
required for enterprise healthcare and gaming environments.

Key Features:
- Secure credential management via AWS Secrets Manager
- Circuit breaker patterns for high availability
- Comprehensive audit logging for PCI compliance
- Error handling and retry logic for production resilience
"""

import httpx
import logging
import json
from typing import Dict, Optional, Any
from datetime import datetime
import asyncio
from ..security.secrets_manager import secrets_manager

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """
    Circuit breaker implementation for third-party API resilience
    Prevents cascade failures when external services are down
    """
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def can_execute(self) -> bool:
        """Check if operation can be executed based on circuit state"""
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            if self.last_failure_time and \
               (datetime.now().timestamp() - self.last_failure_time) > self.timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self):
        """Record successful operation"""
        self.failure_count = 0
        self.state = "CLOSED"
    
    def record_failure(self):
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure_time = datetime.now().timestamp()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


class StripeIntegration:
    """
    Secure Stripe payment integration demonstrating enterprise patterns
    for third-party API integration with comprehensive security controls
    """
    
    def __init__(self):
        """Initialize Stripe integration with security controls"""
        self.base_url = "https://api.stripe.com/v1"
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, timeout=30)
        self.max_retries = 3
        self.timeout = 30
        logger.info("💳 Stripe integration initialized with security controls")
    
    async def _get_credentials(self) -> Optional[Dict[str, str]]:
        """Retrieve Stripe credentials from AWS Secrets Manager"""
        credentials = await secrets_manager.get_api_credentials("stripe")
        
        if not credentials:
            logger.error("❌ Stripe credentials not available")
            return None
        
        # Validate required credentials
        required_fields = ['api_key', 'webhook_secret']
        missing_fields = [field for field in required_fields if field not in credentials]
        
        if missing_fields:
            logger.error(f"❌ Missing Stripe credential fields: {missing_fields}")
            return None
        
        return credentials
    
    async def _make_api_request(self, 
                                method: str, 
                                endpoint: str, 
                                data: Dict[str, Any] = None,
                                headers: Dict[str, str] = None) -> Optional[Dict[str, Any]]:
        """
        Make secure API request to Stripe with comprehensive error handling
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            data: Request payload
            headers: Additional headers
            
        Returns:
            API response data or None if failed
        """
        # Check circuit breaker state
        if not self.circuit_breaker.can_execute():
            logger.warning("🚫 Stripe API circuit breaker is OPEN - request blocked")
            return None
        
        # Get credentials
        credentials = await self._get_credentials()
        if not credentials:
            return None
        
        # Prepare request
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        default_headers = {
            "Authorization": f"Bearer {credentials['api_key']}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "MedConnect-API-Integration/1.0",
            "Stripe-Version": "2023-10-16"
        }
        
        if headers:
            default_headers.update(headers)
        
        # Execute request with retries
        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    logger.info(f"🔄 Stripe API request: {method} {endpoint} (attempt {attempt + 1})")
                    
                    response = await client.request(
                        method=method,
                        url=url,
                        data=data,
                        headers=default_headers
                    )
                    
                    if response.status_code == 200:
                        self.circuit_breaker.record_success()
                        result = response.json()
                        logger.info(f"✅ Stripe API request successful: {endpoint}")
                        return result
                    
                    elif response.status_code in [429, 502, 503, 504]:
                        # Retryable errors
                        logger.warning(f"⚠️  Stripe API retryable error: {response.status_code}")
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                            continue
                    
                    else:
                        # Non-retryable errors
                        logger.error(f"❌ Stripe API error: {response.status_code} - {response.text}")
                        self.circuit_breaker.record_failure()
                        return None
            
            except httpx.TimeoutException:
                logger.warning(f"⏰ Stripe API timeout (attempt {attempt + 1})")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
            
            except Exception as e:
                logger.error(f"❌ Stripe API request error: {str(e)}")
                self.circuit_breaker.record_failure()
                return None
        
        # All retries exhausted
        self.circuit_breaker.record_failure()
        logger.error(f"❌ Stripe API request failed after {self.max_retries} attempts")
        return None
    
    async def create_payment_intent(self, 
                                    amount: int, 
                                    currency: str = "usd",
                                    customer_id: Optional[str] = None,
                                    metadata: Dict[str, str] = None) -> Optional[Dict[str, Any]]:
        """
        Create Stripe payment intent with secure patterns
        
        Args:
            amount: Payment amount in cents
            currency: Payment currency
            customer_id: Stripe customer ID
            metadata: Additional metadata for tracking
            
        Returns:
            Payment intent data or None if failed
        """
        if metadata is None:
            metadata = {}
        
        # Add audit metadata
        metadata.update({
            "integration_version": "1.0",
            "created_by": "api-integration-framework",
            "compliance_context": "hipaa_enabled"
        })
        
        # Prepare payment intent data
        payment_data = {
            "amount": amount,
            "currency": currency,
            "metadata": metadata
        }
        
        if customer_id:
            payment_data["customer"] = customer_id
        
        # Make API request
        result = await self._make_api_request(
            method="POST",
            endpoint="/payment_intents",
            data=payment_data
        )
        
        if result:
            logger.info(f"✅ Payment intent created: {result.get('id')} for amount: ${amount/100}")
            
            # Log audit event for compliance
            audit_data = {
                "event_type": "payment_intent_created",
                "payment_intent_id": result.get('id'),
                "amount": amount,
                "currency": currency,
                "customer_id": customer_id,
                "timestamp": datetime.utcnow().isoformat(),
                "compliance_flags": {
                    "pci_compliant": True,
                    "audit_logged": True,
                    "secure_transport": True
                }
            }
            
            logger.info(f"📋 Payment audit logged: {json.dumps(audit_data)}")
        
        return result
    
    async def retrieve_payment_intent(self, payment_intent_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve payment intent details
        
        Args:
            payment_intent_id: Stripe payment intent ID
            
        Returns:
            Payment intent data or None if failed
        """
        result = await self._make_api_request(
            method="GET",
            endpoint=f"/payment_intents/{payment_intent_id}"
        )
        
        if result:
            logger.info(f"✅ Payment intent retrieved: {payment_intent_id}")
        
        return result
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check Stripe integration health and connectivity
        
        Returns:
            Health status information
        """
        logger.info("🔍 Performing Stripe integration health check")
        
        # Test credentials availability
        credentials = await self._get_credentials()
        credentials_available = credentials is not None
        
        # Test API connectivity (simple balance retrieve)
        api_healthy = False
        if credentials_available and self.circuit_breaker.can_execute():
            try:
                result = await self._make_api_request(
                    method="GET",
                    endpoint="/balance"
                )
                api_healthy = result is not None
            except Exception as e:
                logger.warning(f"⚠️  Stripe health check API error: {str(e)}")
        
        health_status = {
            "service": "stripe",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "healthy" if (credentials_available and api_healthy) else "degraded",
            "checks": {
                "credentials_available": credentials_available,
                "api_connectivity": api_healthy,
                "circuit_breaker_state": self.circuit_breaker.state,
                "failure_count": self.circuit_breaker.failure_count
            },
            "capabilities": {
                "payment_processing": api_healthy,
                "webhooks": credentials_available,
                "compliance_logging": True
            }
        }
        
        logger.info(f"📊 Stripe health check completed: {health_status['status']}")
        return health_status
    
    def validate_webhook_signature(self, 
                                   payload: str, 
                                   signature: str, 
                                   webhook_secret: str) -> bool:
        """
        Validate Stripe webhook signature for security
        
        Args:
            payload: Raw webhook payload
            signature: Stripe signature header
            webhook_secret: Webhook secret from credentials
            
        Returns:
            True if signature is valid
        """
        try:
            # In a real implementation, use Stripe's signature validation
            # This is a simplified version for demonstration
            import hmac
            import hashlib
            
            expected_signature = hmac.new(
                webhook_secret.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Extract signature from header (simplified)
            received_signature = signature.split("=")[-1] if "=" in signature else signature
            
            is_valid = hmac.compare_digest(expected_signature, received_signature)
            
            if is_valid:
                logger.info("✅ Stripe webhook signature validated")
            else:
                logger.warning("⚠️  Invalid Stripe webhook signature")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"❌ Webhook signature validation error: {str(e)}")
            return False


# Global instance for dependency injection
stripe_integration = StripeIntegration()
