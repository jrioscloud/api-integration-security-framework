# Copyright (c) 2025 Jaime Rios. All rights reserved.
# This software is provided for portfolio demonstration and educational purposes only.
# Commercial use requires explicit written permission from the author.

"""
Health Router

This module provides health check endpoints for monitoring and
operational visibility of the API Integration Security Framework.
"""

from fastapi import APIRouter
from typing import Dict, Any
import logging
from datetime import datetime
import psutil
import os

from ..security.secrets_manager import secrets_manager
from ..integrations.stripe_integration import stripe_integration

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/",
            summary="Basic Health Check",
            description="Basic health check endpoint")
async def health_check() -> Dict[str, Any]:
    """
    Basic health check endpoint
    Returns service status and timestamp
    """
    return {
        "status": "healthy",
        "service": "API Integration Security Framework",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@router.get("/detailed",
            summary="Detailed Health Check",
            description="Comprehensive health check with all system components")
async def detailed_health_check() -> Dict[str, Any]:
    """
    Comprehensive health check including all system components
    """
    logger.info("🔍 Performing detailed health check")
    
    health_data = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "API Integration Security Framework",
        "version": "1.0.0",
        "components": {},
        "system": {}
    }
    
    # Check AWS Secrets Manager
    try:
        secrets_health = await secrets_manager.health_check()
        health_data["components"]["secrets_manager"] = secrets_health
    except Exception as e:
        logger.error(f"❌ Secrets Manager health check failed: {str(e)}")
        health_data["components"]["secrets_manager"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # Check Stripe integration
    try:
        stripe_health = await stripe_integration.health_check()
        health_data["components"]["stripe_integration"] = stripe_health
    except Exception as e:
        logger.error(f"❌ Stripe integration health check failed: {str(e)}")
        health_data["components"]["stripe_integration"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # System metrics
    try:
        health_data["system"] = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "uptime_seconds": int(datetime.now().timestamp() - psutil.boot_time()),
            "process_count": len(psutil.pids())
        }
    except Exception as e:
        logger.warning(f"⚠️  System metrics collection failed: {str(e)}")
        health_data["system"] = {"error": "metrics_unavailable"}
    
    # Determine overall status
    component_statuses = [
        comp.get("status", "unknown") 
        for comp in health_data["components"].values()
    ]
    
    if all(status == "healthy" for status in component_statuses):
        health_data["status"] = "healthy"
    elif any(status == "healthy" for status in component_statuses):
        health_data["status"] = "degraded"
    else:
        health_data["status"] = "unhealthy"
    
    logger.info(f"✅ Detailed health check completed: {health_data['status']}")
    return health_data


@router.get("/readiness",
            summary="Readiness Check",
            description="Kubernetes readiness probe endpoint")
async def readiness_check() -> Dict[str, Any]:
    """
    Readiness check for Kubernetes deployments
    Verifies service is ready to handle requests
    """
    try:
        # Check critical dependencies
        secrets_health = await secrets_manager.health_check()
        
        if secrets_health["status"] in ["healthy", "mock_mode"]:
            return {
                "status": "ready",
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            return {
                "status": "not_ready",
                "reason": "secrets_manager_unavailable",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    except Exception as e:
        logger.error(f"❌ Readiness check failed: {str(e)}")
        return {
            "status": "not_ready",
            "reason": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/liveness",
            summary="Liveness Check", 
            description="Kubernetes liveness probe endpoint")
async def liveness_check() -> Dict[str, Any]:
    """
    Liveness check for Kubernetes deployments
    Verifies service is alive and responsive
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": int(datetime.now().timestamp() - psutil.boot_time())
    }
