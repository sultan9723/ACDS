"""
ACDS - Autonomous Cyber Defense System
========================================
Main FastAPI application with all API endpoints for threat detection,
response automation, feedback loops, and report generation.
"""

# Suppress sklearn version warnings FIRST before any imports
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

import os
import sys
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
from config.settings import CORS_ORIGINS

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="ACDS - Autonomous Cyber Defense System",
    description="API for automated phishing detection, incident management, and autonomous response.",
    version="2.0.0"
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# IMPORT AND INCLUDE API ROUTERS
# =============================================================================

# Import route modules
from api.routes import auth, threats, dashboard, ransomware, malware, feedback, reports, testing, demo, malware_demo, credential_stuffing
from api.routes.auth import get_current_user

# Include routers with /api/v1 prefix
app.include_router(auth.router, prefix="/api/v1")
app.include_router(threats.router, prefix="/api/v1")
app.include_router(ransomware.router, prefix="/api/v1")  
app.include_router(malware.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(feedback.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(testing.router, prefix="/api/v1")
app.include_router(demo.router, prefix="/api/v1")
app.include_router(malware_demo.router, prefix="/api/v1")
app.include_router(credential_stuffing.router, prefix="/api/v1")


# =============================================================================
# ROOT AND HEALTH ENDPOINTS
# =============================================================================

@app.get("/", response_class=HTMLResponse, summary="Root endpoint")
async def read_root():
    """Root endpoint with system info."""
    return """
    <html>
        <head>
            <title>ACDS - Autonomous Cyber Defense System</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                h1 { color: #0ea5e9; }
                .status { color: #22c55e; }
                a { color: #0ea5e9; }
            </style>
        </head>
        <body>
            <h1>🛡️ ACDS - Autonomous Cyber Defense System</h1>
            <p><span class="status">● System Online</span></p>
            <p>Multi-Agent Phishing Detection & Response Platform</p>
            <h2>Quick Links</h2>
            <ul>
                <li><a href="/docs">📚 API Documentation (Swagger)</a></li>
                <li><a href="/redoc">📖 API Documentation (ReDoc)</a></li>
                <li><a href="/health">💚 Health Check</a></li>
            </ul>
            <h2>API Endpoints</h2>
            <ul>
                <li><code>/api/v1/threats/</code> - Threat detection endpoints</li>
                <li><code>/api/v1/ransomware/</code> - Ransomware detection endpoints</li>
                <li><code>/api/v1/malware/</code> - Malware detection endpoints</li>
                <li><code>/api/v1/dashboard/</code> - Dashboard statistics</li>
                <li><code>/api/v1/demo/</code> - Demo mode controls</li>
                <li><code>/api/v1/auth/</code> - Authentication</li>
                <li><code>/api/v1/feedback/</code> - Feedback loop</li>
                <li><code>/api/v1/reports/</code> - Report generation</li>
            </ul>
        </body>
    </html>
    """


@app.get("/health", summary="Health check endpoint")
async def health_check():
    """Check system health status."""
    health_status = {
        "status": "healthy",
        "components": {}
    }
    
    # Check ML model
    try:
        from ml.phishing_service import get_phishing_service
        service = get_phishing_service()
        if service and service.model:
            health_status["components"]["ml_model"] = "healthy"
        else:
            health_status["components"]["ml_model"] = "not_loaded"
    except Exception as e:
        health_status["components"]["ml_model"] = f"error: {str(e)}"
    
    # Check database
    try:
        from database.connection import get_database_health
        health_status["components"]["database"] = get_database_health()
    except Exception as e:
        health_status["components"]["database"] = {
            "status": "error",
            "connected": False,
            "last_error": str(e),
        }
    
    # Check orchestrator
    try:
        from agents.orchestrator_agent import get_orchestrator_agent
        orchestrator = get_orchestrator_agent()
        if orchestrator:
            health_status["components"]["orchestrator"] = "ready"
        else:
            health_status["components"]["orchestrator"] = "not_ready"
    except Exception as e:
        health_status["components"]["orchestrator"] = f"error: {str(e)}"
    
    
    try:
        from agents.ransomware_orchestrator_agent import get_ransomware_orchestrator_agent
        ransomware_orchestrator = get_ransomware_orchestrator_agent()
        if ransomware_orchestrator:
            health_status["components"]["ransomware_orchestrator"] = "ready"
        else:
            health_status["components"]["ransomware_orchestrator"] = "not_ready"
    except Exception as e:
        health_status["components"]["ransomware_orchestrator"] = f"error: {str(e)}"

    try:
        from agents.malware_orchestrator_agent import get_malware_orchestrator_agent
        malware_orchestrator = get_malware_orchestrator_agent()
        if malware_orchestrator:
            health_status["components"]["malware_orchestrator"] = "ready"
        else:
            health_status["components"]["malware_orchestrator"] = "not_ready"
    except Exception as e:
        health_status["components"]["malware_orchestrator"] = f"error: {str(e)}"

    database_component = health_status["components"].get("database")
    database_unhealthy = (
        isinstance(database_component, dict)
        and database_component.get("status") != "healthy"
    )
    component_errors = any(
        isinstance(component, str)
        and (
            component.startswith("error:")
            or component in {"not_loaded", "not_ready", "not_configured"}
        )
        for component in health_status["components"].values()
    )
    if database_unhealthy or component_errors:
        health_status["status"] = "degraded"

    
    return health_status


# =============================================================================
# STARTUP AND SHUTDOWN EVENTS
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("🚀 Starting ACDS Backend...")
    
    # Initialize ML model
    try:
        from ml.phishing_service import get_phishing_service
        service = get_phishing_service()
        if service and service.model:
            logger.info("✅ ML Model loaded successfully")
        else:
            logger.warning("⚠️ ML Model not loaded")
    except Exception as e:
        logger.error(f"❌ Error loading ML model: {e}")
    
    # Initialize database connection
    try:
        from database.connection import get_database_health
        database_health = get_database_health(force=True)
        if database_health["connected"]:
            logger.info("Database connection established")
        else:
            logger.warning(
                "Database unavailable; degraded local fallback active: %s",
                database_health.get("last_error") or "not configured",
            )
    except Exception as e:
        logger.error(f"Error checking database: {e}")

    # Run database migrations
    try:
        from database.migrations.manager import run_migrations
        applied = run_migrations()
        if applied > 0:
            logger.info(f"✅ Applied {applied} database migration(s)")
        else:
            logger.info("📦 Database schema is up to date")
    except Exception as e:
        logger.warning(f"⚠️ Database migrations skipped: {e}")
    
    # Initialize orchestrator agent
    try:
        from agents.orchestrator_agent import get_orchestrator_agent
        orchestrator = get_orchestrator_agent()
        if orchestrator:
            logger.info("✅ Orchestrator Agent initialized")
        else:
            logger.warning("⚠️ Orchestrator Agent not initialized")
    except Exception as e:
        logger.error(f"❌ Error initializing orchestrator: {e}")

    try:
        from agents.ransomware_orchestrator_agent import get_ransomware_orchestrator_agent
        ransomware_orchestrator = get_ransomware_orchestrator_agent()
        if ransomware_orchestrator:
            logger.info("✅ Ransomware Orchestrator Agent initialized")
        else:
            logger.warning("⚠️ Ransomware Orchestrator Agent not initialized")
    except Exception as e:
        logger.error(f"❌ Error initializing ransomware orchestrator: {e}")

    try:
        from agents.malware_orchestrator_agent import get_malware_orchestrator_agent
        malware_orchestrator = get_malware_orchestrator_agent()
        if malware_orchestrator:
            logger.info("✅ Malware Orchestrator Agent initialized")
        else:
            logger.warning("⚠️ Malware Orchestrator Agent not initialized")
    except Exception as e:
        logger.error(f"❌ Error initializing malware orchestrator: {e}")
    
    logger.info("🛡️ ACDS Backend is ready!")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("🛑 Shutting down ACDS Backend...")
    
    # Stop demo scheduler if running
    try:
        from services.demo_scheduler import get_demo_scheduler
        scheduler = get_demo_scheduler()
        if scheduler.running:
            await scheduler.stop()
            logger.info("✅ Demo scheduler stopped")
    except Exception as e:
        logger.warning(f"⚠️ Error stopping demo scheduler: {e}")

    try:
        from services.malware_demo_scheduler import get_malware_demo_scheduler
        malware_scheduler = get_malware_demo_scheduler()
        if malware_scheduler.running:
            await malware_scheduler.stop()
            logger.info("✅ Malware demo scheduler stopped")
    except Exception as e:
        logger.warning(f"⚠️ Error stopping malware demo scheduler: {e}")

    logger.info("👋 ACDS Backend shutdown complete")


# =============================================================================
# RUN SERVER
# =============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=True,
        log_level="info"
    )
