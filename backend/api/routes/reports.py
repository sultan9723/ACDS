"""
Reports API Routes
===================
API endpoints for AI-powered report generation and incident report management.
Now supports PDF incident reports generated during threat detection.
"""

import os
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone, timedelta
from enum import Enum
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Local model definitions
class ReportType(str, Enum):
    THREAT_SUMMARY = "threat_summary"
    DETECTION_ANALYSIS = "detection_analysis"
    INCIDENT_LOG = "incident_log"
    PERFORMANCE_METRICS = "performance_metrics"
    EXECUTIVE_SUMMARY = "executive_summary"
    COMPLIANCE_REPORT = "compliance_report"

class ReportRequest(BaseModel):
    report_type: str
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    date_range: Optional[str] = None
    include_details: bool = True
    format: str = "json"

# Import report agent
try:
    from agents.report_agent import ReportGenerationAgent
except ImportError:
    try:
        from backend.agents.report_agent import ReportGenerationAgent
    except ImportError:
        ReportGenerationAgent = None

# Import incident report generator
try:
    from services.incident_report_generator import get_incident_report_generator
    from services.report_pdf_service import get_acds_report_pdf_service
except ImportError:
    try:
        from backend.services.incident_report_generator import get_incident_report_generator
        from backend.services.report_pdf_service import get_acds_report_pdf_service
    except ImportError:
        get_incident_report_generator = None
        get_acds_report_pdf_service = None

router = APIRouter(prefix="/reports", tags=["Reports"])

# Initialize report agent
report_agent = ReportGenerationAgent() if ReportGenerationAgent else None


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """
    Generate an AI-powered threat report.
    
    Creates comprehensive reports based on threat data,
    detection logs, and system metrics.
    """
    try:
        if not get_acds_report_pdf_service:
            raise HTTPException(status_code=503, detail="PDF report service not available")

        end_date = request.end_date or datetime.now(timezone.utc)
        start_date = request.start_date or _start_date_from_range(request.date_range, end_date)

        service = get_acds_report_pdf_service()
        report = service.generate_report(
            report_type=request.report_type,
            start_date=start_date,
            end_date=end_date,
            include_details=request.include_details,
        )

        return {
            "success": True,
            "report": report,
            **report,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/types")
async def get_report_types():
    """Get available report types and their descriptions."""
    if get_acds_report_pdf_service:
        return {
            "success": True,
            "report_types": get_acds_report_pdf_service().get_report_types(),
        }
    return {
        "success": True,
        "report_types": [
            {
                "type": "threat_summary",
                "name": "Threat Summary",
                "description": "Overview of all detected threats with severity breakdown"
            },
            {
                "type": "detection_analysis",
                "name": "Detection Analysis",
                "description": "Detailed analysis of detection patterns and trends"
            },
            {
                "type": "incident_log",
                "name": "Incident Log",
                "description": "Chronological log of all security incidents"
            },
            {
                "type": "performance_metrics",
                "name": "Performance Metrics",
                "description": "System performance and detection accuracy metrics"
            },
            {
                "type": "executive_summary",
                "name": "Executive Summary",
                "description": "High-level summary for management review"
            },
            {
                "type": "compliance_report",
                "name": "Compliance Report",
                "description": "Compliance-focused security posture report"
            }
        ]
    }


# ====================
# INCIDENT PDF REPORTS
# ====================

@router.get("/incidents")
async def get_incident_reports(
    limit: int = Query(50, le=100),
    severity: Optional[str] = None
):
    """
    Get list of generated PDF incident reports.
    These are auto-generated when phishing threats are detected.
    """
    try:
        generated_reports = []
        if get_acds_report_pdf_service:
            generated_reports = get_acds_report_pdf_service().list_reports(limit=limit)

        legacy_reports = []
        if get_incident_report_generator:
            generator = get_incident_report_generator()
            legacy_reports = generator.get_reports(limit=limit)

        reports = generated_reports + [
            report for report in legacy_reports
            if report.get("report_id") not in {item.get("report_id") for item in generated_reports}
        ]
            
        if severity:
            reports = [r for r in reports if r.get("severity", "").upper() == severity.upper()]

        reports = sorted(reports, key=lambda item: item.get("generated_at", ""), reverse=True)[:limit]
        return {
            "success": True,
            "reports": reports,
            "count": len(reports)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/incidents/{report_id}")
async def get_incident_report(report_id: str):
    """Get metadata for a specific incident report."""
    try:
        if get_acds_report_pdf_service:
            report = get_acds_report_pdf_service().get_report(report_id)
            if report:
                return {"success": True, "report": report}

        if get_incident_report_generator:
            generator = get_incident_report_generator()
            report = generator.get_report_by_id(report_id)
            
            if report:
                return {
                    "success": True,
                    "report": report
                }
            else:
                raise HTTPException(status_code=404, detail="Incident report not found")
        else:
            raise HTTPException(status_code=500, detail="Incident report generator not available")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/incidents/{report_id}/download")
async def download_incident_report(report_id: str):
    """
    Download a PDF incident report.
    Returns the actual PDF file for download.
    """
    try:
        if get_acds_report_pdf_service:
            filepath = get_acds_report_pdf_service().get_report_path(report_id)
            if filepath and filepath.exists():
                return FileResponse(
                    path=str(filepath),
                    media_type="application/pdf",
                    filename=filepath.name,
                    headers={"Content-Disposition": f"attachment; filename={filepath.name}"},
                )

        if get_incident_report_generator:
            generator = get_incident_report_generator()
            filepath = generator.get_report_filepath(report_id)
            
            if filepath and os.path.exists(filepath):
                filename = os.path.basename(filepath)
                return FileResponse(
                    path=filepath,
                    media_type="application/pdf",
                    filename=filename,
                    headers={
                        "Content-Disposition": f"attachment; filename={filename}"
                    }
                )
            else:
                raise HTTPException(status_code=404, detail="Report file not found")
        else:
            raise HTTPException(status_code=500, detail="Incident report generator not available")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/incidents/{report_id}")
async def delete_incident_report(report_id: str):
    """Delete an incident report."""
    try:
        if get_acds_report_pdf_service and get_acds_report_pdf_service().delete_report(report_id):
            return {
                "success": True,
                "message": f"Report {report_id} deleted successfully"
            }

        if get_incident_report_generator:
            generator = get_incident_report_generator()
            filepath = generator.get_report_filepath(report_id)
            
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
                
                # Remove from metadata
                generator._reports_metadata = [
                    r for r in generator._reports_metadata 
                    if r.get("report_id") != report_id
                ]
                generator._save_metadata()
                
                return {
                    "success": True,
                    "message": f"Report {report_id} deleted successfully"
                }
            else:
                raise HTTPException(status_code=404, detail="Report not found")
        else:
            raise HTTPException(status_code=500, detail="Incident report generator not available")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ====================
# LEGACY ENDPOINTS - Must be AFTER specific routes
# ====================

@router.get("/list")
async def get_reports_list(
    report_type: Optional[str] = None,
    limit: int = Query(20, le=100)
):
    """Get list of previously generated reports."""
    # Redirect to incident reports
    return await get_incident_reports(limit=limit)


@router.get("/detail/{report_id}")
async def get_report(report_id: str):
    """Get a specific report by ID."""
    return await get_incident_report(report_id)


@router.get("/detail/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = Query("pdf", regex="^(json|pdf|html|txt)$")
):
    """
    Export a report in the specified format.
    For PDF incident reports, use /incidents/{report_id}/download
    """
    if format == "pdf":
        return await download_incident_report(report_id)
    else:
        # For other formats, get the report metadata
        if get_incident_report_generator:
            generator = get_incident_report_generator()
            report = generator.get_report_by_id(report_id)
            if report:
                return {
                    "success": True,
                    "format": format,
                    "report": report
                }
        raise HTTPException(status_code=404, detail="Report not found")


@router.delete("/detail/{report_id}")
async def delete_report(report_id: str):
    """Delete a report."""
    return await delete_incident_report(report_id)


def _start_date_from_range(date_range: Optional[str], end_date: datetime) -> datetime:
    ranges = {
        "24hours": timedelta(hours=24),
        "7days": timedelta(days=7),
        "30days": timedelta(days=30),
        "90days": timedelta(days=90),
    }
    return end_date - ranges.get(date_range or "7days", timedelta(days=7))


def _get_threat_data(start_date: datetime, end_date: datetime) -> dict:
    """
    Get threat data from MongoDB for report generation.
    """
    try:
        from database.connection import get_collection
        
        # Get threats from database
        threats_col = get_collection("threats")
        scans_col = get_collection("email_scans")
        
        threats = []
        total_scans = 0
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        if threats_col:
            cursor = threats_col.find({
                "detected_at": {"$gte": start_date, "$lte": end_date}
            }).sort("detected_at", -1)
            
            for threat in cursor:
                threat["_id"] = str(threat.get("_id"))
                threats.append(threat)
                severity = threat.get("severity", "MEDIUM").upper()
                if severity in severity_breakdown:
                    severity_breakdown[severity] += 1
        
        if scans_col:
            total_scans = scans_col.count_documents({
                "scanned_at": {"$gte": start_date, "$lte": end_date}
            })
        
        return {
            "total_scans": total_scans or 100,
            "threats_detected": len(threats),
            "threats_blocked": len([t for t in threats if t.get("status") == "resolved"]),
            "false_positives": 0,
            "severity_breakdown": severity_breakdown,
            "threat_types": {
                "phishing": len(threats),
            },
            "recent_threats": threats[:10],
            "response_actions": {
                "quarantined": len(threats),
                "blocked_senders": len(set(t.get("email_sender") for t in threats)),
                "notifications_sent": len(threats)
            }
        }
    except Exception as e:
        print(f"Error getting threat data: {e}")
        # Return mock data as fallback
        return {
            "total_scans": 100,
            "threats_detected": 5,
            "threats_blocked": 5,
            "false_positives": 0,
            "severity_breakdown": {
                "CRITICAL": 1,
                "HIGH": 2,
                "MEDIUM": 2,
                "LOW": 0
            },
            "threat_types": {"phishing": 5},
            "response_actions": {
                "quarantined": 5,
                "blocked_senders": 3,
                "notifications_sent": 5
            }
        }
