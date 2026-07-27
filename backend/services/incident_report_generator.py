"""
Incident Report Generator Service
==================================
Generates PDF incident reports for detected phishing threats.
These reports are stored in the reports folder and can be accessed via API.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import json

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: ReportLab not installed. PDF generation will be unavailable.")


@dataclass
class IncidentReport:
    """Data class for incident report metadata."""
    report_id: str
    threat_id: str
    filename: str
    filepath: str
    generated_at: str
    threat_type: str
    severity: str
    confidence: float
    email_subject: str
    email_sender: str
    status: str


class IncidentReportGenerator:
    """
    Generates PDF incident reports for phishing threats.
    """
    
    def __init__(self, reports_dir: str = None):
        """Initialize the report generator."""
        # Set default reports directory
        if reports_dir is None:
            # Go up from backend/services to project root, then to reports
            self.reports_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "reports"
            )
        else:
            self.reports_dir = reports_dir
        
        # Create reports directory if it doesn't exist
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Reports metadata storage (in-memory, could be persisted to DB)
        self._reports_metadata: List[Dict] = []
        
        # Load existing reports metadata
        self._load_metadata()
        
        print(f"IncidentReportGenerator initialized. Reports dir: {self.reports_dir}")
    
    def _load_metadata(self):
        """Load existing reports metadata from JSON file."""
        metadata_file = os.path.join(self.reports_dir, "reports_metadata.json")
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    self._reports_metadata = json.load(f)
                print(f"Loaded {len(self._reports_metadata)} existing report records")
            except Exception as e:
                print(f"Warning: Error loading reports metadata: {e}")
                self._reports_metadata = []
    
    def _save_metadata(self):
        """Save reports metadata to JSON file."""
        metadata_file = os.path.join(self.reports_dir, "reports_metadata.json")
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self._reports_metadata, f, indent=2)
        except Exception as e:
            print(f"Warning: Error saving reports metadata: {e}")
    
    def generate_incident_report(
        self,
        threat_data: Dict[str, Any],
        pipeline_results: Dict[str, Any] = None
    ) -> Optional[IncidentReport]:
        """
        Generate a professionally structured PDF incident report for any detected threat.
        
        Args:
            threat_data: Dictionary containing threat information
            pipeline_results: Optional pipeline results with detection details
            
        Returns:
            IncidentReport object with metadata, or None if generation failed
        """
        if not REPORTLAB_AVAILABLE:
            print("Warning: ReportLab not available, cannot generate PDF report")
            return None
        
        try:
            # Generate unique report ID
            report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
            threat_id = threat_data.get("threat_id", threat_data.get("incident_id", f"THR-{uuid.uuid4().hex[:8].upper()}"))
            
            # Detect threat type from data
            threat_type = self._detect_threat_type(threat_data, pipeline_results)
            
            # Generate filename with threat ID (use existing format if provided)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"incident_report_{threat_id}.pdf"
            filepath = os.path.join(self.reports_dir, filename)
            
            # Extract common threat details
            detected_at = threat_data.get("detected_at", threat_data.get("timestamp", datetime.now(timezone.utc).isoformat()))
            severity = threat_data.get("severity", "MEDIUM")
            confidence = threat_data.get("confidence", 0)
            status = threat_data.get("status", "Resolved")
            
            # Extract pipeline results if available
            detection_result = {}
            explainability_result = {}
            response_result = {}
            report_result = {}
            
            if pipeline_results:
                detection_result = pipeline_results.get("detection", {})
                explainability_result = pipeline_results.get("explainability", {})
                response_result = pipeline_results.get("response", {})
                report_result = pipeline_results.get("report", {})
            
            # Extract actions taken
            actions_taken = (
                threat_data.get("actions_taken", []) or
                response_result.get("actions_executed", []) or
                [threat_data.get("action_taken")] if threat_data.get("action_taken") else
                ["alert_generated"]
            )
            
            # Extract threat-specific details based on type
            threat_details = self._extract_threat_details(threat_data, threat_type, detection_result)
            
            # Generate PDF
            self._create_pdf_report(
                filepath=filepath,
                report_id=report_id,
                threat_id=threat_id,
                threat_type=threat_type,
                detected_at=detected_at,
                severity=severity,
                confidence=confidence,
                status=status,
                actions_taken=actions_taken,
                threat_details=threat_details,
                detection_result=detection_result,
                explainability_result=explainability_result,
                response_result=response_result,
                report_result=report_result
            )
            
            # Create report metadata
            report = IncidentReport(
                report_id=report_id,
                threat_id=threat_id,
                filename=filename,
                filepath=filepath,
                generated_at=datetime.now(timezone.utc).isoformat(),
                threat_type=threat_type,
                severity=severity,
                confidence=confidence,
                email_subject=threat_details.get("subject", "N/A"),
                email_sender=threat_details.get("source", "Unknown"),
                status=status
            )
            
            # Store metadata
            report_dict = {
                "report_id": report.report_id,
                "threat_id": report.threat_id,
                "filename": report.filename,
                "filepath": report.filepath,
                "generated_at": report.generated_at,
                "threat_type": report.threat_type,
                "severity": report.severity,
                "confidence": report.confidence,
                "email_subject": report.email_subject,
                "email_sender": report.email_sender,
                "status": report.status,
                "detected_at": detected_at
            }
            self._reports_metadata.append(report_dict)
            self._save_metadata()
            
            # Also store to database
            self._store_report_to_db(report_dict)
            
            print(f"Generated {threat_type} incident report: {filename}")
            return report
            
        except Exception as e:
            print(f"Error generating incident report: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _detect_threat_type(self, threat_data: Dict[str, Any], pipeline_results: Dict[str, Any] = None) -> str:
        """Detect the type of threat from the data."""
        # Check explicit type field
        if "type" in threat_data:
            threat_type = str(threat_data["type"]).lower()
            if "malware" in threat_type:
                return "Malware"
            elif "ransomware" in threat_type:
                return "Ransomware"
            elif "phishing" in threat_type:
                return "Phishing"
        
        # Check for malware indicators
        if any(key in threat_data for key in ["filename", "file_hash", "file_type", "sample_id"]):
            return "Malware"
        
        # Check for ransomware indicators
        if any(key in threat_data for key in ["command", "process_name", "source_host"]):
            return "Ransomware"
        
        # Check pipeline results
        if pipeline_results:
            detection = pipeline_results.get("detection", {})
            if detection.get("threat_type"):
                return detection["threat_type"].title()
        
        # Default to phishing
        return "Phishing"
    
    def _extract_threat_details(self, threat_data: Dict[str, Any], threat_type: str, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat-specific details based on type."""
        details = {}
        
        if threat_type == "Phishing":
            details["subject"] = threat_data.get("email_subject", threat_data.get("subject", "No Subject"))
            details["source"] = threat_data.get("email_sender", threat_data.get("sender", "Unknown"))
            details["recipient"] = threat_data.get("recipient", "N/A")
            details["content_preview"] = threat_data.get("email_preview", threat_data.get("content", ""))[:500]
            details["email_id"] = threat_data.get("email_id", "N/A")
            
        elif threat_type == "Malware":
            details["subject"] = threat_data.get("filename", "Unknown File")
            details["source"] = "File System Scan"
            details["file_hash"] = threat_data.get("file_hash", "N/A")
            details["file_size"] = threat_data.get("file_size", 0)
            details["file_type"] = threat_data.get("file_type", "Unknown")
            details["sample_id"] = threat_data.get("sample_id", "N/A")
            details["model_used"] = detection_result.get("model_used", "behavioral_analysis")
            
        elif threat_type == "Ransomware":
            details["subject"] = threat_data.get("command", "Suspicious Command")
            details["source"] = threat_data.get("source_host", "Unknown Host")
            details["process_name"] = threat_data.get("process_name", "N/A")
            details["user"] = threat_data.get("user", "N/A")
            details["command_id"] = threat_data.get("command_id", "N/A")
            details["behavior_categories"] = threat_data.get("behavior_categories", [])
        
        return details
    
    def _create_pdf_report(
        self,
        filepath: str,
        report_id: str,
        threat_id: str,
        threat_type: str,
        detected_at: str,
        severity: str,
        confidence: float,
        status: str,
        actions_taken: List[str],
        threat_details: Dict[str, Any],
        detection_result: Dict,
        explainability_result: Dict,
        response_result: Dict,
        report_result: Dict
    ):
        """Create a professionally structured PDF report file."""
        doc = SimpleDocTemplate(filepath, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []
        
        # Parse detected_at timestamp
        try:
            if isinstance(detected_at, str):
                dt = datetime.fromisoformat(detected_at.replace('Z', '+00:00'))
            else:
                dt = datetime.now(timezone.utc)
        except:
            dt = datetime.now(timezone.utc)
        
        detection_date = dt.strftime("%B %d, %Y")
        detection_time = dt.strftime("%H:%M:%S UTC")
        
        # Custom styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor('#1e3a5f')
        )
        
        header_style = ParagraphStyle(
            'Header',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.HexColor('#2563eb'),
            borderPadding=5
        )
        
        normal_style = styles['Normal']
        
        # Severity color
        severity_colors = {
            "CRITICAL": colors.HexColor('#dc2626'),
            "HIGH": colors.HexColor('#ea580c'),
            "MEDIUM": colors.HexColor('#ca8a04'),
            "LOW": colors.HexColor('#16a34a')
        }
        severity_color = severity_colors.get(severity.upper(), colors.gray)
        
        # Title with threat type
        threat_icons = {"Phishing": "📧", "Malware": "🦠", "Ransomware": "🔒"}
        icon = threat_icons.get(threat_type, "⚠️")
        story.append(Paragraph(f"{icon} {threat_type.upper()} INCIDENT REPORT", title_style))
        story.append(Paragraph("Autonomous Cyber Defense System (ACDS)", 
                               ParagraphStyle('Subtitle', parent=normal_style, alignment=TA_CENTER, textColor=colors.gray)))
        story.append(Spacer(1, 0.2 * inch))
        
        # Report Info Box - Clean and Professional
        report_info = [
            ["Report ID:", report_id],
            ["Threat ID:", threat_id],
            ["Detection Date:", detection_date],
            ["Detection Time:", detection_time],
            ["Report Generated:", datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M:%S UTC")],
            ["Status:", status.title()]
        ]
        
        info_table = Table(report_info, colWidths=[1.5*inch, 5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#334155')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Threat Summary Section
        story.append(Paragraph("THREAT SUMMARY", header_style))
        
        # Format confidence
        conf_display = f"{confidence:.1f}%" if confidence > 1 else f"{confidence*100:.1f}%"
        
        # Build threat data based on type
        threat_data = [
            ["Threat Type:", threat_type],
            ["Severity Level:", severity.upper()],
            ["Detection Confidence:", conf_display],
        ]
        
        # Add type-specific fields
        if threat_type == "Phishing":
            subject = threat_details.get("subject", "N/A")
            threat_data.append(["Email Subject:", subject[:70] + "..." if len(subject) > 70 else subject])
            threat_data.append(["Sender Address:", threat_details.get("source", "Unknown")])
            threat_data.append(["Recipient:", threat_details.get("recipient", "N/A")])
            threat_data.append(["Email ID:", threat_details.get("email_id", "N/A")])
            
        elif threat_type == "Malware":
            threat_data.append(["File Name:", threat_details.get("subject", "Unknown")])
            threat_data.append(["File Hash (SHA256):", threat_details.get("file_hash", "N/A")])
            threat_data.append(["File Size:", f"{threat_details.get('file_size', 0):,} bytes"])
            threat_data.append(["File Type:", threat_details.get("file_type", "Unknown")])
            threat_data.append(["Sample ID:", threat_details.get("sample_id", "N/A")])
            threat_data.append(["Detection Model:", threat_details.get("model_used", "N/A")])
            
        elif threat_type == "Ransomware":
            threat_data.append(["Suspicious Command:", threat_details.get("subject", "N/A")])
            threat_data.append(["Source Host:", threat_details.get("source", "Unknown")])
            threat_data.append(["Process Name:", threat_details.get("process_name", "N/A")])
            threat_data.append(["User Account:", threat_details.get("user", "N/A")])
            threat_data.append(["Command ID:", threat_details.get("command_id", "N/A")])
        
        threat_table = Table(threat_data, colWidths=[1.5*inch, 5*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#fef3c7')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#334155')),
            ('TEXTCOLOR', (1, 1), (1, 1), severity_color),  # Severity value colored
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),  # Severity value bold
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#fde68a')),
        ]))
        story.append(threat_table)
        story.append(Spacer(1, 0.2 * inch))
        
        # Content/Details Preview (type-specific)
        if threat_type == "Phishing" and threat_details.get("content_preview"):
            story.append(Paragraph("EMAIL CONTENT PREVIEW", header_style))
            safe_content = threat_details["content_preview"].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            content_style = ParagraphStyle(
                'Content',
                parent=normal_style,
                fontSize=9,
                textColor=colors.HexColor('#475569'),
                backColor=colors.HexColor('#f8fafc'),
                borderPadding=10,
                leftIndent=10,
                rightIndent=10
            )
            story.append(Paragraph(f"<i>{safe_content[:400]}...</i>", content_style))
            story.append(Spacer(1, 0.2 * inch))
        
        elif threat_type == "Ransomware" and threat_details.get("behavior_categories"):
            story.append(Paragraph("BEHAVIOR CATEGORIES DETECTED", header_style))
            behaviors = threat_details["behavior_categories"]
            behavior_text = "<br/>".join([f"• {b.replace('_', ' ').title()}" for b in behaviors[:5]])
            story.append(Paragraph(behavior_text, normal_style))
            story.append(Spacer(1, 0.2 * inch))
        
        # Detection Analysis
        story.append(Paragraph("DETECTION ANALYSIS", header_style))
        
        # Get evidence and indicators from explainability
        evidence = explainability_result.get("evidence", [])
        iocs = explainability_result.get("iocs", {})
        indicators = explainability_result.get("indicators", {})
        
        analysis_parts = []
        
        if evidence:
            analysis_parts.append(f"<b>Key Evidence:</b><br/>")
            for ev in evidence[:4]:
                analysis_parts.append(f"• {ev}<br/>")
            analysis_parts.append("<br/>")
        
        if threat_type == "Phishing":
            suspicious_urls = iocs.get("suspicious_urls", [])
            keywords = iocs.get("keywords", [])
            if suspicious_urls:
                analysis_parts.append(f"<b>Suspicious URLs:</b><br/>")
                for url in suspicious_urls[:3]:
                    analysis_parts.append(f"• {url}<br/>")
                analysis_parts.append("<br/>")
            if keywords:
                analysis_parts.append(f"<b>Trigger Keywords:</b> {', '.join(keywords[:6])}<br/>")
        
        elif threat_type == "Malware":
            if indicators:
                analysis_parts.append(f"<b>Behavioral Indicators:</b><br/>")
                for key, value in list(indicators.items())[:5]:
                    analysis_parts.append(f"• {key.replace('_', ' ').title()}: {value}<br/>")
        
        elif threat_type == "Ransomware":
            behaviors = threat_details.get("behavior_categories", [])
            if behaviors:
                analysis_parts.append(f"<b>Malicious Behaviors:</b> {', '.join([b.replace('_', ' ').title() for b in behaviors])}<br/>")
        
        if analysis_parts:
            story.append(Paragraph(''.join(analysis_parts), normal_style))
        else:
            story.append(Paragraph("Threat detected based on behavioral analysis and pattern matching.", normal_style))
        
        story.append(Spacer(1, 0.2 * inch))
        
        # Automated Response Actions
        story.append(Paragraph("ACTIONS TAKEN", header_style))
        
        # Get action timestamp if available
        action_time = response_result.get("timestamp", dt.strftime("%Y-%m-%d %H:%M:%S UTC"))
        
        actions_display = []
        for action in actions_taken:
            if action:  # Skip None/empty actions
                action_name = str(action).replace("_", " ").title()
                actions_display.append([f"✓ {action_name}", "Completed"])
        
        if actions_display:
            story.append(Paragraph(f"<i>Actions executed at: {action_time}</i>", 
                                 ParagraphStyle('ActionTime', parent=normal_style, fontSize=9, textColor=colors.gray)))
            story.append(Spacer(1, 0.1 * inch))
            
            actions_table = Table(actions_display, colWidths=[4*inch, 2*inch])
            actions_table.setStyle(TableStyle([
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#16a34a')),
                ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#059669')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0fdf4')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#86efac')),
            ]))
            story.append(actions_table)
        else:
            story.append(Paragraph("Alert generated and logged for security team review.", normal_style))
        
        story.append(Spacer(1, 0.3 * inch))
        
        # Recommendations (type-specific)
        story.append(Paragraph("RECOMMENDATIONS", header_style))
        
        if threat_type == "Phishing":
            recommendations = [
                "1. Do not interact with any links or attachments from this email",
                "2. Report this incident to your IT security team immediately",
                "3. If credentials were entered, change passwords immediately",
                "4. Enable multi-factor authentication on all sensitive accounts",
                "5. Review other emails from this sender for potential threats",
                "6. Educate users about phishing indicators and safe email practices"
            ]
        elif threat_type == "Malware":
            recommendations = [
                "1. Quarantine the infected file immediately",
                "2. Run a full system antivirus scan on the affected machine",
                "3. Disconnect the affected system from the network if necessary",
                "4. Review system logs for signs of lateral movement",
                "5. Update antivirus signatures and security patches",
                "6. Implement application whitelisting to prevent unauthorized executables"
            ]
        elif threat_type == "Ransomware":
            recommendations = [
                "1. Immediately isolate the affected system from the network",
                "2. Do NOT pay any ransom demands",
                "3. Restore data from clean, verified backups",
                "4. Scan all systems for indicators of compromise",
                "5. Review and strengthen backup procedures",
                "6. Implement network segmentation to limit ransomware spread",
                "7. Report the incident to law enforcement and regulatory bodies"
            ]
        else:
            recommendations = [
                "1. Review the threat details and take appropriate containment actions",
                "2. Notify the security team and relevant stakeholders",
                "3. Document all findings and actions taken",
                "4. Conduct a post-incident review to improve defenses"
            ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, ParagraphStyle('Rec', parent=normal_style, leftIndent=20, fontSize=10, spaceBefore=3)))
        
        story.append(Spacer(1, 0.4 * inch))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=normal_style,
            fontSize=8,
            textColor=colors.gray,
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            "This report was automatically generated by the Autonomous Cyber Defense System (ACDS)",
            footer_style
        ))
        story.append(Paragraph(
            f"© {datetime.now().year} ACDS Security Platform",
            footer_style
        ))
        
        # Build PDF
        doc.build(story)
    
    def _store_report_to_db(self, report_dict: Dict):
        """Store report metadata to MongoDB."""
        try:
            from database.connection import get_collection
            
            reports_col = get_collection("incident_reports")
            if reports_col is not None:
                reports_col.insert_one(report_dict.copy())
                print(f"Report metadata stored in MongoDB: {report_dict['report_id']}")
        except Exception as e:
            print(f"Warning: Could not store report to database: {e}")
    
    def get_reports(self, limit: int = 50) -> List[Dict]:
        """Get list of generated reports."""
        all_reports = []
        
        # First try database
        try:
            from database.connection import get_collection
            
            reports_col = get_collection("incident_reports")
            if reports_col is not None:
                cursor = reports_col.find({}).sort([("generated_at", -1)]).limit(limit)
                for report in cursor:
                    report["_id"] = str(report.get("_id"))
                    all_reports.append(report)
                print(f"Fetched {len(all_reports)} reports from database")
        except Exception as e:
            print(f"Warning: Could not fetch reports from database: {e}")
        
        # Also check in-memory metadata for any reports not yet in DB
        if self._reports_metadata:
            db_report_ids = {r.get("report_id") for r in all_reports}
            for report in self._reports_metadata:
                if report.get("report_id") not in db_report_ids:
                    all_reports.append(report)
        
        # Sort by generated_at descending and limit
        all_reports = sorted(all_reports, key=lambda x: x.get("generated_at", ""), reverse=True)[:limit]
        return all_reports
    
    def get_report_by_id(self, report_id: str) -> Optional[Dict]:
        """Get a specific report by ID."""
        for report in self._reports_metadata:
            if report.get("report_id") == report_id:
                return report
        return None
    
    def get_report_filepath(self, report_id: str) -> Optional[str]:
        """Get the filepath of a report by ID."""
        report = self.get_report_by_id(report_id)
        if report:
            return report.get("filepath")
        return None


# Global instance
_report_generator: Optional[IncidentReportGenerator] = None


def get_incident_report_generator() -> IncidentReportGenerator:
    """Get or create the incident report generator instance."""
    global _report_generator
    if _report_generator is None:
        _report_generator = IncidentReportGenerator()
    return _report_generator
