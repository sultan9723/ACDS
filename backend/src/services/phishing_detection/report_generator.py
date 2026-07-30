import logging
from typing import Dict, Any, Optional
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from xml.sax.saxutils import escape # Replaced reportlab.lib.utils.escape with xml.sax.saxutils.escape

from .models import Incident, Email # Added Email import
from .database import IncidentDatabase # Added IncidentDatabase import

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates summary reports for phishing incidents.
    """
    def __init__(self, incident_db: Optional[IncidentDatabase] = None):
        self.incident_db = incident_db
        logger.info("ReportGenerator initialized.")

    def generate_incident_report(
        self,
        incident: Incident,
        email: Optional[Email] = None,
        explanation: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generates a human-readable summary report for a given incident.
        """
        if explanation is None and isinstance(email, dict):
            explanation = email
            email = None

        report_lines = []
        report_lines.append(f"--- Phishing Incident Report ({incident.id}) ---")
        report_lines.append(f"Incident ID: {incident.id}")
        report_lines.append(f"Detected On: {incident.detection_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        status_value = incident.status.value if hasattr(incident.status, "value") else str(incident.status)
        report_lines.append(f"Status: {status_value.replace('_', ' ').title()}")
        report_lines.append(f"Associated Email ID: {incident.email_id}")
        if email:
            report_lines.append(f"Sender: {email.sender}")
            report_lines.append(f"Recipients: {', '.join(email.recipients)}")
            report_lines.append(f"Subject: {email.subject}")
        report_lines.append(f"Detection Agent: {incident.detection_agent_id}")
        report_lines.append(f"Assigned Analyst: {incident.assigned_analyst or 'Unassigned'}")
        report_lines.append("\n--- Detection Details ---")
        if explanation:
            report_lines.append(f"Summary: {explanation.get('summary', 'N/A')}")
            report_lines.append(f"Confidence Score: {explanation.get('confidence_score', 0.0):.2f}")
            report_lines.append(f"Matched Indicators: {', '.join(explanation.get('matched_indicators', ['None']))}")
        else:
            report_lines.append("No explanation available.")

        report_lines.append("\n--- Timeline ---")
        for entry in incident.timeline:
            report_lines.append(f"- {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}: {entry.event}")
            if entry.details:
                for k, v in entry.details.items():
                    report_lines.append(f"  {k}: {v}")

        logger.info(f"Generated report for incident {incident.id}.")
        return "\n".join(report_lines)

    async def generate_incident_report_pdf(self, incident: Incident, email: Email, explanation: Dict[str, Any], output_path: str) -> None:   
        """
        Generates a comprehensive, human-readable PDF report for a phishing incident.
        """
        try:
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Custom styles
            header_style = ParagraphStyle('Header', parent=styles['h1'], fontSize=16, alignment=TA_CENTER, spaceAfter=14, textColor=colors.HexColor('#0d47a1'))
            subheader_style = ParagraphStyle('SubHeader', parent=styles['h2'], fontSize=12, spaceBefore=10, spaceAfter=8, textColor=colors.HexColor('#1565c0'))
            normal_style = styles['Normal']
            bold_style = ParagraphStyle('BoldText', parent=normal_style, fontName='Helvetica-Bold')

            # Title
            story.append(Paragraph("Phishing Incident Report", header_style))
            story.append(Spacer(1, 0.2 * inch))

            # Incident Summary
            story.append(Paragraph("INCIDENT SUMMARY", header_style))
            summary_data = [
                ["Incident ID:", str(incident.id)],
                ["Detected On:", incident.detection_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')],
                ["Status:", incident.status.value.replace('_', ' ').title()],
                ["Detection Agent:", incident.detection_agent_id],
                ["Assigned Analyst:", incident.assigned_analyst or 'Unassigned'],
            ]
            summary_table = Table(summary_data, colWidths=[1.5*inch, 5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e3f2fd')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('ALIGN', (0,0), (0,-1), TA_LEFT),
                ('ALIGN', (1,0), (1,-1), TA_LEFT),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.3 * inch))
            
            # ==================== EMAIL DETAILS ====================
            story.append(Paragraph("EMAIL INFORMATION", header_style))

            email_data = [
                ["From:", email.sender],
                ["To:", ', '.join(email.recipients)],
                ["Subject:", email.subject],
            ]

            email_table = Table(email_data, colWidths=[1.5*inch, 5*inch]) 
            email_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e8f5e9')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('ALIGN', (0,0), (0,-1), TA_LEFT),
                ('ALIGN', (1,0), (1,-1), TA_LEFT),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
            ]))
            story.append(email_table)

            # Email body preview
            if email.body:
                story.append(Spacer(1, 0.15 * inch))
                story.append(Paragraph("Email Content Preview:", subheader_style))
                body_preview = email.body[:500] + "..." if len(email.body) > 500 else email.body
                story.append(Paragraph(f"<i>{escape(body_preview)}</i>", 
                                      ParagraphStyle('bodytext', parent=normal_style,
                                                   textColor=colors.HexColor('#34495e'),
                                                   backColor=colors.HexColor('#f8f9fa'),
                                                   borderPadding=10)))

            story.append(Spacer(1, 0.3 * inch))        
            # ==================== DETECTION ANALYSIS ====================
            story.append(Paragraph("DETECTION ANALYSIS", header_style))

            if explanation:
                detection_data = [
                    ["Summary:", explanation.get('summary', 'N/A')],
                    ["Confidence Score:", f"{explanation.get('confidence_score', 0.0):.2f}"],
                    ["Matched Indicators:", ', '.join(explanation.get('matched_indicators', ['None']))],
                ]
            else:
                detection_data = [["No explanation available.", ""]]

            detection_table = Table(detection_data, colWidths=[1.5*inch, 5*inch])
            detection_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ffe0b2')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('ALIGN', (0,0), (0,-1), TA_LEFT),
                ('ALIGN', (1,0), (1,-1), TA_LEFT),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
            ]))
            story.append(detection_table)
            story.append(Spacer(1, 0.3 * inch))

            # ==================== INCIDENT TIMELINE ====================
            story.append(Paragraph("INCIDENT TIMELINE", header_style))
            if incident.timeline:
                timeline_table_data = [['Timestamp', 'Event', 'Details']]
                for entry in incident.timeline:
                    details_str = ", ".join([f"{k}: {v}" for k, v in entry.details.items()])
                    timeline_table_data.append([
                        entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        entry.event,
                        details_str
                    ])
                
                timeline_table = Table(timeline_table_data, colWidths=[1.8*inch, 2*inch, 3*inch])
                timeline_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#cfd8dc')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                    ('ALIGN', (0,0), (-1,-1), TA_LEFT),
                    ('ALIGN', (1,0), (1,-1), TA_LEFT),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,0), 6),
                    ('BACKGROUND', (0,1), (-1,-1), colors.white),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e0e0e0')),
                ]))
                story.append(timeline_table)
            else:
                story.append(Paragraph("No timeline entries available.", normal_style))
            story.append(Spacer(1, 0.3 * inch))

            doc.build(story)
            logger.info(f"PDF report generated successfully at {output_path}")
        except Exception as e:
            logger.error(f"Error generating PDF report for incident {incident.id}: {e}")
            raise

_report_generator_instance: Optional[ReportGenerator] = None

async def get_report_generator(incident_db: IncidentDatabase) -> ReportGenerator:
    """Returns a singleton-like instance of the ReportGenerator."""   
    global _report_generator_instance
    if _report_generator_instance is None:
        _report_generator_instance = ReportGenerator(incident_db)
    return _report_generator_instance
