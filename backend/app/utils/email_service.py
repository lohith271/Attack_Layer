import os
import smtplib
import threading
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("app.email_service")

def send_approval_alert_email(
    event_id: int,
    payload: str,
    threat_type: str,
    severity: str,
    memory_id: int = None
):
    """
    Synchronously send an HTML email alert for a pending human approval event.
    """
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER", "no-reply@attacklayer.com")
    admin_email = os.getenv("ADMIN_EMAIL")
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # If any required configuration is missing, log a warning and return early
    if not smtp_server or not smtp_port or not admin_email:
        logger.warning(
            "SMTP alert skipped: Config is incomplete. "
            "Please check SMTP_SERVER, SMTP_PORT, and ADMIN_EMAIL settings in your .env file."
        )
        return

    try:
        smtp_port = int(smtp_port)
    except ValueError:
        logger.error(f"SMTP alert failed: Invalid SMTP_PORT '{smtp_port}'. Must be an integer.")
        return

    # Determine display types and colors based on threat/severity
    color_map = {
        "HIGH": "#dc3545",    # Red
        "MEDIUM": "#ffc107",  # Yellow
        "LOW": "#17a2b8"      # Cyan
    }
    header_color = color_map.get(severity.upper(), "#6c757d")
    
    event_type = "Memory Contamination Scan" if memory_id else "User Chat Request"
    item_label = f"Memory ID #{memory_id}" if memory_id else f"Audit Event ID #{event_id}"

    # Build direct link to frontend HITL queue
    hitl_link = f"{frontend_url.rstrip('/')}/hitl"

    # Construct MIMEMultipart email message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"⚠️ [HITL Alert] Human Review Required - Severity: {severity}"
    msg["From"] = smtp_sender
    msg["To"] = admin_email

    # HTML Email template body
    html_content = f"""
    <html>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; padding: 24px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); border: 1px solid #e2e8f0; overflow: hidden;">
          
          <!-- Header Banner -->
          <div style="background-color: {header_color}; padding: 24px; text-align: center; color: #ffffff;">
            <h2 style="margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.05em;">SECURITY WARNING</h2>
            <p style="margin: 4px 0 0 0; font-size: 14px; opacity: 0.9;">Pending Human-In-The-Loop Approval</p>
          </div>

          <!-- Content Body -->
          <div style="padding: 24px;">
            <p style="margin-top: 0; font-size: 16px;">
              An event has been flagged and suspended, requiring manual validation before the system can proceed.
            </p>

            <!-- Table of Event Info -->
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px;">
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px 0; font-weight: 600; color: #475569; width: 120px;">Source Type</td>
                <td style="padding: 10px 0; color: #0f172a;">{event_type}</td>
              </tr>
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px 0; font-weight: 600; color: #475569;">Target Item</td>
                <td style="padding: 10px 0; color: #0f172a;">{item_label}</td>
              </tr>
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px 0; font-weight: 600; color: #475569;">Threat Detected</td>
                <td style="padding: 10px 0; color: #dc3545; font-weight: bold;">{threat_type}</td>
              </tr>
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px 0; font-weight: 600; color: #475569;">Severity</td>
                <td style="padding: 10px 0; color: {header_color}; font-weight: bold;">{severity}</td>
              </tr>
              <tr>
                <td style="padding: 10px 0; font-weight: 600; color: #475569; vertical-align: top;">Payload Snippet</td>
                <td style="padding: 10px 0; color: #334155; font-style: italic; background-color: #f1f5f9; padding: 10px; border-radius: 6px; font-family: monospace; white-space: pre-wrap;">{payload}</td>
              </tr>
            </table>

            <!-- Call-to-action Button -->
            <div style="text-align: center; margin: 32px 0 12px 0;">
              <a href="{hitl_link}" style="background-color: #0f172a; color: #ffffff; padding: 12px 30px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; display: inline-block; box-shadow: 0 4px 6px -1px rgba(15, 23, 42, 0.3);">
                Review & Take Action
              </a>
            </div>
            
            <p style="font-size: 13px; color: #64748b; text-align: center; margin-top: 10px;">
              (You will be redirected to the AttackLayer HITL dashboard to approve or reject this request)
            </p>
          </div>

          <!-- Footer -->
          <div style="background-color: #f8fafc; border-top: 1px solid #e2e8f0; padding: 16px; text-align: center; font-size: 12px; color: #64748b;">
            This is an automated security alert sent by AttackLayer.<br/>
            Do not reply directly to this notification.
          </div>
        </div>
      </body>
    </html>
    """
    msg.attach(MIMEText(html_content, "html"))

    try:
        # Connect using TLS or standard SMTP depending on configurations
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        
        # Start TLS if port is standard submission port (587)
        if smtp_port == 587:
            server.starttls()
            
        # Login if username is provided
        if smtp_username:
            server.login(smtp_username, smtp_password)

        server.sendmail(smtp_sender, admin_email, msg.as_string())
        server.quit()
        logger.info(f"Successfully sent HITL email alert for event {event_id} / memory {memory_id} to {admin_email}")
    except Exception as e:
        logger.error(f"Failed to send HITL email alert: {e}", exc_info=True)


def send_approval_alert_email_async(
    event_id: int,
    payload: str,
    threat_type: str,
    severity: str,
    memory_id: int = None
):
    """
    Sends the email alert in a background thread to prevent blocking client requests.
    """
    thread = threading.Thread(
        target=send_approval_alert_email,
        kwargs={
            "event_id": event_id,
            "payload": payload,
            "threat_type": threat_type,
            "severity": severity,
            "memory_id": memory_id
        }
    )
    thread.daemon = True
    thread.start()
