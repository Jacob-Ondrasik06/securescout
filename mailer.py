"""Email sending for SecureScout.

Configured via environment variables so no credentials live in code:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, FROM_EMAIL, FROM_NAME

If SMTP is not configured, send_email() is a no-op that returns False — the
app still captures the lead, it just doesn't deliver mail until creds are set.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", SMTP_USER or "noreply@securescout.app")
FROM_NAME = os.environ.get("FROM_NAME", "SecureScout")


def is_configured():
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS)


def send_email(to_email, subject, html_body):
    """Returns (success: bool, message: str)."""
    if not is_configured():
        print(f"[mailer] SMTP not configured — would have emailed {to_email}: {subject}")
        return False, "Email delivery not configured yet"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        return True, "Sent"
    except Exception as e:
        print(f"[mailer] send failed: {e}")
        return False, str(e)


SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
}


def build_report_email(result, scan_id, base_url=""):
    """Render a scan result dict into an HTML email body."""
    domain = result.get("domain", "your website")
    score = result.get("score", 0)
    risk = result.get("risk", "")
    counts = result.get("counts", {})
    findings = result.get("findings", [])

    if score >= 90:
        score_color = "#22c55e"
    elif score >= 70:
        score_color = "#eab308"
    else:
        score_color = "#ef4444"

    rows = ""
    for f in findings[:8]:
        color = SEV_COLORS.get(f.get("severity"), "#6b7280")
        label = f.get("severity", "").upper()
        rows += f"""
        <tr>
          <td style="padding:10px 12px;border-bottom:1px solid #1f2937;vertical-align:top;">
            <span style="display:inline-block;background:{color};color:#fff;font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;">{label}</span>
          </td>
          <td style="padding:10px 12px;border-bottom:1px solid #1f2937;color:#e5e7eb;font-size:14px;">
            <strong style="color:#fff;">{f.get('title','')}</strong><br>
            <span style="color:#9ca3af;font-size:13px;">{f.get('detail','')}</span>
          </td>
        </tr>"""

    more = ""
    if len(findings) > 8:
        more = f'<p style="color:#9ca3af;font-size:13px;">+ {len(findings) - 8} more findings in your full report.</p>'

    results_link = f"{base_url}/results/{scan_id}" if base_url else ""
    link_btn = ""
    if results_link:
        link_btn = f"""
        <a href="{results_link}" style="display:inline-block;background:#22c55e;color:#0a0a0a;text-decoration:none;font-weight:600;padding:12px 28px;border-radius:8px;font-size:14px;">View full results online</a>"""

    return f"""
    <div style="background:#0a0a0a;padding:32px 0;font-family:Arial,Helvetica,sans-serif;">
      <div style="max-width:600px;margin:0 auto;background:#111827;border:1px solid #1f2937;border-radius:12px;overflow:hidden;">
        <div style="padding:24px 28px;border-bottom:1px solid #1f2937;">
          <span style="color:#22c55e;font-weight:700;font-size:18px;">SecureScout</span>
        </div>
        <div style="padding:28px;">
          <p style="color:#9ca3af;font-size:14px;margin:0 0 4px;">Security scan report for</p>
          <h1 style="color:#fff;font-size:24px;margin:0 0 20px;">{domain}</h1>

          <div style="text-align:center;padding:20px;background:#0a0a0a;border-radius:10px;margin-bottom:24px;">
            <div style="font-size:48px;font-weight:700;color:{score_color};line-height:1;">{score}<span style="font-size:20px;color:#6b7280;">/100</span></div>
            <div style="color:{score_color};font-weight:600;font-size:16px;margin-top:6px;">{risk}</div>
          </div>

          <table width="100%" style="border-collapse:collapse;margin-bottom:24px;text-align:center;">
            <tr>
              <td style="padding:10px;"><div style="font-size:24px;font-weight:700;color:#ef4444;">{counts.get('critical',0)}</div><div style="font-size:12px;color:#9ca3af;">Critical</div></td>
              <td style="padding:10px;"><div style="font-size:24px;font-weight:700;color:#f97316;">{counts.get('high',0)}</div><div style="font-size:12px;color:#9ca3af;">High</div></td>
              <td style="padding:10px;"><div style="font-size:24px;font-weight:700;color:#eab308;">{counts.get('medium',0)}</div><div style="font-size:12px;color:#9ca3af;">Medium</div></td>
              <td style="padding:10px;"><div style="font-size:24px;font-weight:700;color:#3b82f6;">{counts.get('low',0)}</div><div style="font-size:12px;color:#9ca3af;">Low</div></td>
            </tr>
          </table>

          <h2 style="color:#fff;font-size:16px;margin:0 0 12px;">Top findings</h2>
          <table width="100%" style="border-collapse:collapse;margin-bottom:16px;">
            {rows if rows else '<tr><td style="color:#22c55e;padding:12px;">No issues found — nicely done.</td></tr>'}
          </table>
          {more}

          <div style="text-align:center;margin:28px 0 8px;">
            {link_btn}
          </div>

          <p style="color:#6b7280;font-size:12px;text-align:center;margin-top:24px;border-top:1px solid #1f2937;padding-top:20px;">
            This scan covers the basics. The Pro report adds XSS &amp; SQL injection testing,
            a prioritized fix list, and monthly rescans.<br><br>
            SecureScout — built in public by Jacob Ondrasik
          </p>
        </div>
      </div>
    </div>"""
