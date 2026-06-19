import ssl
import socket
from datetime import datetime


def check_ssl(hostname):
    findings = []
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        if days_left < 0:
            findings.append({
                "severity": "critical",
                "title": "SSL certificate expired",
                "detail": f"Certificate expired {abs(days_left)} days ago.",
                "fix": "Renew your SSL certificate immediately. Use Let's Encrypt for free certs."
            })
        elif days_left < 14:
            findings.append({
                "severity": "high",
                "title": "SSL certificate expiring soon",
                "detail": f"Certificate expires in {days_left} days.",
                "fix": "Renew your SSL certificate before it expires."
            })
        elif days_left < 30:
            findings.append({
                "severity": "medium",
                "title": "SSL certificate expiring in under 30 days",
                "detail": f"Certificate expires in {days_left} days.",
                "fix": "Plan to renew your SSL certificate soon."
            })

        protocol = s.version() if hasattr(s, "version") else "Unknown"
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append({
                "severity": "high",
                "title": f"Weak protocol in use: {protocol}",
                "detail": "Older TLS versions have known vulnerabilities.",
                "fix": "Configure your server to use TLS 1.2 or TLS 1.3 only."
            })

        if not findings:
            findings.append({
                "severity": "info",
                "title": "SSL certificate is valid",
                "detail": f"Certificate valid for {days_left} more days.",
                "fix": None
            })

    except ssl.SSLCertVerificationError:
        findings.append({
            "severity": "critical",
            "title": "SSL certificate is invalid or untrusted",
            "detail": "The certificate could not be verified by a trusted authority.",
            "fix": "Replace your certificate with one from a trusted CA like Let's Encrypt."
        })
    except ConnectionRefusedError:
        findings.append({
            "severity": "high",
            "title": "No HTTPS detected",
            "detail": "The site does not appear to be serving traffic over HTTPS on port 443.",
            "fix": "Enable HTTPS. Use Let's Encrypt for a free certificate."
        })
    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "SSL check could not complete",
            "detail": str(e),
            "fix": None
        })

    return findings
