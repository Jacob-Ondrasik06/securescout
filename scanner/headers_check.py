import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "title": "Missing HSTS header",
        "detail": "HTTP Strict Transport Security is not set. Browsers may allow downgrade attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "high",
        "title": "Missing Content-Security-Policy header",
        "detail": "No CSP header found. This makes XSS attacks easier to execute.",
        "fix": "Add a Content-Security-Policy header to restrict which resources can be loaded."
    },
    "X-Frame-Options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options header",
        "detail": "Site can be embedded in iframes, enabling clickjacking attacks.",
        "fix": "Add: X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "title": "Missing X-Content-Type-Options header",
        "detail": "Browsers may MIME-sniff responses, enabling content injection.",
        "fix": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy header",
        "detail": "Browser may send full URL in the Referer header, leaking sensitive paths.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy header",
        "detail": "No restrictions on browser features like camera, microphone, or geolocation.",
        "fix": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
}


def check_headers(url):
    findings = []

    if not url.startswith("http"):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "severity": info["severity"],
                    "title": info["title"],
                    "detail": info["detail"],
                    "fix": info["fix"]
                })

        if "server" in headers:
            server = headers["server"]
            if any(tech in server.lower() for tech in ["apache/", "nginx/", "iis/"]):
                findings.append({
                    "severity": "low",
                    "title": "Server version disclosed",
                    "detail": f"Server header reveals: {server}",
                    "fix": "Configure your server to suppress or genericize the Server header."
                })

        if "x-powered-by" in headers:
            findings.append({
                "severity": "low",
                "title": "Technology stack disclosed via X-Powered-By",
                "detail": f"X-Powered-By: {headers['x-powered-by']}",
                "fix": "Remove the X-Powered-By header from your server config."
            })

        if not findings:
            findings.append({
                "severity": "info",
                "title": "All key security headers are present",
                "detail": "Good header configuration detected.",
                "fix": None
            })

    except requests.exceptions.SSLError:
        findings.append({
            "severity": "critical",
            "title": "SSL error when connecting",
            "detail": "Could not establish a secure connection.",
            "fix": "Check your SSL certificate configuration."
        })
    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Header check could not complete",
            "detail": str(e),
            "fix": None
        })

    return findings
