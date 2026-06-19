import requests
import uuid

# Each entry: (path, severity, title, detail, signatures)
# A finding is only reported if the response is HTTP 200 AND the body contains
# at least one signature. Signatures are INSTANCE-SPECIFIC markers (form field
# names, config syntax) — never just a product's brand name, which can appear on
# unrelated pages. This avoids false positives on catch-all / profile / soft-404 pages.
SENSITIVE_PATHS = [
    ("/.env", "critical", "Environment file exposed",
     "Environment files contain database passwords, API keys, and secrets.",
     ["db_password=", "app_key=", "secret=", "api_key=", "database_url=",
      "aws_access", "db_host=", "mail_password="]),

    ("/.git/config", "critical", "Git repository config exposed",
     "Your source code and full commit history may be downloadable.",
     ["repositoryformatversion", "[remote \"", "[branch \""]),

    ("/wp-config.php.bak", "critical", "WordPress config backup exposed",
     "Contains live database credentials.",
     ["db_password", "define('db_", "define(\"db_"]),

    ("/config.php.bak", "critical", "PHP config backup exposed",
     "May contain database credentials or secrets.",
     ["<?php", "define(", "$config"]),

    ("/backup.sql", "high", "SQL database dump exposed",
     "A full database dump may be publicly downloadable.",
     ["insert into", "create table", "drop table", "-- mysql dump", "-- dump"]),

    ("/db.sql", "high", "SQL database dump exposed",
     "A full database dump may be publicly downloadable.",
     ["insert into", "create table", "drop table", "-- mysql dump", "-- dump"]),

    ("/server-status", "medium", "Apache server-status exposed",
     "Reveals server internals, active requests, and visitor IP addresses.",
     ["apache server status", "server uptime:", "requests currently being processed"]),

    ("/phpmyadmin/", "high", "phpMyAdmin panel exposed",
     "A live database administration panel is publicly reachable.",
     ["name=\"pma_username\"", "name=\"pma_password\"", "pmaversion", "phpmyadmin.css.php"]),

    ("/wp-admin/", "medium", "WordPress admin reachable",
     "The WordPress login page is publicly accessible.",
     ["name=\"wp-submit\"", "wp-login.php", "name=\"log\"", "id=\"loginform\""]),

    ("/.htaccess", "medium", "htaccess file exposed",
     "Server configuration directives may be readable.",
     ["rewriteengine", "rewriterule", "<files", "deny from", "order allow"]),

    ("/robots.txt", "info", "robots.txt found",
     "Review it for sensitive paths that shouldn't be publicly disclosed.",
     ["user-agent:", "disallow:"]),
]

MAX_BODY = 20000  # cap how much we read so a huge backup file can't blow up memory


def _fetch_body(url):
    """Return (status_code, lowercased body up to MAX_BODY chars) or (None, '')."""
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, stream=True)
        status = resp.status_code
        body = ""
        if status == 200:
            for chunk in resp.iter_content(8192):
                if not chunk:
                    break
                body += chunk.decode("utf-8", "ignore")
                if len(body) >= MAX_BODY:
                    break
        resp.close()
        return status, body.lower()
    except Exception:
        return None, ""


def check_exposed_files(url):
    findings = []

    if not url.startswith("http"):
        url = "https://" + url
    base = url.rstrip("/")

    # Baseline: how does this site respond to a path that definitely doesn't exist?
    # If it returns 200 (a catch-all), we use its body to reject look-alike pages.
    rand_path = f"/securescout-{uuid.uuid4().hex[:12]}"
    base_status, base_body = _fetch_body(base + rand_path)
    catch_all = base_status == 200
    base_fingerprint = base_body[:600]

    for path, severity, title, detail, signatures in SENSITIVE_PATHS:
        status, body = _fetch_body(base + path)
        if status != 200 or not body:
            continue

        # If the site is a catch-all and this path returns the same generic page
        # as a random nonexistent path, it's not really exposed — skip it.
        if catch_all and body[:600] == base_fingerprint:
            continue

        if any(sig.lower() in body for sig in signatures):
            findings.append({
                "severity": severity,
                "title": title,
                "detail": f"Found at {base + path} — {detail}",
                "fix": f"Block public access to {path} via your web server config or firewall."
                if severity != "info" else "Review the contents and remove anything sensitive."
            })

    if not findings:
        findings.append({
            "severity": "info",
            "title": "No exposed sensitive files found",
            "detail": "Common sensitive paths were not publicly accessible.",
            "fix": None
        })

    return findings
