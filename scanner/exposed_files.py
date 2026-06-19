import requests

SENSITIVE_PATHS = [
    ("/.env",                  "critical", "Environment file exposed",         ".env files contain database passwords and API keys."),
    ("/.git/config",           "critical", "Git repository exposed",           "Source code and history may be downloadable."),
    ("/wp-config.php.bak",     "critical", "WordPress config backup exposed",  "Contains database credentials."),
    ("/config.php.bak",        "critical", "PHP config backup exposed",        "May contain credentials or secrets."),
    ("/backup.zip",            "high",     "Backup archive exposed",           "Full site backup may be publicly downloadable."),
    ("/backup.sql",            "high",     "SQL dump exposed",                 "Full database contents may be publicly accessible."),
    ("/db.sql",                "high",     "SQL dump exposed",                 "Full database contents may be publicly accessible."),
    ("/admin",                 "high",     "Admin panel exposed",              "Admin interface is publicly accessible."),
    ("/phpmyadmin",            "high",     "phpMyAdmin exposed",               "Database admin panel is publicly accessible."),
    ("/wp-admin",              "medium",   "WordPress admin panel exposed",    "WordPress login page is publicly accessible."),
    ("/server-status",         "medium",   "Apache server-status exposed",     "Reveals server internals and active connections."),
    ("/robots.txt",            "info",     "robots.txt found",                 "Check for hidden paths disclosed in robots.txt."),
    ("/.htaccess",             "medium",   "htaccess file exposed",            "Server config may be readable."),
    ("/config.yaml",           "high",     "YAML config file exposed",         "May contain credentials or secrets."),
    ("/config.json",           "high",     "JSON config file exposed",         "May contain credentials or secrets."),
    ("/.DS_Store",             "low",      "macOS .DS_Store file exposed",     "Leaks directory structure information."),
]


def check_exposed_files(url):
    findings = []

    if not url.startswith("http"):
        url = "https://" + url

    base = url.rstrip("/")

    for path, severity, title, detail in SENSITIVE_PATHS:
        try:
            resp = requests.get(base + path, timeout=8, allow_redirects=False)
            if resp.status_code in (200, 206):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": f"Found at {base + path} — {detail}",
                    "fix": f"Immediately block public access to {path} via your web server config or firewall."
                })
        except Exception:
            continue

    if not findings:
        findings.append({
            "severity": "info",
            "title": "No sensitive files found",
            "detail": "Common sensitive paths were not publicly accessible.",
            "fix": None
        })

    return findings
