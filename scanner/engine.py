import concurrent.futures
from .ssl_check import check_ssl
from .headers_check import check_headers
from .exposed_files import check_exposed_files
from .dns_check import check_dns

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def calculate_score(findings):
    deductions = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
    return max(0, 100 - deductions)


def score_label(score):
    if score >= 90:
        return "good", "Low Risk"
    elif score >= 70:
        return "warning", "Moderate Risk"
    elif score >= 50:
        return "danger", "High Risk"
    else:
        return "danger", "Critical Risk"


def run_scan(url):
    if not url.startswith("http"):
        url = "https://" + url

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    checks = {
        "SSL / TLS":       (check_ssl,           domain),
        "Security Headers":(check_headers,        url),
        "Exposed Files":   (check_exposed_files,  url),
        "DNS Security":    (check_dns,            domain),
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fn, arg): name
            for name, (fn, arg) in checks.items()
        }
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = [{
                    "severity": "info",
                    "title": f"{name} check failed",
                    "detail": str(e),
                    "fix": None
                }]

    all_findings = [f for findings in results.values() for f in findings]
    real_findings = [f for f in all_findings if f["severity"] != "info"]
    real_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    score = calculate_score(real_findings)
    label, risk = score_label(score)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in real_findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "label": label,
        "risk": risk,
        "counts": counts,
        "findings": real_findings,
        "by_category": results,
    }
