import dns.resolver


def check_dns(domain):
    findings = []
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # SPF check
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = any("v=spf1" in str(r) for r in answers)
        if not spf_found:
            findings.append({
                "severity": "medium",
                "title": "No SPF record found",
                "detail": "Without SPF, attackers can send emails that appear to come from your domain.",
                "fix": "Add a TXT record: v=spf1 include:your-mail-provider.com ~all"
            })
    except Exception:
        findings.append({
            "severity": "info",
            "title": "SPF check could not complete",
            "detail": "Could not query TXT records.",
            "fix": None
        })

    # DMARC check
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_found = any("v=DMARC1" in str(r) for r in answers)
        if not dmarc_found:
            findings.append({
                "severity": "medium",
                "title": "No DMARC record found",
                "detail": "Without DMARC, email spoofing from your domain is harder to detect and block.",
                "fix": "Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"
            })
    except dns.resolver.NXDOMAIN:
        findings.append({
            "severity": "medium",
            "title": "No DMARC record found",
            "detail": "DMARC record does not exist for this domain.",
            "fix": "Add a DMARC TXT record at _dmarc.yourdomain.com"
        })
    except Exception:
        pass

    if not findings:
        findings.append({
            "severity": "info",
            "title": "DNS security records look good",
            "detail": "SPF and DMARC records are present.",
            "fix": None
        })

    return findings
