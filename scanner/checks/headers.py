SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Missing CSP allows a broader range of injection attacks (XSS, data injection) to succeed unmitigated.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Missing X-Frame-Options allows the site to be embedded in an iframe, enabling clickjacking attacks.",
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Missing HSTS allows the site to be accessed over unencrypted HTTP, exposing traffic to interception.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Missing X-Content-Type-Options allows browsers to MIME-sniff responses, which can lead to content-type confusion issues.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Missing Referrer-Policy may leak full URLs to third-party sites via the Referer header.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Missing Permissions-Policy leaves browser feature access (camera, geolocation, etc.) unrestricted.",
    },
}


def check_security_headers(response):
    """Given an HTTP response, return a finding for every security header
    that's missing from it."""
    findings = []
    if response is None:
        return findings

    present_headers = {k.lower() for k in response.headers.keys()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name.lower() not in present_headers:
            findings.append({
                "check": "Missing Security Header",
                "header": header_name,
                "severity": meta["severity"],
                "description": meta["description"],
            })

    return findings