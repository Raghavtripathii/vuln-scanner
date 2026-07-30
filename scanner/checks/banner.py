BANNER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def check_server_banners(response):
    findings = []
    if response is None:
        return findings

    for header in BANNER_HEADERS:
        value = response.headers.get(header)
        if value:
            findings.append({
                "check": "Server Banner Disclosure",
                "header": header,
                "value": value,
                "severity": "Low",
                "description": f"The '{header}' header discloses '{value}', which can help an attacker identify known vulnerabilities for that specific software/version.",
            })

    return findings