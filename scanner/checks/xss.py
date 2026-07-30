import uuid

XSS_TEST_PARAMS = ["q", "search", "query", "name", "id", "input", "term"]


def check_reflected_xss(client):
    findings = []
    marker = uuid.uuid4().hex[:8]
    payload = f"<vulnscan{marker}>"

    for param in XSS_TEST_PARAMS:
        resp = client.get("/", params={param: payload})
        if resp is None:
            continue

        if payload in resp.text:
            findings.append({
                "check": "Possible Reflected XSS",
                "parameter": param,
                "severity": "High",
                "evidence": f"Unescaped payload '{payload}' reflected in response for parameter '{param}'.",
                "description": "The application reflects user-supplied input without encoding special HTML characters, which may allow script injection.",
            })

    return findings