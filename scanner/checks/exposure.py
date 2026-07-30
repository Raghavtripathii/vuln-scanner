SENSITIVE_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/admin",
    "/admin/",
    "/wp-admin/",
    "/.htaccess",
    "/config.php",
    "/backup.sql",
    "/.DS_Store",
]


def check_exposed_paths(client):
    findings = []

    for path in SENSITIVE_PATHS:
        resp = client.get(path)
        if resp is None:
            continue

        if resp.status_code == 200:
            findings.append({
                "check": "Exposed Sensitive Path",
                "path": path,
                "status_code": resp.status_code,
                "severity": "High",
                "description": f"Path '{path}' returned HTTP 200, indicating it may be publicly accessible and should not be.",
            })

    return findings


def check_robots_txt(client):
    findings = []
    resp = client.get("/robots.txt")
    if resp is None or resp.status_code != 200:
        return findings

    disallowed = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)

    if disallowed:
        findings.append({
            "check": "robots.txt Discloses Hidden Paths",
            "severity": "Info",
            "disallowed_paths": disallowed,
            "description": "robots.txt lists paths intended to be hidden from search engines. These paths are not access-controlled by robots.txt itself and may reveal application structure to an attacker.",
        })

    return findings