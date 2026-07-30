import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]


def check_tls(hostname, port=443, timeout=8):
    findings = []

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append({
            "check": "TLS Connection Failed",
            "severity": "Info",
            "description": f"Could not connect to {hostname}:{port} for TLS testing: {e}",
        })
        return findings

    if der_cert:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        expiry_date = cert.not_valid_after_utc
        days_left = (expiry_date - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append({
                "check": "TLS Certificate Expired",
                "severity": "Critical",
                "expiry_date": expiry_date.isoformat(),
                "description": "The TLS certificate has expired.",
            })
        elif days_left < 30:
            findings.append({
                "check": "TLS Certificate Expiring Soon",
                "severity": "Medium",
                "expiry_date": expiry_date.isoformat(),
                "days_left": days_left,
                "description": "The TLS certificate will expire within 30 days.",
            })

    if cipher:
        cipher_name = cipher[0]
        if any(weak in cipher_name.upper() for weak in WEAK_CIPHER_KEYWORDS):
            findings.append({
                "check": "Weak TLS Cipher Negotiated",
                "severity": "High",
                "cipher": cipher_name,
                "description": f"The server negotiated a weak cipher suite ({cipher_name}), which may be vulnerable to known cryptographic attacks.",
            })

    return findings