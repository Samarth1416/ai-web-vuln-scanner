import requests
from config import Config

# (header_name, description, severity)
SECURITY_HEADERS = [
    ("Strict-Transport-Security",
     "HSTS missing — forces browsers to use HTTPS. Without it, users are vulnerable to SSL-stripping attacks.",
     "Medium"),
    ("Content-Security-Policy",
     "CSP missing — prevents XSS by controlling which resources the browser can load.",
     "High"),
    ("X-Frame-Options",
     "X-Frame-Options missing — page can be embedded in iframes, enabling clickjacking attacks.",
     "Medium"),
    ("X-Content-Type-Options",
     "X-Content-Type-Options missing — allows MIME-type sniffing, potentially enabling XSS.",
     "Low"),
    ("Referrer-Policy",
     "Referrer-Policy missing — full URL (including sensitive paths) may be leaked to third parties.",
     "Low"),
    ("Permissions-Policy",
     "Permissions-Policy missing — browser features (camera, mic, geolocation) are unrestricted.",
     "Low"),
    ("X-XSS-Protection",
     "X-XSS-Protection missing — legacy browsers have no XSS filter fallback.",
     "Low"),
]

INSECURE_HEADERS = [
    ("Server",
     "Server header exposes web server software and version, aiding fingerprinting.",
     "Info"),
    ("X-Powered-By",
     "X-Powered-By header reveals the backend tech stack, aiding targeted attacks.",
     "Info"),
]


def check_headers(url):
    """
    Fetch the URL and check for missing/insecure HTTP security headers.
    Returns: list of dicts with {header, description, severity, present}
    """
    findings = []

    try:
        r = requests.get(
            url,
            timeout=4,
            allow_redirects=True,
            headers={"User-Agent": "CyberScanAI/1.0"}
        )
        headers = {k.lower(): v for k, v in r.headers.items()}

        # Check for missing security headers
        for header, description, severity in SECURITY_HEADERS:
            if header.lower() not in headers:
                findings.append({
                    "header": header,
                    "description": description,
                    "severity": severity,
                    "evidence": "Header is absent from the HTTP response.",
                    "present": False,
                })

        # Check for leaking headers
        for header, description, severity in INSECURE_HEADERS:
            if header.lower() in headers:
                findings.append({
                    "header": header,
                    "description": description,
                    "severity": severity,
                    "evidence": f'Value: "{headers[header.lower()]}"',
                    "present": True,
                })

    except Exception as e:
        findings.append({
            "header": "Connection Error",
            "description": str(e),
            "severity": "Info",
            "evidence": "Could not connect to the target.",
            "present": False,
        })

    return findings
