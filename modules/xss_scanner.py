import requests
from config import Config
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# 3 most reliable XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
]


def check_xss(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        params = {"q": ["test"]}

    # Test max 2 params
    for param_name in list(params.keys())[:2]:
        found = False
        for payload in XSS_PAYLOADS:
            if found:
                break
            test_params = dict(params)
            test_params[param_name] = [payload]
            new_query = urlencode({k: v[0] for k, v in test_params.items()})
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(
                    test_url,
                    timeout=4,
                    allow_redirects=True,
                    headers={"User-Agent": "CyberScanAI/1.0"}
                )

                if payload.lower() in r.text.lower():
                    findings.append({
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Payload reflected in response (HTTP {r.status_code})",
                        "status_code": r.status_code,
                    })
                    found = True

            except Exception:
                pass

    return findings