import requests
from config import Config
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Only 2 targets needed to detect open redirect
REDIRECT_TARGETS = [
    "https://evil.example.com",
    "//evil.example.com",
]


def check_open_redirect(url):
    """
    Test URL parameters that commonly handle redirects for open redirect vulns.
    Returns: list of dicts with {parameter, payload, evidence}
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Common redirect parameter names
    redirect_params = {"next", "redirect", "url", "return", "returnurl",
                       "goto", "dest", "destination", "redir", "target",
                       "continue", "forward", "location"}

    # Only test parameters that look like redirect params, or all params if small set
    test_params = {k: v for k, v in params.items()
                   if k.lower() in redirect_params} or params

    if not test_params:
        test_params = {"next": ["/"]}

    for param_name in test_params:
        for target in REDIRECT_TARGETS:
            inject = dict(params)
            inject[param_name] = [target]
            new_query = urlencode({k: v[0] for k, v in inject.items()})
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(
                    test_url,
                    timeout=4,
                    allow_redirects=False,
                    headers={"User-Agent": "CyberScanAI/1.0"}
                )

                # Check if 3xx redirect points to our injected target
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.example.com" in loc:
                        findings.append({
                            "parameter": param_name,
                            "payload": target,
                            "evidence": f"Redirect to: {loc}",
                            "status_code": r.status_code,
                        })
                        break

            except Exception:
                pass

    return findings
