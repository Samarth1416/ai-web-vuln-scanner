"""
csrf_scanner.py
Detects missing CSRF protection on HTML forms.
"""

import requests
from bs4 import BeautifulSoup

CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken",
    "xsrf", "xsrf_token", "_csrf_token",
]

def check_csrf(url):
    """
    Fetch the target URL and inspect all HTML forms for CSRF tokens.
    Returns a list of findings dicts.
    """
    findings = []
    try:
        r = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "CyberScanAI/1.0"},
        )
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return findings  # No forms = no CSRF risk from this page

        for i, form in enumerate(forms, 1):
            action = form.get("action", "(same page)")
            method = form.get("method", "get").upper()

            # Only POST forms are at risk
            if method != "POST":
                continue

            # Check for CSRF token in hidden inputs
            inputs = form.find_all("input")
            has_token = False
            for inp in inputs:
                inp_name = (inp.get("name") or "").lower()
                inp_type = (inp.get("type") or "").lower()
                if inp_type == "hidden" and any(tok in inp_name for tok in CSRF_TOKEN_NAMES):
                    has_token = True
                    break

            if not has_token:
                findings.append({
                    "form_index": i,
                    "action": action,
                    "method": method,
                    "evidence": (
                        f"Form #{i} (action='{action}', method=POST) has no CSRF "
                        f"token in hidden inputs. Fields: "
                        f"{[inp.get('name','?') for inp in inputs]}"
                    ),
                })

    except Exception as e:
        findings.append({
            "form_index": 0,
            "action": "N/A",
            "method": "N/A",
            "evidence": f"CSRF scanner error: {e}",
        })

    return findings
