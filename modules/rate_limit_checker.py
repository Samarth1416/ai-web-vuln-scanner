"""
rate_limit_checker.py
Tests whether the target enforces rate limiting on login / sensitive forms.
Sends 12 rapid requests and checks for 429 / Retry-After / CAPTCHA signals.
"""

import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def _find_login_form(url, html):
    """Return (form_action, form_data) for the first login-like form found."""
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        names = [i.get("name", "").lower() for i in inputs]
        # Heuristic: form has a password field → likely a login form
        if any("pass" in n for n in names):
            action = form.get("action", "")
            if not action:
                action = url
            elif not action.startswith("http"):
                action = urljoin(url, action)

            # Build dummy POST data
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                n = name.lower()
                if "user" in n or "email" in n or "login" in n:
                    data[name] = "testuser_ratelimit@example.com"
                elif "pass" in n:
                    data[name] = "WrongPassword123!"
                else:
                    data[name] = inp.get("value", "test")
            return action, data
    return None, None


def check_rate_limit(url):
    """
    Probe the target for missing rate-limit protection on login forms.
    Returns a list of finding dicts.
    """
    findings = []
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "CyberScanAI/1.0"})

        # Fetch the page to find a login form
        r = session.get(url, timeout=6, allow_redirects=True)
        action, data = _find_login_form(url, r.text)

        if not action or not data:
            # No login form found — skip
            return findings

        # Send rapid requests
        PROBE_COUNT = 12
        statuses = []
        blocked = False
        for _ in range(PROBE_COUNT):
            try:
                resp = session.post(action, data=data, timeout=4, allow_redirects=False)
                statuses.append(resp.status_code)
                # Check for rate-limit signals
                if resp.status_code == 429:
                    blocked = True
                    break
                if "retry-after" in resp.headers or "x-ratelimit" in " ".join(resp.headers.keys()).lower():
                    blocked = True
                    break
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in ["too many", "rate limit", "captcha", "slow down", "blocked"]):
                    blocked = True
                    break
            except requests.exceptions.Timeout:
                blocked = True  # Server is throttling — treat as protected
                break
            except Exception:
                break
            time.sleep(0.05)

        if not blocked:
            unique_statuses = list(set(statuses))
            findings.append({
                "parameter": "Login Form",
                "evidence": (
                    f"Sent {len(statuses)} rapid POST requests to '{action}'. "
                    f"No rate-limiting (HTTP 429 / Retry-After / CAPTCHA) detected. "
                    f"Response codes: {unique_statuses}"
                ),
            })

    except Exception as e:
        findings.append({
            "parameter": "Rate Limit Check",
            "evidence": f"Rate limit checker error: {e}",
        })

    return findings
