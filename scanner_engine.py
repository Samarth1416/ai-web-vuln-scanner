"""
scanner_engine.py
Orchestrates all scanner modules and produces a unified findings list.
Designed to be called inside a Flask SSE generator for real-time progress.
"""

import json
import time
from modules.sql_scanner import check_sql
from modules.xss_scanner import check_xss
from modules.redirect_scanner import check_open_redirect
from modules.header_scanner import check_headers
from modules.csrf_scanner import check_csrf
from modules.ssl_checker import check_ssl
from modules.rate_limit_checker import check_rate_limit
from ml_classifier import classify_severity

REMEDIATION = {
    "SQL Injection": (
        "Use parameterised queries / prepared statements. Never concatenate user input into SQL. "
        "Apply the principle of least privilege on database accounts. Consider a WAF."
    ),
    "XSS": (
        "HTML-encode all user-controlled output before rendering. Implement a strict "
        "Content-Security-Policy header. Use frameworks that auto-escape output (React, Vue, Angular)."
    ),
    "Open Redirect": (
        "Validate redirect destinations against a strict allowlist of internal paths. "
        "Never use raw user input as a redirect target."
    ),
    "Missing Security Header": (
        "Configure your web server or application to include the missing header. "
        "Use tools like securityheaders.com to verify your configuration."
    ),
    "Information Disclosure": (
        "Remove or suppress headers that reveal server software versions. "
        "Configure your web server to omit the Server and X-Powered-By headers."
    ),
    "CSRF": (
        "Implement CSRF tokens (synchronizer token pattern) on all state-changing forms. "
        "Use the SameSite=Strict or SameSite=Lax cookie attribute. "
        "Validate the Origin/Referer header on sensitive endpoints."
    ),
    "SSL/TLS": (
        "Ensure a valid, non-expired certificate from a trusted CA is installed. "
        "Enable HSTS to enforce HTTPS. Redirect all HTTP traffic to HTTPS. "
        "Use TLS 1.2+ and disable weak cipher suites."
    ),
    "Missing Rate Limiting": (
        "Implement account lockout or exponential backoff after repeated failed login attempts. "
        "Add CAPTCHA for suspicious activity. Use a WAF rule to throttle rapid requests. "
        "Return HTTP 429 Too Many Requests with a Retry-After header."
    ),
}


def run_scan(url, progress_callback=None):
    """
    Run all vulnerability scanners against the target URL.

    Args:
        url: Target URL string
        progress_callback: optional callable(message) for SSE progress

    Returns:
        list of finding dicts:
        {vulnerability, severity, details, remediation, evidence, parameter}
    """

    def emit(msg):
        if progress_callback:
            progress_callback(msg)

    all_findings = []

    # ── Phase 1: Connectivity check ─────────────
    emit("[*] Initialising scan engine...")
    time.sleep(0.3)
    emit(f"[+] Target: {url}")
    time.sleep(0.2)
    emit("[+] Crawling website structure...")
    time.sleep(0.5)

    # ── Phase 2: SQL Injection ───────────────────
    emit("[+] Testing SQL Injection payloads...")
    try:
        sql_findings = check_sql(url)
        if sql_findings:
            for f in sql_findings:
                severity = classify_severity("SQL Injection")
                all_findings.append({
                    "vulnerability": "SQL Injection",
                    "severity": severity,
                    "details": f"Parameter '{f['parameter']}' is vulnerable. Evidence: {f['evidence']}",
                    "remediation": REMEDIATION["SQL Injection"],
                    "evidence": f['evidence'],
                    "parameter": f['parameter'],
                })
            emit(f"[!] SQL Injection DETECTED in {len(sql_findings)} parameter(s)!")
        else:
            emit("[✓] SQL Injection — No vulnerabilities found")
    except Exception as e:
        emit(f"[!] SQL scanner error: {e}")

    time.sleep(0.3)

    # ── Phase 3: XSS ────────────────────────────
    emit("[+] Testing Cross-Site Scripting (XSS) payloads...")
    try:
        xss_findings = check_xss(url)
        if xss_findings:
            for f in xss_findings:
                severity = classify_severity("XSS")
                all_findings.append({
                    "vulnerability": "XSS",
                    "severity": severity,
                    "details": f"Reflected XSS in parameter '{f['parameter']}'. Payload reflected unescaped.",
                    "remediation": REMEDIATION["XSS"],
                    "evidence": f['evidence'],
                    "parameter": f['parameter'],
                })
            emit(f"[!] XSS DETECTED in {len(xss_findings)} parameter(s)!")
        else:
            emit("[✓] XSS — No vulnerabilities found")
    except Exception as e:
        emit(f"[!] XSS scanner error: {e}")

    time.sleep(0.3)

    # ── Phase 4: Open Redirect ───────────────────
    emit("[+] Testing Open Redirect vulnerabilities...")
    try:
        redir_findings = check_open_redirect(url)
        if redir_findings:
            for f in redir_findings:
                all_findings.append({
                    "vulnerability": "Open Redirect",
                    "severity": "Medium",
                    "details": f"Parameter '{f['parameter']}' redirected to: {f['evidence']}",
                    "remediation": REMEDIATION["Open Redirect"],
                    "evidence": f['evidence'],
                    "parameter": f['parameter'],
                })
            emit("[!] Open Redirect DETECTED!")
        else:
            emit("[✓] Open Redirect — No vulnerabilities found")
    except Exception as e:
        emit(f"[!] Redirect scanner error: {e}")

    time.sleep(0.3)

    # ── Phase 5: Security Headers ────────────────
    emit("[+] Checking HTTP security headers...")
    try:
        header_findings = check_headers(url)
        for f in header_findings:
            vuln_type = "Missing Security Header" if not f['present'] else "Information Disclosure"
            all_findings.append({
                "vulnerability": f"{vuln_type}: {f['header']}",
                "severity": f['severity'],
                "details": f['description'],
                "remediation": REMEDIATION.get(vuln_type, ""),
                "evidence": f['evidence'],
                "parameter": "HTTP Header",
            })
        if header_findings:
            emit(f"[!] {len(header_findings)} header issue(s) found!")
        else:
            emit("[✓] Security Headers — All headers present")
    except Exception as e:
        emit(f"[!] Header scanner error: {e}")

    time.sleep(0.2)

    # ── Phase 6: CSRF ────────────────────────────
    emit("[+] Checking for CSRF vulnerabilities on forms...")
    try:
        csrf_findings = check_csrf(url)
        if csrf_findings:
            for f in csrf_findings:
                all_findings.append({
                    "vulnerability": "CSRF — Missing Token",
                    "severity": "High",
                    "details": (
                        f"Form #{f['form_index']} (action='{f['action']}') "
                        f"accepts POST requests without a CSRF token."
                    ),
                    "remediation": REMEDIATION["CSRF"],
                    "evidence": f['evidence'],
                    "parameter": f"Form #{f['form_index']}",
                })
            emit(f"[!] CSRF vulnerability found in {len(csrf_findings)} form(s)!")
        else:
            emit("[✓] CSRF — All POST forms appear to have CSRF protection")
    except Exception as e:
        emit(f"[!] CSRF scanner error: {e}")

    time.sleep(0.3)

    # ── Phase 7: SSL/TLS ─────────────────────────
    emit("[+] Validating SSL/TLS certificate and configuration...")
    try:
        ssl_findings = check_ssl(url)
        if ssl_findings:
            for f in ssl_findings:
                all_findings.append({
                    "vulnerability": f"SSL/TLS: {f['check']}",
                    "severity": f['severity'],
                    "details": f['evidence'],
                    "remediation": REMEDIATION["SSL/TLS"],
                    "evidence": f['evidence'],
                    "parameter": "SSL/TLS",
                })
            emit(f"[!] {len(ssl_findings)} SSL/TLS issue(s) detected!")
        else:
            emit("[✓] SSL/TLS — Certificate is valid and HTTPS is enforced")
    except Exception as e:
        emit(f"[!] SSL checker error: {e}")

    time.sleep(0.3)

    # ── Phase 8: Rate Limiting ───────────────────
    emit("[+] Testing rate limiting on login forms...")
    try:
        rl_findings = check_rate_limit(url)
        if rl_findings:
            for f in rl_findings:
                all_findings.append({
                    "vulnerability": "Missing Rate Limiting",
                    "severity": "High",
                    "details": (
                        "Login form accepts rapid repeated requests without throttling. "
                        "This enables brute-force attacks."
                    ),
                    "remediation": REMEDIATION["Missing Rate Limiting"],
                    "evidence": f['evidence'],
                    "parameter": f.get('parameter', 'Login Form'),
                })
            emit("[!] No rate limiting detected — brute-force attack possible!")
        else:
            emit("[✓] Rate Limiting — Login form appears to be protected")
    except Exception as e:
        emit(f"[!] Rate limit checker error: {e}")

    time.sleep(0.2)

    # ── Summary ──────────────────────────────────
    if all_findings:
        emit(f"[✓] Scan complete — {len(all_findings)} issue(s) found.")
    else:
        emit("[✓] Scan complete — No vulnerabilities detected.")

    return all_findings