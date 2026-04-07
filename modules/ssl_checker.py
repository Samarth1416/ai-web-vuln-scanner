"""
ssl_checker.py
Validates the SSL/TLS configuration of a target host.
Checks: certificate expiry, self-signed cert, HTTPS redirect enforcement.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


def check_ssl(url):
    """
    Perform SSL/TLS checks on the target URL's hostname.
    Returns a list of finding dicts.
    """
    findings = []
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    # Strip port if present
    hostname = hostname.split(":")[0]

    # ── 1. HTTPS redirect check ──────────────────
    if url.startswith("http://"):
        try:
            r = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "CyberScanAI/1.0"},
            )
            final = r.url or url
            if not final.startswith("https://"):
                findings.append({
                    "check": "No HTTPS Redirect",
                    "severity": "Medium",
                    "evidence": (
                        f"Site did not redirect HTTP → HTTPS. "
                        f"Final URL: {final}"
                    ),
                })
        except Exception:
            pass

    # ── 2. Certificate checks ────────────────────
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=6),
            server_hostname=hostname,
        )
        cert = conn.getpeercert()
        conn.close()

        # Expiry check
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                if days_left < 0:
                    findings.append({
                        "check": "Expired SSL Certificate",
                        "severity": "Critical",
                        "evidence": (
                            f"Certificate expired on {not_after_str} "
                            f"({abs(days_left)} days ago)."
                        ),
                    })
                elif days_left < 14:
                    findings.append({
                        "check": "SSL Certificate Expiring Soon",
                        "severity": "High",
                        "evidence": (
                            f"Certificate expires {not_after_str} "
                            f"({days_left} days remaining). Renew immediately."
                        ),
                    })
                elif days_left < 30:
                    findings.append({
                        "check": "SSL Certificate Expiring Soon",
                        "severity": "Medium",
                        "evidence": (
                            f"Certificate expires {not_after_str} "
                            f"({days_left} days remaining)."
                        ),
                    })
            except ValueError:
                pass

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "check": "Invalid / Self-Signed Certificate",
            "severity": "High",
            "evidence": f"Certificate verification failed: {e}",
        })
    except ssl.SSLError as e:
        findings.append({
            "check": "SSL/TLS Error",
            "severity": "High",
            "evidence": f"SSL handshake error on {hostname}:443 — {e}",
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Host not on HTTPS or unreachable on 443 — only report if http:// target
        if url.startswith("http://"):
            findings.append({
                "check": "No HTTPS Support",
                "severity": "High",
                "evidence": (
                    f"Port 443 is not open or unreachable on {hostname}. "
                    f"Site may not support HTTPS at all."
                ),
            })
    except Exception as e:
        findings.append({
            "check": "SSL Check Error",
            "severity": "Info",
            "evidence": str(e),
        })

    return findings
