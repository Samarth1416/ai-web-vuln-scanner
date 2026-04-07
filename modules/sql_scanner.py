import requests
from config import Config

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "mysql_fetch",
    "ora-01756",
    "sqlite_error",
    "syntax error in query expression",
    "[microsoft][odbc",
]

# Only 3 most effective payloads for speed
PAYLOADS = [
    "'",
    "' OR '1'='1'--",
    '" OR 1=1--',
]


def check_sql(url):
    findings = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        params = {"id": ["1"]}

    # Test max 2 params to keep scan fast
    for param_name in list(params.keys())[:2]:
        found = False
        for payload in PAYLOADS:
            if found:
                break
            test_params = dict(params)
            test_params[param_name] = [payload]
            new_query = urlencode({k: v[0] for k, v in test_params.items()})
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, timeout=4,
                                 allow_redirects=True,
                                 headers={"User-Agent": "CyberScanAI/1.0"})
                body = r.text.lower()

                for error in SQL_ERRORS:
                    if error in body:
                        findings.append({
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": error,
                            "status_code": r.status_code,
                        })
                        found = True
                        break

            except Exception:
                pass

    return findings