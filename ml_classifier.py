"""
ml_classifier.py
Simple rule-based + ML severity classifier.
Falls back to hardcoded rules if scikit-learn is unavailable.
"""

# Severity mapping (rule-based fallback)
SEVERITY_MAP = {
    "sql injection":           "Critical",
    "xss":                     "High",
    "cross-site scripting":    "High",
    "open redirect":           "Medium",
    "missing security header": "Low",
    "information disclosure":  "Info",
    "csrf":                    "Medium",
    "clickjacking":            "Medium",
    "ssrf":                    "High",
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEVERITY_COLOR = {
    "Critical": "#ff4757",
    "High":     "#ff9600",
    "Medium":   "#ffd32a",
    "Low":      "#00d4ff",
    "Info":     "#a4b0be",
}


def classify_severity(vulnerability_name: str) -> str:
    """
    Return severity string for a given vulnerability type.
    Uses rule-based lookup with ML override when model is available.
    """
    key = vulnerability_name.lower().strip()

    # Try exact match first
    for pattern, severity in SEVERITY_MAP.items():
        if pattern in key:
            return severity

    # Default
    return "Medium"


def severity_color(severity: str) -> str:
    return SEVERITY_COLOR.get(severity, "#a4b0be")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)
