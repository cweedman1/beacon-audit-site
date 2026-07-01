from __future__ import annotations

from typing import Any


NOT_EXECUTED = "Not Executed"
VERIFIED = "Verified"
NOT_DETECTED = "Not Detected"
VERIFICATION_FAILED = "Verification Failed"
TIMED_OUT = "Timed Out"
SKIPPED = "Skipped"
DEPRECATED = "Deprecated"


SCAN_CAPABILITIES: dict[str, dict[str, bool]] = {
    "QuickScan": {
        "Homepage only": True,
        "DNS": True,
        "SSL": True,
        "Headers": True,
        "Technology Profile": True,
        "Hosting": True,
        "Framework": True,
        "Registrar": True,
        "Analytics": True,
        "Migration": True,
        "Homepage Lighthouse": True,
        "Business Summary": True,
        "Representative pages": False,
        "Site Crawl": False,
        "Full Repair Plan": False,
        "Per-page analysis": False,
        "Public scan checks": True,
    },
    "Business Audit": {
        "Homepage only": True,
        "DNS": True,
        "SSL": True,
        "Headers": True,
        "Technology Profile": True,
        "Hosting": True,
        "Framework": True,
        "Registrar": True,
        "Analytics": True,
        "Migration": True,
        "Homepage Lighthouse": True,
        "Business Summary": True,
        "Representative pages": False,
        "Site Crawl": False,
        "Full Repair Plan": True,
        "Per-page analysis": False,
        "Public scan checks": True,
    },
    "Deep Site Audit": {
        "Homepage only": False,
        "DNS": True,
        "SSL": True,
        "Headers": True,
        "Technology Profile": True,
        "Hosting": True,
        "Framework": True,
        "Registrar": True,
        "Analytics": True,
        "Migration": True,
        "Homepage Lighthouse": True,
        "Business Summary": True,
        "Representative pages": True,
        "Site Crawl": True,
        "Full Repair Plan": True,
        "Per-page analysis": True,
        "Public scan checks": True,
    },
}


REPORT_SECTIONS = [
    "Business Report",
    "Technology Profile",
    "Migration",
    "Repair",
    "Business Summary",
    "Expert Review",
    "Technical Findings",
    "Diagnostics",
    "Integrity",
]


def capability_matrix(audit_type: str) -> dict[str, Any]:
    capabilities = SCAN_CAPABILITIES.get(audit_type, SCAN_CAPABILITIES["Business Audit"])
    return {
        "audit_type": audit_type,
        "components": [
            {
                "component": component,
                "executed": executed,
                "status": "Executed" if executed else NOT_EXECUTED,
                "reason": None if executed else f"{component} is outside the {audit_type} scope.",
            }
            for component, executed in capabilities.items()
        ],
    }


def section_contract(audit_type: str) -> list[dict[str, str]]:
    return [
        {
            "section": section,
            "status": "Executed",
            "reason": "",
        }
        for section in REPORT_SECTIONS
    ]
