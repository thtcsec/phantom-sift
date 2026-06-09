"""Threat Intelligence — IOC enrichment via VirusTotal + AbuseIPDB.

Directly adapted from SOAR repos' integrations/intel.py.
This enriches findings with external reputation data when IOCs are found.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from ..config import get_settings

logger = structlog.get_logger()


@dataclass
class IntelResult:
    """Result from threat intelligence lookup."""

    source: str
    indicator: str
    indicator_type: str  # "hash", "ip", "domain"
    malicious: bool
    score: float  # 0.0 - 1.0
    details: dict[str, Any]


class ThreatIntelClient:
    """Multi-source threat intelligence lookups.

    Ported from SOAR's integrations/intel.py — same API structure,
    adapted for forensic IOC enrichment rather than real-time scoring.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._vt_key = settings.virustotal_api_key
        self._abuse_key = settings.abuseipdb_api_key
        self._client = httpx.Client(timeout=10.0)

    def lookup_hash(self, file_hash: str) -> list[IntelResult]:
        """Look up file hash against threat intelligence."""
        results = []
        if self._vt_key:
            results.append(self._vt_hash_lookup(file_hash))
        return [r for r in results if r is not None]

    def lookup_ip(self, ip_address: str) -> list[IntelResult]:
        """Look up IP address reputation."""
        results = []
        if self._vt_key:
            results.append(self._vt_ip_lookup(ip_address))
        if self._abuse_key:
            results.append(self._abuseipdb_lookup(ip_address))
        return [r for r in results if r is not None]

    def lookup_domain(self, domain: str) -> list[IntelResult]:
        """Look up domain reputation."""
        results = []
        if self._vt_key:
            results.append(self._vt_domain_lookup(domain))
        return [r for r in results if r is not None]

    def _vt_hash_lookup(self, file_hash: str) -> IntelResult | None:
        """Query VirusTotal for file hash."""
        try:
            resp = self._client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self._vt_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = malicious_count / total
                return IntelResult(
                    source="virustotal",
                    indicator=file_hash,
                    indicator_type="hash",
                    malicious=score > 0.3,
                    score=score,
                    details=stats,
                )
            return None
        except Exception as e:
            logger.warning("vt_lookup_failed", error=str(e))
            return None

    def _vt_ip_lookup(self, ip: str) -> IntelResult | None:
        """Query VirusTotal for IP reputation."""
        try:
            resp = self._client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self._vt_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = malicious_count / total
                return IntelResult(
                    source="virustotal",
                    indicator=ip,
                    indicator_type="ip",
                    malicious=score > 0.2,
                    score=score,
                    details=stats,
                )
            return None
        except Exception as e:
            logger.warning("vt_ip_failed", error=str(e))
            return None

    def _vt_domain_lookup(self, domain: str) -> IntelResult | None:
        """Query VirusTotal for domain reputation."""
        try:
            resp = self._client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self._vt_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = malicious_count / total
                return IntelResult(
                    source="virustotal",
                    indicator=domain,
                    indicator_type="domain",
                    malicious=score > 0.2,
                    score=score,
                    details=stats,
                )
            return None
        except Exception as e:
            logger.warning("vt_domain_failed", error=str(e))
            return None

    def _abuseipdb_lookup(self, ip: str) -> IntelResult | None:
        """Query AbuseIPDB for IP reputation."""
        try:
            resp = self._client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._abuse_key, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                return IntelResult(
                    source="abuseipdb",
                    indicator=ip,
                    indicator_type="ip",
                    malicious=abuse_score > 50,
                    score=abuse_score / 100.0,
                    details={
                        "abuse_confidence": abuse_score,
                        "total_reports": data.get("totalReports", 0),
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                    },
                )
            return None
        except Exception as e:
            logger.warning("abuseipdb_failed", error=str(e))
            return None
