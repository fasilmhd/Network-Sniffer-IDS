# services/threat_intel.py
import requests
import logging

logger = logging.getLogger("ThreatIntel")

class ThreatIntelService:
    """Queries AbuseIPDB for IP reputation."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self._cache = {}

    def lookup(self, ip: str) -> dict:
        """Returns threat data for an IP. Caches results to avoid API limits."""
        if ip in self._cache:
            return self._cache[ip]

        if not self.api_key or self.api_key.strip() == "":
            return {"error": "No API key configured"}

        try:
            headers = {
                "Accept": "application/json",
                "Key": self.api_key
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            resp = requests.get(self.base_url, headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()["data"]
                score = data.get("abuseConfidenceScore", 0)
                country = data.get("countryCode", "Unknown")
                usage = data.get("usageType", "Unknown")
                
                result = {
                    "score": score,
                    "country": country,
                    "usage": usage,
                    "is_malicious": score > 50
                }
                self._cache[ip] = result
                return result
            else:
                logger.error(f"AbuseIPDB error {resp.status_code}: {resp.text}")
                return {"error": f"API Error {resp.status_code}"}
        except Exception as e:
            logger.error(f"Threat Intel lookup failed for {ip}: {e}")
            return {"error": str(e)}
