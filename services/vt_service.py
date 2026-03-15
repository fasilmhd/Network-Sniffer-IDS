import requests
import logging

logger = logging.getLogger("VirusTotalService")


class VirusTotalService:
    """
    Wrapper around the VirusTotal HTTP API v3 for file reputation lookups.
    Requires a valid API key.
    """

    BASE_URL = "https://www.virustotal.com/gui/home/upload"

    def __init__(self, api_key: str):
        self.api_key = api_key.strip()
        if not self.api_key:
            logger.warning("VirusTotalService initialized without API key.")
    def __init__(self, api_key: str):
        """
        Initialize the VirusTotalService with an API key.

        This constructor sets up the VirusTotalService instance with the provided API key.
        It strips any leading or trailing whitespace from the key and logs a warning if
        the key is empty after stripping.

        Args:
            api_key (str): The VirusTotal API key to be used for authentication.

        Returns:
            None

        Note:
            If the api_key is empty after stripping, a warning will be logged.
        """
        self.api_key = api_key.strip()
        if not self.api_key:
            logger.warning("VirusTotalService initialized without API key.")
    def lookup(self, md5: str) -> tuple[bool, dict]:
        """
        Query VirusTotal for the given file MD5.
        Returns (malicious_flag, stats_dict).
        - malicious_flag: True if VT engines flagged the file.
        - stats_dict: last_analysis_stats from VT API.
        """
        headers = {"x-apikey": self.api_key}
        url = self.BASE_URL + md5
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) > 0
            return malicious, stats
        except requests.HTTPError as he:
            logger.error("VT HTTP error for %s: %s", md5, he)
        except Exception as e:
            logger.error("VT lookup failed for %s: %s", md5, e)
        return False, {}