# utils/geoip_lookup.py
# ─────────────────────────────────────────────────────────────────────────────
# GeoIP lookup utility.
# Strategy (in order):
#   1. If assets/GeoLite2-City.mmdb is present → use it (geoip2, fast, offline)
#   2. Fallback to ip-api.com JSON API (free, no key, online)
#   3. If both fail → return ("Unknown", "")
#
# Results are cached per-IP to avoid hammering the API.
# ─────────────────────────────────────────────────────────────────────────────

import os
import logging
import threading

logger = logging.getLogger(__name__)

_MMDB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets", "GeoLite2-City.mmdb"
)

# Thread-safe in-memory cache
_cache: dict = {}
_cache_lock  = threading.Lock()

# Private MMDB reader (None until first use)
_mmdb_reader = None
_mmdb_tried  = False


def _get_mmdb_reader():
    global _mmdb_reader, _mmdb_tried
    if _mmdb_tried:
        return _mmdb_reader
    _mmdb_tried = True
    if os.path.exists(_MMDB_PATH):
        try:
            import geoip2.database
            _mmdb_reader = geoip2.database.Reader(_MMDB_PATH)
            logger.info("GeoIP: using local GeoLite2-City.mmdb")
        except Exception as e:
            logger.debug("GeoIP: could not open mmdb — %s", e)
    return _mmdb_reader


def _lookup_mmdb(ip: str):
    reader = _get_mmdb_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        country = r.country.name or "Unknown"
        city    = r.city.name    or ""
        return country, city
    except Exception:
        return None


def _lookup_api(ip: str):
    """ip-api.com — free, no key, ~1000 req/min limit."""
    try:
        import urllib.request, json
        url = f"http://ip-api.com/json/{ip}?fields=country,city,status"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return data.get("country", "Unknown"), data.get("city", "")
    except Exception:
        pass
    return None


def get_location(ip: str) -> tuple:
    """
    Returns (country: str, city: str).
    Always returns something — ("Unknown", "") on complete failure.
    """
    if not ip or ip.startswith(("10.", "192.168.", "172.", "127.", "0.")):
        return ("Private / LAN", "")

    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    result = _lookup_mmdb(ip) or _lookup_api(ip) or ("Unknown", "")

    with _cache_lock:
        _cache[ip] = result

    return result


def format_location(ip: str) -> str:
    """Returns a short human-readable string like 'United States, New York'."""
    country, city = get_location(ip)
    if country == "Unknown":
        return ""
    return f"{country}{', ' + city if city else ''}"
