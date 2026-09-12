"""
IP geolocation module using ip-api.com's free JSON API.

Important limitations, worth keeping in mind when interpreting results:
- This gives an ISP/hosting-provider location, not a precise physical
  address — accuracy varies from city-level (residential ISPs) to
  "wherever the datacenter is" (cloud/ESP infrastructure like SendGrid,
  AWS, etc.) which may be nowhere near the actual sender.
- Free tier: 45 requests/minute, no HTTPS (HTTP only), no API key needed.
- Private/reserved IPs (10.x, 192.168.x, 127.x, etc.) can't be geolocated
  at all — ip-api.com returns a "fail" status for these, which we handle.
"""

import requests

BATCH_URL = "http://ip-api.com/batch"

FIELDS = (
    "status,message,country,countryCode,region,regionName,"
    "city,lat,lon,isp,org,as,proxy,hosting,query"
)


def geolocate_ips(ip_list: list[str]) -> list[dict]:
    """
    Takes a list of IPv4 addresses, returns a list of geolocation results
    in the same order. ip-api.com's batch endpoint accepts up to 100 IPs
    per request and returns results in the order submitted.

    Each result dict has a "status" of "success" or "fail" — always check
    this before trusting the other fields, since private/reserved IPs
    and malformed input will fail cleanly rather than raising.
    """
    if not ip_list:
        return []

    # ip-api's batch endpoint takes a JSON array of objects; we attach
    # the same `fields` param to each so every result includes proxy/
    # hosting flags, which the default response omits.
    payload = [{"query": ip, "fields": FIELDS} for ip in ip_list]

    try:
        response = requests.post(BATCH_URL, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        # Network failure, timeout, or ip-api.com being unreachable —
        # return a fail entry per IP rather than letting this crash
        # the whole /analyze-email response.
        return [
            {"query": ip, "status": "fail", "message": f"lookup error: {e}"}
            for ip in ip_list
        ]


def summarize_geolocation(geo_result: dict) -> str:
    """Human-readable one-liner for a single successful geolocation result."""
    if geo_result.get("status") != "success":
        return f"Could not geolocate {geo_result.get('query', 'IP')}: {geo_result.get('message', 'unknown error')}"

    parts = [geo_result.get("city"), geo_result.get("regionName"), geo_result.get("country")]
    location = ", ".join(p for p in parts if p)
    org = geo_result.get("org") or geo_result.get("isp") or "unknown org"

    flags = []
    if geo_result.get("proxy"):
        flags.append("proxy/VPN")
    if geo_result.get("hosting"):
        flags.append("hosting/datacenter")
    flag_str = f" [{', '.join(flags)}]" if flags else ""

    return f"{geo_result['query']} → {location} ({org}){flag_str}"
