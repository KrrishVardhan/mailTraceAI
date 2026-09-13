"""
Email header forensics module.

Parses raw .eml bytes to:
1. Extract and interpret SPF/DKIM/DMARC results from Authentication-Results
2. Reconstruct the Received: header relay chain (earliest hop first)
3. Extract candidate IP addresses from each hop
4. Flag simple red flags (From/Reply-To domain mismatch)

This module has no FastAPI dependency — it's plain Python, so it's easy
to unit test on its own with sample .eml files.
"""

import re
from email import message_from_bytes
from email.header import decode_header
from email.message import Message
from email.utils import parsedate_to_datetime

IP_PATTERN = re.compile(
    r"\[((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\]"
)

# Curated, non-exhaustive: many countries share a UTC offset, so this
# names a few well-known examples per offset rather than claiming an
# exhaustive or authoritative list. It's a hint, not a determination.
OFFSET_REGION_HINTS = {
    "+05:30": ["India", "Sri Lanka"],
    "+05:45": ["Nepal"],
    "+00:00": ["UK", "Portugal", "Ghana", "Iceland"],
    "-05:00": ["US Eastern", "Colombia", "Peru"],
    "-08:00": ["US Pacific"],
    "+01:00": ["Central Europe", "Nigeria"],
    "+08:00": ["China", "Singapore", "Philippines", "Western Australia"],
    "+09:00": ["Japan", "South Korea"],
    "+10:00": ["Eastern Australia"],
    "+03:00": ["East Africa", "Saudi Arabia", "Iraq"],
    "+04:00": ["UAE", "Azerbaijan"],
}

# Substrings matched against the geolocation "org"/"isp" fields (case-
# insensitive) to detect when the traced IP is a major provider's own
# infrastructure rather than an end-user/attacker's actual connection.
# Not exhaustive — extend as you encounter more in testing.
MASKING_PROVIDERS = [
    "google", "microsoft", "outlook", "yahoo", "amazon", "amazonses",
    "sendgrid", "mailgun", "mailchimp", "zoho",
]


def decode_mime_header(raw_value: str | None) -> str | None:
    """
    Decodes RFC 2047 encoded-word headers (e.g. '=?UTF-8?B?...?=') into
    plain readable text. Real-world Subject/From headers often contain
    these when they include emoji, accented characters, or non-English
    names — without this, they show up as garbled base64/quoted-printable.
    """
    if not raw_value:
        return raw_value
    parts = decode_header(raw_value)
    decoded = ""
    for text, encoding in parts:
        if isinstance(text, bytes):
            decoded += text.decode(encoding or "utf-8", errors="replace")
        else:
            decoded += text
    return decoded


def extract_sender_timezone(msg: Message) -> dict | None:
    """
    Parses the Date header's UTC offset — this reflects the sending
    device's own clock/timezone setting, which is an independent signal
    from IP-based geolocation and isn't affected by mail-provider
    infrastructure masking the sender's real IP.

    Caveat worth keeping in mind: a device's timezone setting can be
    wrong, spoofed, or simply not match the user's physical location
    (e.g. travel, a misconfigured OS) — this is a hint, not proof.
    """
    date_header = msg.get("Date")
    if not date_header:
        return None
    try:
        dt = parsedate_to_datetime(date_header)
        offset = dt.utcoffset()
        if offset is None:
            return None
    except (TypeError, ValueError):
        return None

    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    hours, minutes = divmod(abs(total_minutes), 60)
    offset_str = f"{sign}{hours:02d}:{minutes:02d}"

    return {
        "utc_offset": offset_str,
        "plausible_regions": OFFSET_REGION_HINTS.get(offset_str, []),
    }


def assess_origin_masking(geo_result: dict) -> dict:
    """
    Flags when a geolocated IP belongs to a known major mail/cloud
    provider's own infrastructure, meaning the location shown is that
    provider's datacenter/relay — not necessarily anywhere near the
    actual sender. Prevents over-reading provider infrastructure as a
    confident "this is where the attacker/sender is" result.
    """
    org_and_isp = f"{geo_result.get('org', '')} {geo_result.get('isp', '')}".lower()
    matched = next((p for p in MASKING_PROVIDERS if p in org_and_isp), None)

    if matched:
        return {
            "likely_masked": True,
            "note": (
                f"This IP belongs to {geo_result.get('org') or geo_result.get('isp')}'s "
                f"own infrastructure. The location shown is that provider's server "
                f"location, not necessarily the actual sender's location."
            ),
        }
    return {"likely_masked": False, "note": None}


def synthesize_origin_assessment(geo_results: list[dict], timezone_info: dict | None) -> dict:
    """
    Combines the IP-geolocation result with the independent timezone
    signal into one human-readable verdict, with an explicit confidence
    level — rather than leaving it to whoever's reading the JSON to
    mentally reconcile "IP says X" against "timezone says Y" themselves.

    This is intentionally conservative: it never claims high confidence
    from a single masked signal, and it's explicit when there's nothing
    useful to go on at all.
    """
    successful_geo = [g for g in geo_results if g.get("status") == "success"]
    tz_regions = (timezone_info or {}).get("plausible_regions", [])
    tz_offset = (timezone_info or {}).get("utc_offset")

    if not successful_geo:
        if tz_regions:
            return {
                "verdict": f"No usable IP geolocation. Device timezone (UTC{tz_offset}) is "
                           f"consistent with {' or '.join(tz_regions)}, but this alone is weak "
                           f"evidence — timezone settings can be wrong or unrelated to physical location.",
                "confidence": "low",
            }
        return {
            "verdict": "No usable signal for origin location — IP geolocation failed and no timezone data was available.",
            "confidence": "none",
        }

    geo = successful_geo[0]
    location = ", ".join(filter(None, [geo.get("city"), geo.get("regionName"), geo.get("country")]))
    masking = geo.get("masking", {})

    if masking.get("likely_masked"):
        if tz_regions:
            return {
                "verdict": f"IP traces to {location}, but this is {geo.get('org') or geo.get('isp')}'s "
                           f"own infrastructure, not the sender's real location. Device timezone "
                           f"(UTC{tz_offset}) independently suggests {' or '.join(tz_regions)} — "
                           f"treat this as the more likely region for the actual sender.",
                "confidence": "medium",
            }
        return {
            "verdict": f"IP traces to {location}, but this is {geo.get('org') or geo.get('isp')}'s "
                       f"own infrastructure — the sender's real location cannot be determined from "
                       f"headers alone in this case.",
            "confidence": "low",
        }

    # Not masked — a non-major-provider IP is a much stronger origin signal
    # (see the README's phishing-sample case for why this holds in practice).
    hosting_note = " (hosting/datacenter IP, not a residential connection)" if geo.get("hosting") else ""
    return {
        "verdict": f"IP traces to {location}{hosting_note} — not a known major-provider relay, "
                   f"so this is a reasonably strong origin signal for the sending infrastructure.",
        "confidence": "high" if not geo.get("hosting") else "medium",
    }


def load_eml_bytes(raw_bytes: bytes) -> Message:
    return message_from_bytes(raw_bytes)


def parse_authentication_results(msg: Message) -> dict:
    """
    Parses the Authentication-Results header, e.g.:
    'mx.google.com; dkim=fail ...; spf=softfail ...; dmarc=fail ...'
    Returns {"spf": "softfail", "dkim": "fail", "dmarc": "fail"}
    """
    header = msg.get("Authentication-Results", "")
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", header, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "not_found"
    return results


def extract_received_chain(msg: Message) -> list[dict]:
    """
    Returns Received headers in chronological order (earliest hop first).
    get_all() returns them most-recent-first (each server prepends its own
    line), so we reverse to get earliest-to-latest — i.e. sender toward
    delivery.
    """
    received_headers = msg.get_all("Received", [])
    chain = []
    for i, raw in enumerate(reversed(received_headers)):
        chain.append({
            "hop": i + 1,
            "raw": " ".join(raw.split()),
            "ip_candidates": sorted(set(IP_PATTERN.findall(raw))),
        })
    return chain


def assess_auth_risk(auth: dict) -> str:
    """Simple heuristic scoring — a real system would weigh these differently
    and factor in sender reputation, not just pass/fail counts."""
    fails = sum(1 for v in auth.values() if v in ("fail", "softfail"))
    if fails >= 2:
        return "high"
    elif fails == 1:
        return "medium"
    return "low"


def find_red_flags(msg: Message) -> list[str]:
    flags = []
    from_domain = msg.get("From", "").split("@")[-1].rstrip(">").strip()
    reply_domain = msg.get("Reply-To", "").split("@")[-1].rstrip(">").strip()
    if reply_domain and from_domain and reply_domain != from_domain:
        flags.append(
            f"From domain ({from_domain}) differs from Reply-To domain "
            f"({reply_domain}) — replies get redirected elsewhere, a "
            f"common BEC/phishing pattern."
        )
    return flags


def analyze_eml(raw_bytes: bytes) -> dict:
    """Main entry point: takes raw .eml bytes, returns a full structured
    analysis dict — this is what the FastAPI route will call and return
    directly as JSON."""
    msg = load_eml_bytes(raw_bytes)

    auth = parse_authentication_results(msg)
    chain = extract_received_chain(msg)

    # The first hop with IP candidates, after any purely-internal
    # (no-IP) hops, is our best naive guess at "probable origin" —
    # see the trust-boundary caveat discussed with the user.
    probable_origin_ips = next(
        (hop["ip_candidates"] for hop in chain if hop["ip_candidates"]),
        [],
    )

    return {
        "headers": {
            "from": decode_mime_header(msg.get("From")),
            "reply_to": msg.get("Reply-To"),
            "return_path": msg.get("Return-Path"),
            "subject": decode_mime_header(msg.get("Subject")),
            "message_id": msg.get("Message-ID"),
        },
        "authentication": {
            **auth,
            "risk_level": assess_auth_risk(auth),
        },
        "relay_chain": chain,
        "probable_origin_ips": probable_origin_ips,
        "red_flags": find_red_flags(msg),
        "sender_timezone": extract_sender_timezone(msg),
    }
