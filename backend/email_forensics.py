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

IP_PATTERN = re.compile(
    r"\[((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\]"
)


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
    }
