"""
LLM-based verdict layer for MailTrace AI.

Uses Groq's API (llama-3.3-70b-versatile) to produce a final investigative
verdict that synthesizes the email body text with the existing structured
analysis (headers, SPF/DKIM/DMARC, relay chain, geolocation, ML classifier).

The LLM is the *primary* verdict source; the ML classifier's output is
passed as supporting evidence for the LLM to reason against.

Configuration
-------------
Set GROQ_API_KEY in the environment (or in a .env file loaded by the app).
Never hardcode the key here.
"""
from dotenv import load_dotenv
import json
import logging
import os
import re
import io
from email import policy
from email.parser import BytesParser

import requests

load_dotenv()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-120b"
REQUEST_TIMEOUT_SECONDS = 10

SYSTEM_PROMPT = (
    "You are a cybersecurity forensic analyst embedded in MailTrace AI, an "
    "email threat investigation platform. You will receive: (1) the raw email "
    "body text, and (2) structured analysis already computed by the platform "
    "— headers, SPF/DKIM/DMARC authentication results, relay chain, "
    "geolocation with IP-masking notes, and a trained ML classifier's phishing "
    "probability score.\n\n"
    "Your job is to produce the FINAL investigative verdict, synthesizing ALL "
    "evidence provided — not just reading the email body in isolation. Analyze "
    "the body for social engineering, urgency language, credential or payment "
    "requests, impersonation, and Business Email Compromise (BEC) patterns. "
    "Then weigh that against the header/auth/ML evidence given to you.\n\n"
    "Explicitly state whether your reading agrees or disagrees with the ML "
    "classifier's verdict, and why. Do not treat header authentication "
    "failures (SPF/DKIM/DMARC) as proof of phishing on their own — legitimate "
    "senders sometimes have auth misconfigurations (e.g. DKIM key rotation "
    "causing permerror) unrelated to fraud. Do not treat 'hosting'/'proxy' "
    "flags on a well-known provider's IP (e.g. Google, Microsoft) as "
    "suspicious by themselves — check the masking note for context.\n\n"
    "Respond ONLY with valid JSON in this exact shape, no preamble, no markdown "
    "fences:\n"
    "{\n"
    '  "llm_verdict": "phishing" | "suspicious" | "legitimate",\n'
    '  "llm_confidence": <integer 0-100>,\n'
    '  "reasoning_summary": "<2-3 sentence plain-language explanation>",\n'
    '  "evidence": ["<specific phrase or pattern from the body>", ...] or ["no significant indicators found"],\n'
    '  "ml_agreement": "agree" | "disagree" | "partial",\n'
    '  "agreement_explanation": "<why the LLM verdict matches or diverges from the ML classifier score, citing specifics>",\n'
    '  "final_recommended_risk_level": "low" | "medium" | "high" | "critical"\n'
    "}"
)


# ---------------------------------------------------------------------------
# Body extraction (mirrors the logic in phishing_classifier.py)
# ---------------------------------------------------------------------------

def _extract_body_from_bytes(raw_bytes: bytes) -> str:
    """
    Extract plain-text body from raw .eml bytes.
    Prefers text/plain parts; falls back to HTML with tags stripped.
    Returns an empty string if nothing is found.
    """
    try:
        msg = BytesParser(policy=policy.default).parse(io.BytesIO(raw_bytes))
    except Exception as exc:
        logger.warning("Could not parse email for body extraction: %s", exc)
        return ""

    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ct = part.get_content_type()
            try:
                if ct == "text/plain":
                    plain_parts.append(part.get_content())
                elif ct == "text/html":
                    html_parts.append(part.get_content())
            except Exception:
                pass
    else:
        ct = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if ct == "text/plain":
            plain_parts.append(content)
        elif ct == "text/html":
            html_parts.append(content)

    if plain_parts:
        return "\n".join(plain_parts).strip()

    # Strip HTML tags for a readable plain-text fallback
    return "\n".join(
        re.sub(r"<[^>]+>", " ", h) for h in html_parts
    ).strip()


# ---------------------------------------------------------------------------
# Fallback builder
# ---------------------------------------------------------------------------

def _fallback(existing_analysis: dict, error_note: str | None = None) -> dict:
    """Return the safe fallback dict when the LLM call cannot succeed."""
    try:
        ml_risk = existing_analysis["phishing_analysis"]["risk_level"]
    except (KeyError, TypeError):
        ml_risk = "unknown"

    result = {
        "llm_verdict": None,
        "llm_confidence": None,
        "reasoning_summary": (
            "LLM analysis unavailable — falling back to ML classifier result."
        ),
        "evidence": [],
        "ml_agreement": "unavailable",
        "agreement_explanation": None,
        "final_recommended_risk_level": ml_risk,
        "llm_error": True,
    }
    if error_note:
        logger.warning("LLM verdict fallback triggered: %s", error_note)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_llm_verdict(email_body: str, existing_analysis: dict) -> dict:
    """
    Call Groq's chat-completions API to produce the final investigative verdict.

    Parameters
    ----------
    email_body       : plain-text email body (may be empty string)
    existing_analysis: the full response dict already built by the endpoint
                       (headers, auth, relay_chain, geolocation, phishing_analysis …)

    Returns
    -------
    dict with keys:
        llm_verdict                  — "phishing" | "suspicious" | "legitimate" | null
        llm_confidence               — int 0-100 | null
        reasoning_summary            — str
        evidence                     — list[str]
        ml_agreement                 — "agree" | "disagree" | "partial" | "unavailable"
        agreement_explanation        — str | null
        final_recommended_risk_level — "low" | "medium" | "high" | "critical"
        llm_error                    — bool (only present when True)
    """
    api_key = os.environ.get("GROQ_API_KEY", "").strip()

    if not api_key:
        return _fallback(
            existing_analysis,
            "GROQ_API_KEY not set"
        )

    logger.info(
        "Groq API key loaded: %s",
        bool(api_key)
    )
    if not api_key:
        return _fallback(existing_analysis, "GROQ_API_KEY not set")

    # Build the user message
    body_section = email_body if email_body else "(no body text extracted)"
    try:
        analysis_json = json.dumps(existing_analysis, default=str, indent=2)
    except Exception as exc:
        return _fallback(existing_analysis, f"Could not serialise existing_analysis: {exc}")

    user_message = (
        "=== EMAIL BODY ===\n"
        f"{body_section}\n\n"
        "=== STRUCTURED ANALYSIS (headers, auth, relay chain, geolocation, ML classifier) ===\n"
        f"{analysis_json}"
    )

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        "temperature": 0.2,       # low temp for deterministic forensic output
        "max_tokens": 1024,
        "response_format": {"type": "json_object"},
    }

    headers = {
        "Content-Type":  "application/json",
    }

    headers = {**headers, "Authorization": "Bearer " + api_key}

    try:
        resp = requests.post(
            GROQ_API_URL,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        print("DEBUG: Groq status:", resp.status_code)
        print("DEBUG: Groq response:", resp.text)

        resp.raise_for_status()

    except requests.exceptions.Timeout:
        return _fallback(existing_analysis, "Groq API request timed out")

    except requests.exceptions.RequestException as exc:
        return _fallback(
            existing_analysis,
            f"Groq API request failed: {exc}"
        )

    # Parse the response
    try:
        raw_content = resp.json()["choices"][0]["message"]["content"]
        verdict_data = json.loads(raw_content)
    except (KeyError, IndexError, json.JSONDecodeError, TypeError) as exc:
        return _fallback(existing_analysis, f"Failed to parse Groq response: {exc}")

    # Validate required keys exist; fill missing ones defensively
    required_keys = {
        "llm_verdict", "llm_confidence", "reasoning_summary",
        "evidence", "ml_agreement", "agreement_explanation",
        "final_recommended_risk_level",
    }
    missing = required_keys - set(verdict_data.keys())
    if missing:
        logger.warning("Groq response missing keys %s — using fallback", missing)
        return _fallback(existing_analysis, f"Groq response missing keys: {missing}")

    # Ensure evidence is always a list
    if not isinstance(verdict_data.get("evidence"), list):
        verdict_data["evidence"] = []

    # Normalise llm_confidence to int if the model returned a float or string
    try:
        verdict_data["llm_confidence"] = int(verdict_data["llm_confidence"])
    except (TypeError, ValueError):
        verdict_data["llm_confidence"] = None

    return verdict_data
