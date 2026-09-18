"""
Phishing classifier inference module for the FastAPI backend.

Loads the trained hybrid model (TF-IDF + structural features) once at
import time and exposes a single function: classify_email().

Decision thresholds
-------------------
Rather than a binary 50% cutoff, we use a three-band system:

    phishing_probability ≥ 0.70  →  verdict = "PHISHING"    (red)
    phishing_probability ≤ 0.30  →  verdict = "LEGITIMATE"  (green)
    everything in between        →  verdict = "SUSPICIOUS"   (yellow)

This avoids confidently-wrong labels when the model is genuinely
uncertain (e.g. short transactional emails that share vocabulary with
phishing but lack hard structural signals).
"""

import os
import sys
import re
import logging
from pathlib import Path
from email import policy
from email.parser import BytesParser

import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

# Allow importing feature_engineering from ml/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))
from feature_engineering import extract_features

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model paths
# ---------------------------------------------------------------------------
_MODEL_DIR       = Path(__file__).parent / "ml" / "models"
_VECTORIZER_PATH = _MODEL_DIR / "phishing_vectorizer.joblib"
_MODEL_PATH      = _MODEL_DIR / "phishing_classifier.joblib"
_SCALER_PATH     = _MODEL_DIR / "phishing_scaler.joblib"

# ---------------------------------------------------------------------------
# Decision thresholds
# ---------------------------------------------------------------------------
PHISHING_THRESHOLD   = 0.70   # ≥ this → PHISHING  (red)
LEGITIMATE_THRESHOLD = 0.30   # ≤ this → LEGITIMATE (green)
                               # between → SUSPICIOUS (yellow)

# ---------------------------------------------------------------------------
# Lazy singleton loader
# ---------------------------------------------------------------------------
_vectorizer = None
_model      = None
_scaler     = None
_load_error = None


def _load_models():
    global _vectorizer, _model, _scaler, _load_error

    if _vectorizer is not None:
        return True   # already loaded

    missing = [p for p in [_VECTORIZER_PATH, _MODEL_PATH, _SCALER_PATH]
               if not p.exists()]
    if missing:
        _load_error = f"Model files not found: {[str(p) for p in missing]}"
        logger.warning(_load_error)
        return False

    try:
        _vectorizer = joblib.load(_VECTORIZER_PATH)
        _model      = joblib.load(_MODEL_PATH)
        _scaler     = joblib.load(_SCALER_PATH)
        logger.info("Phishing classifier loaded successfully.")
        return True
    except Exception as exc:
        _load_error = str(exc)
        logger.exception("Failed to load phishing classifier: %s", exc)
        return False


# Attempt load at import time so the first request isn't slow.
_load_models()


# ---------------------------------------------------------------------------
# Text helpers (same logic as test_real_emails.py)
# ---------------------------------------------------------------------------

def _extract_fields_from_bytes(raw_bytes: bytes) -> dict:
    """Parse raw .eml bytes into the fields the classifier needs."""
    msg = BytesParser(policy=policy.default).parse(
        __import__("io").BytesIO(raw_bytes)
    )

    subject  = str(msg.get("Subject", "") or "")
    sender   = str(msg.get("From", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")

    plain_parts, html_parts = [], []

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

    body = "\n".join(plain_parts) if plain_parts else (
        "\n".join(re.sub(r"<[^>]+>", " ", h) for h in html_parts)
    )
    raw_body = "\n".join(html_parts) if html_parts else body

    return {
        "subject":  subject.strip(),
        "body":     body.strip(),
        "raw_body": raw_body.strip(),
        "sender":   sender.strip(),
        "reply_to": reply_to.strip(),
    }


def _clean(text: str) -> str:
    return re.sub(r"\s+", text.replace("\x00", " "), " ").strip()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_email(raw_bytes: bytes) -> dict:
    """
    Run the hybrid phishing classifier against a raw .eml file.

    Parameters
    ----------
    raw_bytes : raw bytes of the uploaded .eml file

    Returns
    -------
    dict with keys:
        verdict              — "PHISHING" | "SUSPICIOUS" | "LEGITIMATE" | "UNAVAILABLE"
        phishing_probability — float 0–1
        legitimate_probability — float 0–1
        confidence           — probability of the chosen verdict class
        risk_level           — "high" | "medium" | "low"
        threshold_used       — dict explaining the thresholds applied
        error                — str or None (if model unavailable)
    """
    if not _load_models():
        return {
            "verdict":                "UNAVAILABLE",
            "phishing_probability":   None,
            "legitimate_probability": None,
            "confidence":             None,
            "risk_level":             "unknown",
            "threshold_used":         None,
            "error":                  _load_error,
        }

    try:
        fields = _extract_fields_from_bytes(raw_bytes)
        subject  = _clean(fields["subject"])
        body     = _clean(fields["body"])
        raw_body = _clean(fields["raw_body"])

        combined_text = f"{subject} {body}".strip()

        if not combined_text:
            return {
                "verdict":                "UNAVAILABLE",
                "phishing_probability":   None,
                "legitimate_probability": None,
                "confidence":             None,
                "risk_level":             "unknown",
                "threshold_used":         None,
                "error":                  "No text content found in email.",
            }

        # --- TF-IDF features ---
        X_tfidf = _vectorizer.transform([combined_text])

        # --- Structural features ---
        struct_vec = extract_features(
            subject=subject,
            body=raw_body,
            sender=fields["sender"],
            reply_to=fields["reply_to"],
            urls_field=None,
        ).reshape(1, -1)

        struct_scaled = _scaler.transform(struct_vec)
        X = hstack([X_tfidf, csr_matrix(struct_scaled)])

        # --- Predict ---
        probabilities = _model.predict_proba(X)[0]
        class_probs   = dict(zip(_model.classes_, probabilities))

        phishing_prob   = float(class_probs.get(1, 0.0))
        legitimate_prob = float(class_probs.get(0, 0.0))

        # Three-band decision
        if phishing_prob >= PHISHING_THRESHOLD:
            verdict    = "PHISHING"
            risk_level = "high"
            confidence = phishing_prob
        elif phishing_prob <= LEGITIMATE_THRESHOLD:
            verdict    = "LEGITIMATE"
            risk_level = "low"
            confidence = legitimate_prob
        else:
            verdict    = "SUSPICIOUS"
            risk_level = "medium"
            confidence = phishing_prob   # how phishy it looks

        return {
            "verdict":                verdict,
            "phishing_probability":   round(phishing_prob, 4),
            "legitimate_probability": round(legitimate_prob, 4),
            "confidence":             round(confidence, 4),
            "risk_level":             risk_level,
            "threshold_used": {
                "phishing_above":    PHISHING_THRESHOLD,
                "legitimate_below":  LEGITIMATE_THRESHOLD,
            },
            "error": None,
        }

    except Exception as exc:
        logger.exception("Classifier error: %s", exc)
        return {
            "verdict":                "UNAVAILABLE",
            "phishing_probability":   None,
            "legitimate_probability": None,
            "confidence":             None,
            "risk_level":             "unknown",
            "threshold_used":         None,
            "error":                  str(exc),
        }
