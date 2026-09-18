"""
Test the saved hybrid phishing classifier against real .eml files.

Run from backend/:
    ./venv/bin/python test_real_emails.py

Loads:
    ml/models/phishing_vectorizer.joblib
    ml/models/phishing_classifier.joblib
    ml/models/phishing_scaler.joblib        ← new (structural feature scaler)
"""

import sys
import os
import re
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.message import Message

import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

# Allow `import feature_engineering` from ml/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))
from feature_engineering import extract_features

MODEL_DIR = Path("ml/models")
EMAIL_DIR = Path("test_emails")

VECTORIZER_PATH  = MODEL_DIR / "phishing_vectorizer.joblib"
MODEL_PATH       = MODEL_DIR / "phishing_classifier.joblib"
SCALER_PATH      = MODEL_DIR / "phishing_scaler.joblib"


# ---------------------------------------------------------------------------
# .eml parsing
# ---------------------------------------------------------------------------

def extract_email_fields(eml_path: Path) -> dict:
    """
    Parse a .eml file and return the raw fields needed by both the
    TF-IDF vectorizer (text_combined) and the structural extractor.
    """
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

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

    if plain_parts:
        body = "\n".join(plain_parts)
    elif html_parts:
        # Basic strip — no bs4 available
        body = "\n".join(
            re.sub(r"<[^>]+>", " ", h) for h in html_parts
        )
    else:
        body = ""

    # Keep the raw HTML for structural analysis (img/form/a tags etc.)
    raw_body_for_struct = "\n".join(html_parts) if html_parts else body

    return {
        "subject":  subject.strip(),
        "body":     body.strip(),
        "raw_body": raw_body_for_struct.strip(),
        "sender":   sender.strip(),
        "reply_to": reply_to.strip(),
    }


def clean_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict_email(vectorizer, model, scaler, eml_path: Path) -> dict:
    fields = extract_email_fields(eml_path)

    subject  = clean_text(fields["subject"])
    body     = clean_text(fields["body"])
    raw_body = clean_text(fields["raw_body"])
    sender   = fields["sender"]
    reply_to = fields["reply_to"]

    combined_text = f"{subject} {body}".strip()

    if not combined_text:
        return {
            "subject": subject,
            "body_length": 0,
            "label": "NO TEXT",
            "confidence": 0.0,
            "phishing_probability": 0.0,
            "legitimate_probability": 0.0,
        }

    # --- TF-IDF features ---
    X_tfidf = vectorizer.transform([combined_text])

    # --- Structural features ---
    # Use raw_body for the structural extractor so HTML tag signals work
    struct_vec = extract_features(
        subject=subject,
        body=raw_body,
        sender=sender,
        reply_to=reply_to,
        urls_field=None,   # auto-count from body
    ).reshape(1, -1)       # (1, 32)

    struct_scaled = scaler.transform(struct_vec)
    X_struct = csr_matrix(struct_scaled)

    # --- Combine ---
    X = hstack([X_tfidf, X_struct])

    prediction    = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    class_probs   = dict(zip(model.classes_, probabilities))

    phishing_prob   = class_probs.get(1, 0.0)
    legitimate_prob = class_probs.get(0, 0.0)

    label      = "PHISHING"  if prediction == 1 else "LEGITIMATE"
    confidence = phishing_prob if prediction == 1 else legitimate_prob

    return {
        "subject":                subject,
        "body_length":            len(body),
        "label":                  label,
        "confidence":             confidence,
        "phishing_probability":   phishing_prob,
        "legitimate_probability": legitimate_prob,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("REAL-WORLD GENERALIZATION TEST  (hybrid model)")
    print("=" * 70)

    for path, label in [
        (VECTORIZER_PATH, "Vectorizer"),
        (MODEL_PATH,      "Classifier"),
        (SCALER_PATH,     "Scaler"),
    ]:
        if not path.exists():
            print(f"\nERROR: {label} not found: {path}")
            print("Run:  ./venv/bin/python train_phishing_classifier.py")
            return

    if not EMAIL_DIR.exists():
        print(f"\nERROR: Test directory not found: {EMAIL_DIR}")
        return

    print("\nLoading saved model artefacts...")
    vectorizer = joblib.load(VECTORIZER_PATH)
    model      = joblib.load(MODEL_PATH)
    scaler     = joblib.load(SCALER_PATH)
    print(f"  Vectorizer : {VECTORIZER_PATH}")
    print(f"  Classifier : {MODEL_PATH}")
    print(f"  Scaler     : {SCALER_PATH}")
    print(f"  Classes    : {model.classes_}")

    email_files = sorted(EMAIL_DIR.glob("*.eml"))
    if not email_files:
        print(f"\nNo .eml files found in {EMAIL_DIR}/")
        return

    print(f"\nFound {len(email_files)} .eml file(s).")
    print("-" * 70)

    results = []
    for eml_path in email_files:
        try:
            result = predict_email(vectorizer, model, scaler, eml_path)
            results.append((eml_path, result))

            icon = "🚨" if result["label"] == "PHISHING" else "✅"
            print(f"\n{icon}  {eml_path.name}")
            print(f"   Subject   : {result['subject'][:90] or '(none)'}")
            print(f"   Body chars: {result['body_length']:,}")
            print(f"   Prediction: {result['label']}")
            print(f"   Confidence: {result['confidence'] * 100:.2f}%")
            print(f"   Phishing  : {result['phishing_probability'] * 100:.2f}%"
                  f"   Legit: {result['legitimate_probability'] * 100:.2f}%")

        except Exception as e:
            print(f"\n❌  {eml_path.name}  →  Error: {e}")
            import traceback; traceback.print_exc()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    phishing_count  = sum(1 for _, r in results if r["label"] == "PHISHING")
    legitimate_count = sum(1 for _, r in results if r["label"] == "LEGITIMATE")

    for eml_path, r in results:
        print(f"{eml_path.name:50s}  {r['label']:12s}  {r['confidence']*100:6.2f}%")

    print("-" * 70)
    print(f"Total tested : {len(results)}")
    print(f"Legitimate   : {legitimate_count}")
    print(f"Phishing     : {phishing_count}")
    print("=" * 70)


if __name__ == "__main__":
    main()
