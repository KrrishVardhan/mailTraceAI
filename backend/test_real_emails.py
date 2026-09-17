"""
Test the saved phishing classifier against previously unseen .eml files.

Run from backend/:
    ./venv/bin/python test_real_emails.py

This DOES NOT train anything.
It loads:
    ml/models/phishing_vectorizer.joblib
    ml/models/phishing_classifier.joblib
"""

from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.message import Message
import re
import joblib


MODEL_DIR = Path("ml/models")
EMAIL_DIR = Path("test_emails")

VECTORIZER_PATH = MODEL_DIR / "phishing_vectorizer.joblib"
MODEL_PATH = MODEL_DIR / "phishing_classifier.joblib"


def extract_email_content(eml_path: Path):
    """Extract subject and readable text body from an .eml file."""

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = str(msg.get("Subject", ""))

    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    plain_parts.append(part.get_content())
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()

        try:
            content = msg.get_content()
        except Exception:
            content = ""

        if content_type == "text/plain":
            plain_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)

    # Prefer text/plain because it is cleaner for NLP.
    if plain_parts:
        body = "\n".join(plain_parts)
    elif html_parts:
        # Very basic HTML fallback.
        body = "\n".join(
            re.sub(r"<[^>]+>", " ", html)
            for html in html_parts
        )
    else:
        body = ""

    return subject.strip(), body.strip()


def clean_text(text: str):
    """
    Lightweight normalization.

    The saved TF-IDF vectorizer already handles lowercase/tokenization,
    so we deliberately do NOT perform aggressive preprocessing here.
    """
    text = text.replace("\x00", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def predict_email(vectorizer, model, eml_path: Path):
    subject, body = extract_email_content(eml_path)

    subject = clean_text(subject)
    body = clean_text(body)

    # Same conceptual input as the training dataset:
    # subject + body.
    combined_text = f"{subject} {body}".strip()

    if not combined_text:
        return {
            "subject": subject,
            "body_length": len(body),
            "label": "NO TEXT",
            "confidence": 0.0,
            "phishing_probability": 0.0,
        }

    X = vectorizer.transform([combined_text])

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    # Model classes are expected to be:
    # 0 = legitimate
    # 1 = phishing
    class_to_probability = dict(zip(model.classes_, probabilities))

    phishing_probability = class_to_probability.get(1, 0.0)
    legitimate_probability = class_to_probability.get(0, 0.0)

    if prediction == 1:
        label = "PHISHING"
        confidence = phishing_probability
    else:
        label = "LEGITIMATE"
        confidence = legitimate_probability

    return {
        "subject": subject,
        "body_length": len(body),
        "label": label,
        "confidence": confidence,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
    }


def main():
    print("=" * 70)
    print("REAL-WORLD GENERALIZATION TEST")
    print("=" * 70)

    if not VECTORIZER_PATH.exists():
        print(f"\nERROR: Vectorizer not found:")
        print(f"  {VECTORIZER_PATH}")
        return

    if not MODEL_PATH.exists():
        print(f"\nERROR: Model not found:")
        print(f"  {MODEL_PATH}")
        return

    if not EMAIL_DIR.exists():
        print(f"\nERROR: Test directory not found:")
        print(f"  {EMAIL_DIR}")
        print("\nCreate it with:")
        print("  mkdir -p test_emails")
        return

    print("\nLoading saved model...")
    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)

    print(f"Vectorizer: {VECTORIZER_PATH}")
    print(f"Classifier: {MODEL_PATH}")
    print(f"Classes: {model.classes_}")

    email_files = sorted(EMAIL_DIR.glob("*.eml"))

    if not email_files:
        print(f"\nNo .eml files found in {EMAIL_DIR}/")
        return

    print(f"\nFound {len(email_files)} .eml file(s).")
    print("-" * 70)

    results = []

    for eml_path in email_files:
        try:
            result = predict_email(vectorizer, model, eml_path)
            results.append((eml_path, result))

            print(f"\n📧 {eml_path.name}")
            print(f"   Subject: {result['subject'][:100] or '(none)'}")
            print(f"   Body characters: {result['body_length']:,}")
            print(f"   Prediction: {result['label']}")
            print(f"   Confidence: {result['confidence'] * 100:.2f}%")
            print(
                f"   Phishing probability: "
                f"{result['phishing_probability'] * 100:.2f}%"
            )
            print(
                f"   Legitimate probability: "
                f"{result['legitimate_probability'] * 100:.2f}%"
            )

        except Exception as e:
            print(f"\n❌ {eml_path.name}")
            print(f"   Error: {e}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    phishing_count = 0
    legitimate_count = 0

    for eml_path, result in results:
        if result["label"] == "PHISHING":
            phishing_count += 1
        elif result["label"] == "LEGITIMATE":
            legitimate_count += 1

        print(
            f"{eml_path.name:35s} "
            f"{result['label']:12s} "
            f"{result['confidence'] * 100:6.2f}%"
        )

    print("-" * 70)
    print(f"Total tested: {len(results)}")
    print(f"Predicted legitimate: {legitimate_count}")
    print(f"Predicted phishing:   {phishing_count}")
    print("=" * 70)


if __name__ == "__main__":
    main()
