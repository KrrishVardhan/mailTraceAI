"""
Trains a hybrid phishing classifier:
    TF-IDF (10k text features)  +  32 structural/behavioural features
    ──────────────────────────────────────────────────────────────────
    combined with scipy.sparse.hstack → Logistic Regression

Loading is done from the *raw* source CSVs rather than the merged
phishing_email.csv so we can access per-field columns (sender, subject,
body, urls) needed for structural features.

Run from backend/:
    ./venv/bin/python train_phishing_classifier.py

Outputs to ml/models/:
    phishing_vectorizer.joblib   — fitted TF-IDF vectorizer
    phishing_classifier.joblib   — fitted Logistic Regression (hybrid)
    phishing_scaler.joblib       — StandardScaler for structural features
"""

import sys
import os
import warnings
warnings.filterwarnings("ignore")

# Allow `import feature_engineering` from ml/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))

import numpy as np
import pandas as pd
import joblib
from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

from feature_engineering import extract_features_batch, FEATURE_NAMES

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR = "ml/data"
MODEL_DIR = "ml/models"

SOURCE_CSVS = {
    # name: (path, has_sender, has_urls)
    "CEAS":      ("CEAS_08.csv",        True,  True),
    "Nazario":   ("Nazario.csv",        True,  True),
    "Enron":     ("Enron.csv",          False, False),
    "Ling":      ("Ling.csv",           False, False),
    "SpamAssassin": ("SpamAssasin.csv", False, False),
    "Nigerian":  ("Nigerian_Fraud.csv", False, False),
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_all_sources() -> pd.DataFrame:
    """
    Load every source CSV and normalise to a common schema:
        subject, body, sender, reply_to, urls, label, text_combined

    Returns a single concatenated DataFrame.
    """
    frames = []

    for name, (filename, has_sender, has_urls) in SOURCE_CSVS.items():
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            print(f"  [WARN] {filename} not found — skipping {name}")
            continue

        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip().str.lower()

        # Normalise column names we care about
        if "body" not in df.columns:
            # Some files might use 'message' or 'content'
            for alt in ("message", "content", "text"):
                if alt in df.columns:
                    df = df.rename(columns={alt: "body"})
                    break

        # Ensure all expected columns exist
        for col in ("subject", "body", "sender", "reply_to", "urls"):
            if col not in df.columns:
                df[col] = ""

        df["subject"] = df["subject"].fillna("").astype(str)
        df["body"]    = df["body"].fillna("").astype(str)
        df["sender"]  = df["sender"].fillna("").astype(str) if has_sender else ""
        df["urls"]    = df["urls"].fillna(0) if has_urls else 0
        df["reply_to"] = df.get("reply_to", pd.Series([""] * len(df))).fillna("").astype(str)

        # Build text_combined the same way the old pipeline did
        df["text_combined"] = (df["subject"] + " " + df["body"]).str.strip()

        df = df[["subject", "body", "sender", "reply_to", "urls", "text_combined", "label"]]
        df = df.dropna(subset=["label"])
        df["label"] = df["label"].astype(int)

        frames.append(df)
        print(f"  Loaded {name}: {len(df):,} rows  "
              f"(phishing={df['label'].sum():,}, legit={(df['label']==0).sum():,})")

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  Total: {len(combined):,} rows")
    print(f"  Label distribution:\n{combined['label'].value_counts()}\n")
    return combined


# ---------------------------------------------------------------------------
# Feature matrix construction
# ---------------------------------------------------------------------------

def build_hybrid_matrix(df: pd.DataFrame, vectorizer: TfidfVectorizer,
                         scaler: StandardScaler, fit: bool = True):
    """
    Build the combined feature matrix by horizontally stacking:
        [TF-IDF sparse matrix]  |  [scaled structural dense matrix]

    If fit=True  → fit_transform the vectorizer and scaler (training).
    If fit=False → transform only (inference / test set).
    """
    # --- TF-IDF part ---
    if fit:
        X_tfidf = vectorizer.fit_transform(df["text_combined"])
    else:
        X_tfidf = vectorizer.transform(df["text_combined"])

    # --- Structural features ---
    print("  Extracting structural features...", flush=True)
    struct = extract_features_batch(df)          # (n, 32) float32 ndarray

    if fit:
        struct_scaled = scaler.fit_transform(struct)
    else:
        struct_scaled = scaler.transform(struct)

    # Convert dense to sparse and hstack
    X_struct = csr_matrix(struct_scaled)
    X_hybrid = hstack([X_tfidf, X_struct])

    return X_hybrid


# ---------------------------------------------------------------------------
# Training & evaluation
# ---------------------------------------------------------------------------

def train_and_evaluate(df_train, df_test, vectorizer, scaler):
    print("Building hybrid feature matrices...")
    X_train = build_hybrid_matrix(df_train, vectorizer, scaler, fit=True)
    X_test  = build_hybrid_matrix(df_test,  vectorizer, scaler, fit=False)

    y_train = df_train["label"].values
    y_test  = df_test["label"].values

    print(f"  Train matrix: {X_train.shape}  (TF-IDF + 32 structural)")
    print(f"  Test  matrix: {X_test.shape}\n")

    print("=" * 60)
    print("LOGISTIC REGRESSION  (TF-IDF + structural hybrid)")
    print("=" * 60)
    model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        class_weight="balanced",
        solver="lbfgs",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    print(classification_report(y_test, y_pred,
                                  target_names=["legitimate", "phishing"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    return model


def show_top_tfidf_features(vectorizer, model, n=15):
    """Show most-weighted TF-IDF tokens and structural feature weights."""
    tfidf_names = list(vectorizer.get_feature_names_out())
    all_names = tfidf_names + FEATURE_NAMES
    coefs = model.coef_[0]

    top_phishing = coefs.argsort()[-n:][::-1]
    top_legit    = coefs.argsort()[:n]

    print("\n" + "=" * 60)
    print(f"TOP {n} FEATURES → PHISHING")
    print("=" * 60)
    for idx in top_phishing:
        name = all_names[idx] if idx < len(all_names) else f"feat_{idx}"
        print(f"  {name:35s}  weight={coefs[idx]:.3f}")

    print("\n" + "=" * 60)
    print(f"TOP {n} FEATURES → LEGITIMATE")
    print("=" * 60)
    for idx in top_legit:
        name = all_names[idx] if idx < len(all_names) else f"feat_{idx}"
        print(f"  {name:35s}  weight={coefs[idx]:.3f}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("HYBRID PHISHING CLASSIFIER — TRAINING")
    print("=" * 60)

    print("\nLoading source CSVs...")
    df = load_all_sources()

    df_train, df_test = train_test_split(
        df, test_size=0.2, random_state=42, stratify=df["label"]
    )
    print(f"Train: {len(df_train):,}   Test: {len(df_test):,}\n")

    vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        min_df=5,
        max_df=0.8,
        sublinear_tf=True,   # log(tf+1) — helps with long email bodies
    )
    scaler = StandardScaler(with_mean=False)  # sparse-safe (mean=False)

    model = train_and_evaluate(df_train, df_test, vectorizer, scaler)

    show_top_tfidf_features(vectorizer, model)

    # Save artefacts
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vectorizer, f"{MODEL_DIR}/phishing_vectorizer.joblib")
    joblib.dump(model,      f"{MODEL_DIR}/phishing_classifier.joblib")
    joblib.dump(scaler,     f"{MODEL_DIR}/phishing_scaler.joblib")

    print(f"\nSaved to {MODEL_DIR}/:")
    print("  phishing_vectorizer.joblib")
    print("  phishing_classifier.joblib")
    print("  phishing_scaler.joblib")


if __name__ == "__main__":
    main()
