"""
Trains a phishing-vs-legitimate text classifier on the Kaggle merged
phishing email dataset (Enron/Ling/CEAS/Nazario/Nigerian Fraud/SpamAssassin).

Run from backend/:
    ./venv/bin/python ml/train_phishing_classifier.py

Outputs two files into ml/models/:
    phishing_vectorizer.joblib  — the fitted TF-IDF vectorizer
    phishing_classifier.joblib  — the fitted Logistic Regression model
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

DATA_PATH = "ml/data/phishing_email.csv"
MODEL_DIR = "ml/models"


def load_data():
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df)} rows. Label distribution:\n{df['label'].value_counts()}\n")
    return df


def train_and_evaluate(X_train, X_test, y_train, y_test, vectorizer):
    """
    Trains both a Logistic Regression and a Random Forest on the same
    TF-IDF features, so we can compare them directly rather than
    committing to one algorithm without evidence it's the better choice.
    """
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    results = {}

    print("=" * 60)
    print("LOGISTIC REGRESSION")
    print("=" * 60)
    log_reg = LogisticRegression(max_iter=1000, class_weight="balanced")
    log_reg.fit(X_train_vec, y_train)
    y_pred = log_reg.predict(X_test_vec)
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print()
    results["logistic_regression"] = log_reg

    print("=" * 60)
    print("RANDOM FOREST")
    print("=" * 60)
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=42)
    rf.fit(X_train_vec, y_train)
    y_pred_rf = rf.predict(X_test_vec)
    print(classification_report(y_test, y_pred_rf, target_names=["legitimate", "phishing"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred_rf))
    print()
    results["random_forest"] = rf

    return results, X_train_vec


def show_top_features(vectorizer, model, n=20):
    """
    Prints the words/phrases the Logistic Regression weighted most
    heavily toward each class. This is the interpretability payoff of
    using a linear model instead of a black box — genuinely useful for
    a report, since you can show *why* the model flags something.
    """
    feature_names = vectorizer.get_feature_names_out()
    coefs = model.coef_[0]

    top_phishing_idx = coefs.argsort()[-n:][::-1]
    top_legit_idx = coefs.argsort()[:n]

    print("=" * 60)
    print(f"TOP {n} WORDS/PHRASES PUSHING TOWARD 'PHISHING'")
    print("=" * 60)
    for idx in top_phishing_idx:
        print(f"  {feature_names[idx]:30s}  weight={coefs[idx]:.3f}")

    print()
    print("=" * 60)
    print(f"TOP {n} WORDS/PHRASES PUSHING TOWARD 'LEGITIMATE'")
    print("=" * 60)
    for idx in top_legit_idx:
        print(f"  {feature_names[idx]:30s}  weight={coefs[idx]:.3f}")


def main():
    df = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        df["text_combined"], df["label"],
        test_size=0.2, random_state=42, stratify=df["label"]
    )
    print(f"Train size: {len(X_train)}, Test size: {len(X_test)}\n")

    # ngram_range=(1, 2) captures two-word phrases like "click here" or
    # "verify account", not just single words — meaningfully improves
    # phishing detection since a lot of the signal is in short phrases.
    # max_features caps vocabulary size to keep this fast and avoid
    # overfitting to extremely rare words.
    vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        min_df=5,       # ignore words appearing in fewer than 5 emails
        max_df=0.8,     # ignore words appearing in more than 80% of emails (too common to be useful)
    )

    models, _ = train_and_evaluate(X_train, X_test, y_train, y_test, vectorizer)

    show_top_features(vectorizer, models["logistic_regression"])

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vectorizer, f"{MODEL_DIR}/phishing_vectorizer.joblib")
    joblib.dump(models["logistic_regression"], f"{MODEL_DIR}/phishing_classifier.joblib")
    print(f"\nSaved vectorizer and Logistic Regression model to {MODEL_DIR}/")


if __name__ == "__main__":
    main()
