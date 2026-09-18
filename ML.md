# ML Layer — How It Works

This document explains the entire machine learning and API layer of mailTraceAI from scratch. No prior ML knowledge assumed. Every file path is exact.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [The Training Data](#2-the-training-data)
3. [How the Model Learns — Feature Engineering](#3-how-the-model-learns--feature-engineering)
   - [Part A: TF-IDF (text features)](#part-a-tf-idf-text-features)
   - [Part B: Structural Features](#part-b-structural-features)
   - [The Hybrid Matrix](#the-hybrid-matrix)
4. [The Classifier — Logistic Regression](#4-the-classifier--logistic-regression)
5. [Training the Model](#5-training-the-model)
6. [Saved Model Files](#6-saved-model-files)
7. [The Decision Threshold System](#7-the-decision-threshold-system)
8. [How the API Uses the Model](#8-how-the-api-uses-the-model)
9. [Complete Request Flow](#9-complete-request-flow)
10. [How to Retrain](#10-how-to-retrain)
11. [Limitations and Known Gaps](#11-limitations-and-known-gaps)

---

## 1. The Big Picture

When you upload a `.eml` file to mailTraceAI, three things happen in parallel:

```
.eml file uploaded
       │
       ├──► Header Forensics  → SPF/DKIM/DMARC, relay chain, origin IPs
       │
       ├──► Geolocation       → IP → city/country/ISP
       │
       └──► ML Classifier     → Is this phishing, suspicious, or legitimate?
```

This document covers only the **ML Classifier** branch. The result it produces is added to the API response under the key `phishing_analysis`.

---

## 2. The Training Data

**File:** `backend/train_phishing_classifier.py`  
**Data directory:** `backend/ml/data/`

The model was trained on **82,486 labelled emails** from 6 public datasets:

| Dataset | File | Emails | Has Sender? | Has URL count? |
|---|---|---|---|---|
| CEAS 2008 spam corpus | `CEAS_08.csv` | 39,154 | ✅ | ✅ |
| Nazario phishing corpus | `Nazario.csv` | 1,565 | ✅ | ✅ |
| Enron email corpus (legit) | `Enron.csv` | 29,767 | ❌ | ❌ |
| Ling spam corpus | `Ling.csv` | 2,859 | ❌ | ❌ |
| SpamAssassin corpus | `SpamAssasin.csv` | 5,809 | ❌ | ❌ |
| Nigerian Fraud emails | `Nigerian_Fraud.csv` | 3,332 | ❌ | ❌ |

**Labels:** Every email is labelled either `1` (phishing/spam) or `0` (legitimate). The dataset is roughly balanced: 42,891 phishing vs 39,595 legitimate.

**What columns each CSV has:**
- CEAS and Nazario: `sender`, `receiver`, `date`, `subject`, `body`, `urls`, `label`
- Enron, Ling, SpamAssassin, Nigerian: `subject`, `body`, `label`

When training, the script loads all 6 files, normalises them to a common schema (filling in empty strings for missing columns), and concatenates them into one big DataFrame.

---

## 3. How the Model Learns — Feature Engineering

**File:** `backend/ml/feature_engineering.py`

Before the model can classify anything, each email must be converted into numbers — because models only understand numbers, not words or sentences. This conversion process is called **feature extraction**. We use two completely different approaches and combine them.

### Part A: TF-IDF (text features)

**What it is:** TF-IDF stands for *Term Frequency–Inverse Document Frequency*. It converts the full text of an email (subject + body combined) into a vector of 10,000 numbers, where each number represents how important a particular word or 2-word phrase is in that email compared to all emails in the training set.

**How it works in plain English:**
- The word "your" appearing many times in an email is not very meaningful because it appears in almost every email — TF-IDF gives it a low score.
- The phrase "click here" appearing in an email is more meaningful because it appears more often in phishing emails than legitimate ones — TF-IDF gives it a higher score.
- The phrase "verify account" is even more distinctive — very high score for that email.

**Configuration used** (in `train_phishing_classifier.py`):
```python
TfidfVectorizer(
    max_features=10000,   # keep only the 10,000 most useful words/phrases
    ngram_range=(1, 2),   # look at single words AND 2-word phrases
    min_df=5,             # ignore words appearing in fewer than 5 emails
    max_df=0.8,           # ignore words appearing in more than 80% of emails
    sublinear_tf=True,    # use log(count+1) instead of raw count — helps with long emails
)
```

**What it produces:** A sparse matrix of shape `(n_emails, 10000)` — 10,000 numbers per email.

**The limitation of TF-IDF alone:** It only looks at words. It cannot tell apart:

- "your account has been **secured**" ← legitimate
- "your account will be **suspended** unless you act now" ← phishing

Both sentences share most of the same words. TF-IDF sees them as nearly identical. This is why we need structural features.

---

### Part B: Structural Features

**File:** `backend/ml/feature_engineering.py`  
**Function:** `extract_features(subject, body, sender, reply_to, urls_field)`

These are 32 hand-crafted, objective signals extracted from the email's structure and metadata — things that are true regardless of what words are used. They are grouped into 6 categories:

#### Text-level (features 0–6)

These capture basic writing style statistics:

| # | Name | What it measures | Why it helps |
|---|---|---|---|
| 0 | `body_length` | Total characters in body | Phishing emails are often either very short or padded with noise |
| 1 | `subject_length` | Total characters in subject | — |
| 2 | `body_word_count` | Number of words in body | — |
| 3 | `avg_word_length` | Mean word length | Spam often uses unusual long words or random strings |
| 4 | `exclamation_count` | Number of `!` in body | Phishing loves exclamation marks |
| 5 | `question_count` | Number of `?` in body | — |
| 6 | `caps_ratio` | Ratio of UPPERCASE letters | PHISHING LOVES ALL CAPS |

#### Urgency / Social Engineering (features 7–9)

These detect manipulative language patterns using regular expressions:

| # | Name | What it looks for | Example phrases |
|---|---|---|---|
| 7 | `urgency_score` | Pressure / fear language | "urgent", "act now", "account suspended", "within 24 hours", "verify your account" |
| 8 | `credential_score` | Credential harvesting cues | "click here", "enter your password", "submit the form", "reset password" |
| 9 | `reward_score` | Prize / lure language | "congratulations", "you won", "gift card", "lottery", "inheritance" |

Each score is the count of how many patterns matched. An email with `urgency_score = 4` is saying "act now", "account disabled", "unusual activity", and "verify your identity" — that's a strong phishing signal.

#### Link / URL Signals (features 10–13)

| # | Name | What it measures | Why it helps |
|---|---|---|---|
| 10 | `url_count` | Total number of http/https links | Phishing has many links; a plain text reply has zero |
| 11 | `unique_domains` | How many different domains the links point to | Phishing often uses many different redirect domains |
| 12 | `has_ip_url` | 1 if any link uses a raw IP address (e.g. `http://192.168.1.1/steal`) | Legitimate emails never link to raw IPs — this is a near-certain phishing signal |
| 13 | `url_body_ratio` | Links per word | An email that's mostly links is suspicious |

#### Sender / Domain Signals (features 14–18)

| # | Name | What it measures | Why it helps |
|---|---|---|---|
| 14 | `from_display_ne_email` | 1 if the display name differs from the email address | e.g. shown as "PayPal Security" but sent from `fraud@random.ru` |
| 15 | `from_reply_domain_mismatch` | 1 if From domain ≠ Reply-To domain | Classic BEC (Business Email Compromise) pattern — you see `ceo@company.com` but replies go to `attacker@gmail.com` |
| 16 | `sender_domain_length` | Length of the sender's domain string | Legitimate companies have short domains; phishers use long lookalike domains |
| 17 | `sender_is_free_email` | 1 if sender uses Gmail, Yahoo, Hotmail, etc. | Legitimate bank/corporate emails never come from free providers |
| 18 | `sender_has_numbers` | 1 if the local part of the email has digits | e.g. `support2847362@service.com` — randomly generated sender |

#### Subject Signals (features 19–21)

| # | Name | What it measures |
|---|---|---|
| 19 | `subject_all_caps` | 1 if the entire subject is uppercase |
| 20 | `subject_has_re_fwd` | 1 if subject starts with RE: or FW: (fake thread hijacking) |
| 21 | `subject_urgency` | 1 if the subject contains an urgency phrase |

#### HTML / Formatting Signals (features 22–26)

| # | Name | What it measures | Why it helps |
|---|---|---|---|
| 22 | `html_tag_count` | Total HTML tags in body | Heavily HTML-formatted emails are often marketing/phishing |
| 23 | `img_tag_count` | Number of `<img>` tags | Many images = tracking pixels or visual spoofing |
| 24 | `form_tag_count` | Number of `<form>` tags | Forms in email bodies are a direct credential harvesting indicator |
| 25 | `a_tag_count` | Number of `<a>` anchor/link tags | More links = more redirect opportunities |
| 26 | `has_hidden_text` | 1 if body has `display:none` or `visibility:hidden` CSS | Hidden text is used to trick spam filters with innocent-sounding content |

#### Numeric / Statistical (features 27–31)

| # | Name | What it measures |
|---|---|---|
| 27 | `digit_ratio` | Ratio of digits to total characters |
| 28 | `special_char_ratio` | Ratio of special characters (not letters, numbers, or spaces) |
| 29 | `line_count` | Number of newlines — indicates email length/formatting |
| 30 | `quoted_line_ratio` | Ratio of lines starting with `>` — common in legitimate reply threads |
| 31 | `subject_body_overlap` | Jaccard similarity between words in subject and words in body — phishing often has a generic body unrelated to the subject |

**What it produces:** A dense array of shape `(1, 32)` — 32 numbers per email.

---

### The Hybrid Matrix

**File:** `backend/train_phishing_classifier.py` — `build_hybrid_matrix()` function

The TF-IDF output is a **sparse matrix** (mostly zeros, stored efficiently). The structural features are a **dense array** (32 actual numbers). They are combined using `scipy.sparse.hstack`:

```
TF-IDF output:        (82486, 10000)   ← 10,000 text features
Structural features:  (82486,    32)   ← 32 structural features
                      ─────────────────
Combined matrix:      (82486, 10032)   ← model sees all 10,032 features at once
```

Before combining, the 32 structural features are passed through a `StandardScaler` — this rescales each feature to have mean=0 and standard deviation=1. This is important because `body_length` might be 5000 while `has_ip_url` is 0 or 1. Without scaling, the large-magnitude features would dominate. The scaler is saved separately so it can be reapplied identically at inference time.

---

## 4. The Classifier — Logistic Regression

**File:** `backend/train_phishing_classifier.py`

The model used is a **Logistic Regression** from scikit-learn. Despite the name, it's a classifier, not a regression.

**How it works in plain English:** Logistic Regression learns a weight (a positive or negative number) for each of the 10,032 features. At prediction time, it multiplies each feature value by its weight, sums everything up, and passes the result through a sigmoid function to produce a probability between 0 and 1.

- A feature with a **positive weight** pushes the prediction toward phishing.
- A feature with a **negative weight** pushes the prediction toward legitimate.

This is why Logistic Regression is interpretable — you can literally look at which features have the highest weights to understand *why* an email was flagged. The training script prints this out as "TOP 15 FEATURES → PHISHING".

**Why not a neural network?** For this task with this amount of data, Logistic Regression achieves 99% accuracy on the test set. A neural network would be slower to train, harder to interpret, and wouldn't meaningfully improve accuracy. The hybrid feature engineering is what drives the accuracy, not the model architecture.

**Configuration used:**
```python
LogisticRegression(
    max_iter=1000,          # give it enough iterations to converge
    C=1.0,                  # regularisation strength (prevents overfitting)
    class_weight="balanced",# compensates for any class imbalance in data
    solver="lbfgs",         # efficient solver for large feature sets
    n_jobs=-1,              # use all CPU cores
)
```

---

## 5. Training the Model

**File:** `backend/train_phishing_classifier.py`  
**Run from:** `backend/` directory

```bash
cd backend
./venv/bin/python train_phishing_classifier.py
```

**What it does step by step:**

1. Loads all 6 source CSVs from `backend/ml/data/` and concatenates them into one DataFrame
2. Splits into 80% training (65,988 rows) and 20% test (16,498 rows), stratified so both halves have the same phishing ratio
3. Fits the TF-IDF vectorizer on training text → learns the vocabulary
4. Extracts the 32 structural features for every email in the training set
5. Fits the StandardScaler on the structural features → learns the mean/std of each feature
6. Stacks TF-IDF + scaled structural features → (65,988 × 10,032) matrix
7. Trains Logistic Regression on that matrix
8. Evaluates on the held-out test set → prints precision, recall, F1
9. Saves three files to `backend/ml/models/`

**Test set results achieved:**
```
              precision    recall  f1-score
  legitimate       0.99      0.99      0.99
    phishing       0.99      0.99      0.99
    accuracy                   0.99
```

Confusion matrix:
```
Predicted →   Legit   Phishing
Actual Legit  [7818,    101]   ← 101 legitimate emails called phishing (false positives)
Actual Phish  [  83,   8496]  ← 83 phishing emails missed (false negatives)
```

---

## 6. Saved Model Files

**Directory:** `backend/ml/models/`

After training, three files are saved using `joblib`:

| File | What it is | Needed for? |
|---|---|---|
| `phishing_vectorizer.joblib` | The fitted TF-IDF vectorizer | Transforms new email text into the same 10,000-feature space it was trained on |
| `phishing_classifier.joblib` | The trained Logistic Regression model | Makes the actual prediction |
| `phishing_scaler.joblib` | The fitted StandardScaler | Rescales the 32 structural features using the same mean/std as training |

**Important:** All three files must be used together. If you retrain and only replace one, the others will be out of sync and predictions will be wrong.

---

## 7. The Decision Threshold System

**File:** `backend/phishing_classifier.py`

The default behavior of a classifier is: if `phishing_probability > 50%`, say PHISHING. But 51% confident is not the same as 99% confident — showing both as a red alarm is misleading.

Instead, we use a **three-band system**:

```
phishing_probability ≥ 70%  →  PHISHING   🔴  risk_level = "high"
phishing_probability ≤ 30%  →  LEGITIMATE 🟢  risk_level = "low"
         30% < p < 70%       →  SUSPICIOUS 🟡  risk_level = "medium"
```

**Why 70% and 30%?**
- 70% means the model has seen enough signals to be reasonably confident. Below that, transactional emails from services like GitHub or webinar platforms can fall into the uncertain zone — which is honest, because they genuinely look similar to phishing at the word level.
- 30% is the mirror threshold. Below 30% phishing probability means ≥70% legitimate probability — confident enough to call it clean.
- The 30–70% band (SUSPICIOUS) is the model saying "I'm not sure — a human should look at this." That's better than a confident wrong answer.

These thresholds are constants at the top of `backend/phishing_classifier.py` and can be adjusted:

```python
PHISHING_THRESHOLD   = 0.70
LEGITIMATE_THRESHOLD = 0.30
```

---

## 8. How the API Uses the Model

**File:** `backend/phishing_classifier.py` — `classify_email()` function  
**Called from:** `backend/email_routes.py`

The `classify_email()` function is the bridge between the trained model and the API. Here's exactly what it does when called with raw `.eml` bytes:

**Step 1 — Parse the email**

```python
msg = BytesParser(policy=policy.default).parse(BytesIO(raw_bytes))
```

Extracts: `subject`, `body` (plain text preferred over HTML), `raw_body` (HTML version kept for tag counting), `sender` (From header), `reply_to` (Reply-To header).

**Step 2 — Build TF-IDF features**

```python
X_tfidf = _vectorizer.transform([combined_text])
# combined_text = subject + " " + body
```

The vectorizer was fitted during training — it already knows the vocabulary. Here it just transforms the new email into the same 10,000-dimensional space. Result: a sparse matrix of shape `(1, 10000)`.

**Step 3 — Build structural features**

```python
struct_vec = extract_features(
    subject=subject,
    body=raw_body,   # use HTML version so tag counts work
    sender=sender,
    reply_to=reply_to,
    urls_field=None, # auto-count from body text
).reshape(1, -1)     # shape: (1, 32)

struct_scaled = _scaler.transform(struct_vec)  # shape: (1, 32)
```

**Step 4 — Combine and predict**

```python
X = hstack([X_tfidf, csr_matrix(struct_scaled)])  # shape: (1, 10032)
probabilities = _model.predict_proba(X)[0]
# e.g. [0.07, 0.93] → 7% legit, 93% phishing
```

**Step 5 — Apply thresholds and return**

```python
if phishing_prob >= 0.70:
    verdict = "PHISHING"
elif phishing_prob <= 0.30:
    verdict = "LEGITIMATE"
else:
    verdict = "SUSPICIOUS"
```

Returns a dict:

```json
{
  "verdict": "PHISHING",
  "phishing_probability": 0.9985,
  "legitimate_probability": 0.0015,
  "confidence": 0.9985,
  "risk_level": "high",
  "threshold_used": {
    "phishing_above": 0.7,
    "legitimate_below": 0.3
  },
  "error": null
}
```

**Model loading — singleton pattern**

The three model files are loaded **once** when `phishing_classifier.py` is first imported (at server startup), not on every request. This is important — loading a joblib file on every request would make the API slow. After the first load, the same in-memory objects are reused for all subsequent requests.

```python
# At module level — runs once when the server starts
_load_models()
```

---

## 9. Complete Request Flow

Here is the full path from `.eml` upload to API response:

```
User uploads .eml
       │
       ▼
backend/email_routes.py  →  POST /analyze-email
       │
       ├── raw_bytes = await file.read()
       │
       ├──► email_forensics.analyze_eml(raw_bytes)
       │         Parses headers, extracts:
       │         - From / Reply-To / Return-Path / Subject / Message-ID
       │         - SPF / DKIM / DMARC from Authentication-Results header
       │         - Relay chain (all Received: headers, reversed to sender→delivery)
       │         - Probable origin IPs from relay chain
       │         - Sender timezone from Date header
       │         - Red flags (e.g. From domain ≠ Reply-To domain)
       │
       ├──► geolocation.geolocate_ips(probable_origin_ips)
       │         For each IP: calls ip-api.com
       │         Returns: city, country, ISP, org, lat/lon, proxy flag
       │         Then: assess_origin_masking() checks if IP is a major
       │               provider's own infrastructure (Google, Amazon, etc.)
       │         Then: synthesize_origin_assessment() combines geo + timezone
       │               into one verdict with a confidence level
       │
       ├──► phishing_classifier.classify_email(raw_bytes)
       │         Parses email again (independently)
       │         Builds TF-IDF features (10,000 dimensions)
       │         Builds structural features (32 dimensions)
       │         Combines: (1, 10032) matrix
       │         Runs Logistic Regression
       │         Applies 3-band threshold
       │         Returns: verdict, probabilities, risk_level
       │
       └── Merges all three results into one JSON response
```

The final JSON response has this structure (simplified):

```json
{
  "headers": { "from": "...", "subject": "...", ... },
  "authentication": { "spf": "fail", "dkim": "fail", "dmarc": "fail", "risk_level": "high" },
  "relay_chain": [ { "hop": 1, "raw": "...", "ip_candidates": ["1.2.3.4"] }, ... ],
  "probable_origin_ips": ["1.2.3.4"],
  "red_flags": ["From domain differs from Reply-To domain..."],
  "sender_timezone": { "utc_offset": "+05:30", "plausible_regions": ["India", "Sri Lanka"] },
  "geolocation": [ { "status": "success", "country": "India", "city": "Mumbai", ... } ],
  "origin_assessment": { "verdict": "IP traces to ...", "confidence": "medium" },
  "phishing_analysis": {
    "verdict": "PHISHING",
    "phishing_probability": 0.9985,
    "legitimate_probability": 0.0015,
    "confidence": 0.9985,
    "risk_level": "high",
    "threshold_used": { "phishing_above": 0.7, "legitimate_below": 0.3 },
    "error": null
  }
}
```

---

## 10. How to Retrain

If you want to retrain (e.g. after adding new data or changing features):

```bash
cd backend
./venv/bin/python train_phishing_classifier.py
```

This will:
- Reload all 6 source CSVs from `backend/ml/data/`
- Re-fit the vectorizer, scaler, and model from scratch
- Overwrite the three `.joblib` files in `backend/ml/models/`
- Print accuracy metrics so you can compare before/after

To test the new model against your real `.eml` test files:

```bash
./venv/bin/python test_real_emails.py
```

This loads the saved model (does NOT retrain) and runs it against every `.eml` in `backend/test_emails/`.

To add new training data, drop a new CSV into `backend/ml/data/` and add an entry to the `SOURCE_CSVS` dict in `train_phishing_classifier.py`, specifying whether it has sender and URL columns.

---

## 11. Limitations and Known Gaps

**Dataset age:** Most of the training data is from 2001–2008 (Enron is 2001, CEAS is 2008). Modern phishing has evolved — AI-generated language, lookalike domains, complex redirects. The model may miss newer sophisticated attacks.

**No URL reputation checking:** The model counts links but doesn't check if those links are in any threat intelligence database. A single link to a known malicious domain would be a near-certain phishing indicator but is currently ignored.

**No attachment analysis:** The `.eml` body is scanned but attachments (PDFs, Office documents, zip files) are skipped. Malware delivery via attachment is not detected.

**No WHOIS / domain age:** A domain registered yesterday sending security alerts is highly suspicious. The model currently has no access to DNS or WHOIS data.

**The SUSPICIOUS band requires human review:** An email classified as SUSPICIOUS (30–70% phishing probability) means the model genuinely doesn't know. The forensics data in the left sidebar (SPF/DKIM failures, relay chain anomalies, red flags) should be used alongside the ML verdict to make a final judgment — not the ML result alone.

**Retraining does not update the running server.** After retraining, the server must be restarted for it to load the new `.joblib` files.

---

## File Reference Summary

```
backend/
├── train_phishing_classifier.py   ← Run this to retrain the model
├── test_real_emails.py            ← Run this to test against .eml files
├── phishing_classifier.py         ← Inference module used by the API
├── email_routes.py                ← FastAPI route that calls classify_email()
├── ml/
│   ├── feature_engineering.py    ← The 32 structural features
│   ├── data/
│   │   ├── CEAS_08.csv            ← Training data (39,154 emails)
│   │   ├── Enron.csv              ← Training data (29,767 emails)
│   │   ├── Ling.csv               ← Training data (2,859 emails)
│   │   ├── Nazario.csv            ← Training data (1,565 emails)
│   │   ├── SpamAssasin.csv        ← Training data (5,809 emails)
│   │   ├── Nigerian_Fraud.csv     ← Training data (3,332 emails)
│   │   └── phishing_email.csv     ← Legacy merged CSV (not used for training anymore)
│   └── models/
│       ├── phishing_vectorizer.joblib   ← Saved TF-IDF vectorizer
│       ├── phishing_classifier.joblib   ← Saved Logistic Regression model
│       └── phishing_scaler.joblib       ← Saved StandardScaler
└── test_emails/                   ← .eml files for manual testing
```
