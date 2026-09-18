"""
Structural / behavioural feature extractor for phishing classification.

This module computes hand-crafted, interpretable features from raw email
fields (subject, body, sender, urls).  These are combined with TF-IDF
text features using scipy.sparse.hstack so the downstream classifier
sees both the lexical content *and* objective signals that TF-IDF alone
cannot capture.

Why bother?
-----------
A pure TF-IDF model sees "your account has been secured" and "your
account will be suspended unless you act now" as nearly identical
because they share most of the same tokens.  Structural features pull
out the *objective* differences: urgency word density, number of
external links, From/Reply-To domain mismatch, etc.

Feature list (32 total)
-----------------------
Text-level
  0   body_length           — character count of body
  1   subject_length        — character count of subject
  2   body_word_count       — whitespace-delimited words in body
  3   avg_word_length       — mean word length in body
  4   exclamation_count     — number of '!' in body
  5   question_count        — number of '?' in body
  6   caps_ratio            — ratio of uppercase to total alpha chars

Urgency / social engineering
  7   urgency_score         — weighted count of urgency phrase hits
  8   credential_score      — count of credential-harvesting phrase hits
  9   reward_score          — count of reward/prize lure phrase hits

Link / URL signals
  10  url_count             — total http/https URLs in body
  11  unique_domains        — number of distinct link domains
  12  has_ip_url            — 1 if any URL uses a raw IP address
  13  url_body_ratio        — url_count / max(body_word_count, 1)

Sender / domain signals
  14  from_display_ne_email — 1 if display name ≠ email address portion
  15  from_reply_domain_mismatch — 1 if From domain ≠ Reply-To domain
  16  sender_domain_length  — length of sender domain string
  17  sender_is_free_email  — 1 if sender uses a well-known free provider
  18  sender_has_numbers    — 1 if sender local-part contains digits

Subject signals
  19  subject_all_caps      — 1 if subject is all uppercase
  20  subject_has_re_fwd    — 1 if subject starts with RE: / FW: / FWD:
  21  subject_urgency       — 1 if subject contains urgency phrase

HTML / formatting signals
  22  html_tag_count        — count of <tag> patterns in body
  23  img_tag_count         — count of <img … > tags
  24  form_tag_count        — count of <form … > tags (credential harvest)
  25  a_tag_count           — count of <a … > / anchor tags
  26  has_hidden_text       — 1 if body contains display:none/visibility:hidden

Numeric / statistical
  27  digit_ratio           — ratio of digit chars to total body chars
  28  special_char_ratio    — ratio of non-alphanum non-space to total
  29  line_count            — number of newlines in body
  30  quoted_line_ratio     — ratio of '>' prefixed lines (legit replies)
  31  subject_body_overlap  — Jaccard similarity of subject/body word sets
"""

import re
from typing import Optional

import numpy as np

# ---------------------------------------------------------------------------
# Wordlists (compiled once at import time for speed)
# ---------------------------------------------------------------------------

_URGENCY_PHRASES = [
    r"urgent", r"immediately", r"action required", r"your account.{0,15}suspended",
    r"verify.{0,20}account", r"confirm.{0,20}identity", r"limited time",
    r"expires?\s+(?:today|soon|in \d+)", r"act now", r"respond.{0,10}immediately",
    r"failure to.{0,20}result", r"within \d+ hours?", r"24 hours?",
    r"48 hours?", r"account.{0,15}disabled", r"account.{0,15}locked",
    r"unusual.{0,20}activit", r"suspicious.{0,20}activit",
]
_CREDENTIAL_PHRASES = [
    r"enter.{0,20}password", r"click.{0,20}link", r"click here",
    r"login.{0,15}here", r"sign.{0,10}in.{0,10}here", r"update.{0,20}info",
    r"provide.{0,20}details?", r"submit.{0,20}form", r"reset.{0,15}password",
    r"validate.{0,15}account",
]
_REWARD_PHRASES = [
    r"congratulations?", r"you.{0,10}won", r"you.{0,10}selected",
    r"free.{0,15}prize", r"claim.{0,15}reward", r"\$\d+", r"gift card",
    r"lottery", r"million.{0,10}dollar", r"inheritance",
]
_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "ymail.com",
    "live.com", "msn.com", "rocketmail.com",
}

# Pre-compile for performance
_RE_URGENCY = [re.compile(p, re.IGNORECASE) for p in _URGENCY_PHRASES]
_RE_CREDENTIAL = [re.compile(p, re.IGNORECASE) for p in _CREDENTIAL_PHRASES]
_RE_REWARD = [re.compile(p, re.IGNORECASE) for p in _REWARD_PHRASES]
_RE_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_RE_IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
_RE_DOMAIN = re.compile(r"https?://([^/\s<>\"']+)", re.IGNORECASE)
_RE_HTML_TAG = re.compile(r"<[^>]+>", re.IGNORECASE)
_RE_IMG = re.compile(r"<img\b", re.IGNORECASE)
_RE_FORM = re.compile(r"<form\b", re.IGNORECASE)
_RE_ANCHOR = re.compile(r"<a\b", re.IGNORECASE)
_RE_HIDDEN = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_str(val) -> str:
    """Return empty string for None/NaN, otherwise str."""
    if val is None:
        return ""
    try:
        import math
        if math.isnan(float(val)):
            return ""
    except (TypeError, ValueError):
        pass
    return str(val).strip()


def _extract_email_parts(sender: str):
    """
    Split 'Display Name <user@domain.com>' into (display_name, local, domain).
    Returns ("", "", "") on parse failure.
    """
    sender = _safe_str(sender)
    # Pattern: "Display Name <email>"
    m = re.search(r"<([^>]+)>", sender)
    email_str = m.group(1) if m else sender
    display = sender[: m.start()].strip().strip('"') if m else ""

    if "@" in email_str:
        local, domain = email_str.rsplit("@", 1)
        return display, local.strip(), domain.strip().lower()
    return display, "", ""


def _domain_from_url(url: str) -> str:
    m = _RE_DOMAIN.match(url)
    return m.group(1).lower() if m else ""


def _jaccard(a: str, b: str) -> float:
    wa = set(a.lower().split())
    wb = set(b.lower().split())
    if not wa and not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_features(
    subject: str,
    body: str,
    sender: str = "",
    reply_to: str = "",
    urls_field=None,          # pre-extracted URL count from dataset (int or NaN)
) -> np.ndarray:
    """
    Extract the 32 structural features for a single email.

    Parameters
    ----------
    subject    : email subject string
    body       : email body text (plain or lightly-stripped HTML)
    sender     : raw From header value, e.g. 'Alice <alice@evil.com>'
    reply_to   : raw Reply-To header value
    urls_field : integer url count already in the dataset (CEAS/Nazario
                 have this), or None/NaN to auto-count from body text

    Returns
    -------
    np.ndarray of shape (32,), dtype float32
    """
    subject = _safe_str(subject)
    body = _safe_str(body)
    sender = _safe_str(sender)
    reply_to = _safe_str(reply_to)

    # --- Text-level features (0-6) ---
    body_len = len(body)
    subj_len = len(subject)
    words = body.split()
    word_count = len(words)
    avg_word_len = (sum(len(w) for w in words) / word_count) if words else 0.0
    exclamation = body.count("!")
    question = body.count("?")
    alpha_chars = sum(c.isalpha() for c in body)
    upper_chars = sum(c.isupper() for c in body)
    caps_ratio = (upper_chars / alpha_chars) if alpha_chars else 0.0

    # --- Urgency / social engineering (7-9) ---
    urgency_score = sum(
        len(pat.findall(body)) for pat in _RE_URGENCY
    )
    credential_score = sum(
        len(pat.findall(body)) for pat in _RE_CREDENTIAL
    )
    reward_score = sum(
        len(pat.findall(body)) for pat in _RE_REWARD
    )

    # --- Link / URL signals (10-13) ---
    urls_in_body = _RE_URL.findall(body)
    if urls_field is not None:
        try:
            url_count_val = int(float(urls_field))
            if url_count_val < 0:
                url_count_val = len(urls_in_body)
        except (TypeError, ValueError):
            url_count_val = len(urls_in_body)
    else:
        url_count_val = len(urls_in_body)

    domains = [_domain_from_url(u) for u in urls_in_body]
    unique_doms = len(set(d for d in domains if d))
    has_ip_url = int(bool(_RE_IP_URL.search(body)))
    url_body_ratio = url_count_val / max(word_count, 1)

    # --- Sender / domain signals (14-18) ---
    display_name, from_local, from_domain = _extract_email_parts(sender)
    _, _, reply_domain = _extract_email_parts(reply_to)

    from_display_ne_email = int(
        bool(display_name) and
        bool(from_local) and
        display_name.lower() != from_local.lower()
    )
    from_reply_mismatch = int(
        bool(from_domain) and bool(reply_domain) and
        from_domain != reply_domain
    )
    sender_domain_len = len(from_domain)
    sender_is_free = int(from_domain in _FREE_EMAIL_DOMAINS)
    sender_has_numbers = int(bool(re.search(r"\d", from_local)))

    # --- Subject signals (19-21) ---
    subject_all_caps = int(bool(subject) and subject == subject.upper() and
                           any(c.isalpha() for c in subject))
    subject_has_re_fwd = int(bool(re.match(r"re\s*:|fw[d]?\s*:", subject, re.IGNORECASE)))
    subject_urgency = int(any(pat.search(subject) for pat in _RE_URGENCY))

    # --- HTML / formatting signals (22-26) ---
    html_tags = len(_RE_HTML_TAG.findall(body))
    img_tags = len(_RE_IMG.findall(body))
    form_tags = len(_RE_FORM.findall(body))
    a_tags = len(_RE_ANCHOR.findall(body))
    has_hidden = int(bool(_RE_HIDDEN.search(body)))

    # --- Numeric / statistical (27-31) ---
    total_chars = max(len(body), 1)
    digit_ratio = sum(c.isdigit() for c in body) / total_chars
    special_ratio = sum(
        not (c.isalnum() or c.isspace()) for c in body
    ) / total_chars
    line_count = body.count("\n")
    lines = body.split("\n")
    quoted_lines = sum(1 for ln in lines if ln.strip().startswith(">"))
    quoted_ratio = (quoted_lines / len(lines)) if lines else 0.0
    subj_body_overlap = _jaccard(subject, body)

    features = np.array([
        body_len,              # 0
        subj_len,              # 1
        word_count,            # 2
        avg_word_len,          # 3
        exclamation,           # 4
        question,              # 5
        caps_ratio,            # 6
        urgency_score,         # 7
        credential_score,      # 8
        reward_score,          # 9
        url_count_val,         # 10
        unique_doms,           # 11
        has_ip_url,            # 12
        url_body_ratio,        # 13
        from_display_ne_email, # 14
        from_reply_mismatch,   # 15
        sender_domain_len,     # 16
        sender_is_free,        # 17
        sender_has_numbers,    # 18
        subject_all_caps,      # 19
        subject_has_re_fwd,    # 20
        subject_urgency,       # 21
        html_tags,             # 22
        img_tags,              # 23
        form_tags,             # 24
        a_tags,                # 25
        has_hidden,            # 26
        digit_ratio,           # 27
        special_ratio,         # 28
        line_count,            # 29
        quoted_ratio,          # 30
        subj_body_overlap,     # 31
    ], dtype=np.float32)

    return features


def extract_features_batch(df) -> np.ndarray:
    """
    Vectorised extraction over a DataFrame with columns:
        subject, body, [sender], [reply_to], [urls]
    Missing columns are treated as empty strings / None.

    Returns np.ndarray of shape (n_rows, 32).
    """
    has_sender = "sender" in df.columns
    has_reply = "reply_to" in df.columns
    has_urls = "urls" in df.columns

    rows = []
    for _, row in df.iterrows():
        rows.append(extract_features(
            subject=row.get("subject", ""),
            body=row.get("body", ""),
            sender=row.get("sender", "") if has_sender else "",
            reply_to=row.get("reply_to", "") if has_reply else "",
            urls_field=row.get("urls", None) if has_urls else None,
        ))
    return np.vstack(rows)


# ---------------------------------------------------------------------------
# Feature names (for inspection / reporting)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "body_length", "subject_length", "body_word_count", "avg_word_length",
    "exclamation_count", "question_count", "caps_ratio",
    "urgency_score", "credential_score", "reward_score",
    "url_count", "unique_domains", "has_ip_url", "url_body_ratio",
    "from_display_ne_email", "from_reply_domain_mismatch",
    "sender_domain_length", "sender_is_free_email", "sender_has_numbers",
    "subject_all_caps", "subject_has_re_fwd", "subject_urgency",
    "html_tag_count", "img_tag_count", "form_tag_count", "a_tag_count",
    "has_hidden_text",
    "digit_ratio", "special_char_ratio", "line_count",
    "quoted_line_ratio", "subject_body_overlap",
]
