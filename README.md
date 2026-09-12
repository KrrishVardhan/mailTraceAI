# Email Forensics POC

A proof-of-concept tool for analyzing `.eml` files: validating SPF/DKIM/DMARC authentication, reconstructing the email's relay path (`Received:` header chain), and geolocating the probable origin IP — without a full ML/NLP fraud classifier, by design (see [Scope](#scope) below).

Built as a learning/demo project with FastAPI + React, to explore the "origin traceability and geolocation" component of a broader email-fraud-detection concept.

## Table of Contents

- [Scope](#scope)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Running the App](#running-the-app)
- [API Reference](#api-reference)
- [Testing With Real Emails](#testing-with-real-emails)
- [Key Findings & Limitations](#key-findings--limitations)
- [Not Yet Implemented](#not-yet-implemented)

## Scope

This POC deliberately isolates **one** piece of a larger email-fraud-detection concept: given a raw `.eml` file, can we (a) verify whether its authentication headers are legitimate, and (b) trace and geolocate its probable network origin? It does **not** include NLP-based content classification, ML-based fraud scoring, or threat-intel/campaign correlation — those were out of scope for this POC on purpose, to validate the header-forensics piece in isolation first.

## Features

- ✅ Parses raw `.eml` files (headers, MIME-encoded subjects, multi-hop `Received:` chains)
- ✅ Validates and interprets `Authentication-Results` (SPF / DKIM / DMARC pass/fail/softfail/permerror)
- ✅ Simple heuristic risk scoring (low/medium/high) based on authentication failures
- ✅ Reconstructs the relay chain in chronological order (earliest hop → delivery)
- ✅ Extracts the probable origin IP (bracket-anchored extraction — see [Key Findings](#key-findings--limitations) for why this matters)
- ✅ Geolocates the origin IP via [ip-api.com](https://ip-api.com) (city/region/country, ISP/org, proxy & hosting-provider flags)
- ✅ Flags simple red flags (e.g. From/Reply-To domain mismatch — a common BEC pattern)
- ✅ Interactive map visualization (Leaflet + OpenStreetMap) of the geolocated origin
- ✅ Clean React/TypeScript dashboard: authentication badges, red-flag alerts, relay chain, map

## Tech Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI, Python's built-in `email` module, `requests` |
| Frontend | React + TypeScript (Vite), Tailwind CSS v4, shadcn/ui, Leaflet / react-leaflet |
| Database | PostgreSQL 16 (via Docker) — provisioned, not yet used |
| Geolocation | [ip-api.com](https://ip-api.com) free batch API |
| Maps | Leaflet + OpenStreetMap tiles (no API key required) |

## Project Structure

```
email-forensics-poc/
├── docker-compose.yml          # Postgres (currently unused by the app)
├── backend/
│   ├── main.py                 # FastAPI app entrypoint, CORS, router mounting
│   ├── email_routes.py         # POST /analyze-email endpoint
│   ├── email_forensics.py      # Core parsing: headers, auth, relay chain
│   ├── geolocation.py          # ip-api.com batch lookup
│   ├── sample.eml              # Fabricated phishing sample for testing
│   └── venv/                   # (gitignored)
└── frontend/
    ├── src/
    │   ├── App.tsx              # Main UI
    │   ├── lib/api.ts           # Typed fetch wrapper for the backend
    │   └── components/
    │       └── IpLocationMap.tsx  # Leaflet map component
    └── ...
```

## Setup & Installation

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm (or pnpm)
- Docker + Docker Compose

### 1. Clone and enter the project

```bash
git clone https://github.com/KrrishVardhan/email-forensics-poc
cd email-forensics-poc
```

### 2. Update `.gitignore` (root)

Your current root `.gitignore` only covers Node/JS artifacts. Add Python entries so the backend's virtual environment and cache files don't get committed:

```gitignore
# Python
backend/venv/
__pycache__/
*.pyc
.env
```

### 3. Start PostgreSQL

```bash
docker compose up -d
```

> Note: the database isn't used by the app yet (see [Not Yet Implemented](#not-yet-implemented)) — this step just keeps the environment ready for when persistence is added.

### 4. Backend setup

```bash
cd backend
python -m venv venv
```

Activate it:

```bash
source venv/bin/activate      # macOS/Linux
venv\Scripts\activate         # Windows
```

> **Using a Python version manager (mise, asdf, pyenv)?** Their shims can sometimes take priority over an activated venv's `PATH` entries, silently causing packages to resolve from the wrong Python. If you hit `ModuleNotFoundError` despite installing correctly, sidestep it by always invoking the venv's binary explicitly:
> ```bash
> ./venv/bin/python -m pip install -r requirements.txt
> ./venv/bin/python -m uvicorn main:app --reload
> ```

Install dependencies:

```bash
pip install fastapi uvicorn python-multipart requests
```

(Or, if you've created a `requirements.txt`: `pip install -r requirements.txt`.)

### 5. Frontend setup

```bash
cd ../frontend
npm install
npm install leaflet react-leaflet
npm install -D @types/leaflet
```

Make sure `leaflet/dist/leaflet.css` is imported once in your entry point (`src/main.tsx`):

```tsx
import "leaflet/dist/leaflet.css";
```

## Running the App

Two terminals:

```bash
# Terminal 1 — backend
cd backend
./venv/bin/python -m uvicorn main:app --reload
# → http://127.0.0.1:8000  (interactive docs at /docs)
```

```bash
# Terminal 2 — frontend
cd frontend
npm run dev
# → http://localhost:5173
```

Open `http://localhost:5173`, upload a `.eml` file, click Analyze.

## API Reference

### `POST /analyze-email`

**Request**: `multipart/form-data` with a single field `file` (must have a `.eml` extension).

**Response**: `200 OK`

```json
{
  "headers": {
    "from": "string | null",
    "reply_to": "string | null",
    "return_path": "string | null",
    "subject": "string | null",
    "message_id": "string | null"
  },
  "authentication": {
    "spf": "pass | fail | softfail | not_found | ...",
    "dkim": "pass | fail | permerror | not_found | ...",
    "dmarc": "pass | fail | not_found | ...",
    "risk_level": "low | medium | high"
  },
  "relay_chain": [
    { "hop": 1, "raw": "string", "ip_candidates": ["string"] }
  ],
  "probable_origin_ips": ["string"],
  "red_flags": ["string"],
  "geolocation": [
    {
      "status": "success | fail",
      "query": "string",
      "country": "string",
      "regionName": "string",
      "city": "string",
      "lat": 0.0,
      "lon": 0.0,
      "isp": "string",
      "org": "string",
      "proxy": false,
      "hosting": false
    }
  ]
}
```

**Errors**: `400` if the uploaded file isn't `.eml` or can't be parsed.

## Testing With Real Emails

Export a real `.eml` to test against:

- **Gmail**: open the email → ⋮ (three-dot menu) → "Show original" → "Download Original"
- **Outlook**: open the email → File → Save As → choose `.eml`

A fabricated phishing sample (`backend/sample.eml`) is included for a guaranteed high-risk test case.

## Key Findings & Limitations

Testing against real emails surfaced some important, non-obvious behavior worth understanding before trusting this tool's output:

| Test case | Auth result | Origin traced to | Takeaway |
|---|---|---|---|
| Fabricated phishing sample | SPF softfail, DKIM/DMARC fail | Hosting provider, Brisbane AU | Correctly flagged high risk |
| Real email, self-sent via Gmail | SPF pass, DKIM permerror | Google infrastructure, Mountain View CA | Correctly low risk — but **not the sender's real location** |
| Real newsletter, landed in Gmail spam | SPF/DKIM/DMARC all pass | Amazon SES, Seattle WA | Correctly low risk — spam ≠ fraudulent |

**Gmail/Outlook/Yahoo do not leak the sending device's IP.** Emails sent through major webmail providers only ever show that provider's own outbound relay in `Received:` headers — by design, for sender privacy. This means:
- Origin tracing works well against **externally-hosted phishing infrastructure** (cheap VPS/hosting providers, compromised smaller mail servers) — exactly the infrastructure real phishing campaigns tend to use, since spoofing a domain through Gmail/Outlook's infrastructure would fail DKIM/DMARC alignment anyway.
- Origin tracing **cannot** recover a real sender's IP/location when the email was legitimately sent through a major provider — including in the Business Email Compromise (BEC) case where an attacker has compromised a real account. Retrieving that data requires legal process against the provider, not header analysis.

**Spam-folder placement is not a fraud signal this tool measures.** Gmail's spam classification draws on sender reputation history, bulk-send patterns, and recipient engagement data this tool has no access to. A properly authenticated bulk sender (e.g. a legitimate newsletter via Amazon SES) can land in spam while still being completely legitimate — this tool correctly reports that case as low risk.

## Not Yet Implemented

- **Persistence** — Postgres is provisioned via Docker but the app is currently stateless; no case history or database storage yet.
- **"Last trusted hop" boundary logic** — distinguishing which `Received:` hops are attacker-controlled (and therefore potentially forged) vs. verified by a trusted relay.
- **NLP/ML content classification** — intentionally out of scope for this POC (see [Scope](#scope)).
- **Domain/WHOIS intelligence, threat-intel correlation, campaign/case grouping** — future extensions from the original broader concept, not built here.
