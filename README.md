# mailTraceAI

mailTraceAI is an email-forensics dashboard for investigating raw `.eml` files. It combines header and authentication analysis, relay-chain reconstruction, origin-IP geolocation, a trained phishing classifier, and a Groq-powered LLM verdict into one investigation view.

The project is designed as an investigative aid, not as a replacement for mail-provider evidence or human review. Provider relay IPs usually identify Google, Microsoft, Amazon, or another infrastructure provider—not the sender's physical location.

## What it does

- Parses email headers and MIME content from `.eml` files.
- Extracts SPF, DKIM, and DMARC results and calculates authentication risk.
- Reconstructs the `Received:` relay chain and probable origin IPs.
- Flags useful indicators such as authentication failures and address mismatches.
- Geolocates probable origin IPs through `ip-api.com`.
- Classifies phishing probability with the bundled scikit-learn model.
- Uses Groq's OpenAI-compatible API to synthesize the ML, header, body, relay, and geolocation evidence.
- Shows verdicts, model agreement, evidence, relay hops, and origin maps in the React dashboard.
- Stores completed investigations in Neon Postgres and caches results by SHA-256 email hash.

## Architecture

```text
React + Vite dashboard
          │
          ▼
FastAPI /analyze-email
          │
          ├── .eml parsing and authentication analysis
          ├── relay-chain and origin-IP analysis
          ├── ip-api geolocation
          ├── local ML phishing classifier
          ├── Groq LLM verdict
          └── Neon Postgres cache/history
```

The backend uses `psycopg2` connection pooling directly; it does not use SQLAlchemy or another ORM. The database schema is initialized automatically at application startup with `CREATE TABLE IF NOT EXISTS`.

## Requirements

- Python 3.10+
- Node.js 18+
- pnpm
- A Groq API key
- A Neon Postgres connection string

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/KrrishVardhan/mailTraceAI.git
cd mailTraceAI
```

### 2. Configure environment variables

Copy `.env.example` to `.env` and add your credentials:

```env
GROQ_API_KEY=your_groq_api_key
DATABASE_URL=postgresql://user:password@ep-example.region.aws.neon.tech/dbname?sslmode=require
```

`DATABASE_URL` must point to Neon or another PostgreSQL-compatible database. The backend adds `sslmode=require` automatically if it is omitted. A Neon `-pooler` endpoint can be used directly when available.

Never commit `.env` or real API keys.

### 3. Install backend dependencies

```bash
cd backend
python -m venv venv
source venv/bin/activate       # macOS/Linux
# venv\Scripts\activate        # Windows
python -m pip install -r requirements.txt
```

If your shell resolves a different Python after activation, use the virtual-environment executable explicitly:

```bash
./venv/bin/python -m pip install -r requirements.txt
```

### 4. Install frontend dependencies

```bash
cd ../frontend
pnpm install
```

## Run locally

Start the backend:

```bash
cd backend
./venv/bin/python -m uvicorn main:app --reload
```

The API runs at [http://127.0.0.1:8000](http://127.0.0.1:8000). Interactive API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

In a second terminal, start the frontend:

```bash
cd frontend
pnpm dev
```

Open [http://localhost:5173](http://localhost:5173), upload an `.eml` file, and select **Analyze**.

## API

### `POST /analyze-email`

Accepts `multipart/form-data` with a `.eml` file in the `file` field.

The response contains:

- `headers`
- `authentication`
- `relay_chain`
- `probable_origin_ips`
- `red_flags`
- `geolocation`
- `origin_assessment`
- `phishing_analysis`
- `llm_analysis`
- `primary_verdict`
- `cached`

`cached` is `false` for a newly computed analysis and `true` when the exact same raw email has already been analyzed. Cached requests return immediately without running the ML classifier or Groq call.

### `GET /cases?limit=20`

Returns recent investigation summaries. `limit` defaults to 20 and is capped at 100:

```json
[
  {
    "id": 1,
    "filename": "sample.eml",
    "uploaded_at": "2026-09-23T21:19:43Z",
    "risk_level": "high",
    "verdict": "phishing",
    "llm_verdict": "phishing",
    "ml_agreement": "agree"
  }
]
```

If the database is temporarily unavailable, this endpoint returns an empty list with HTTP 200.

### `GET /cases/{id}`

Returns the complete stored analysis result for a previous investigation, using the same response shape as `/analyze-email`. It returns HTTP 404 when the case does not exist.

## Persistence

The `analyses` table is defined in `backend/db/schema.sql` and initialized during FastAPI startup. Each raw email is keyed by:

```text
sha256(raw uploaded bytes)
```

Database failures are logged and treated as non-fatal: a new analysis still completes if Neon is unreachable, and history endpoints degrade gracefully.

## Project structure

```text
mailTraceAI/
├── backend/
│   ├── main.py                 # FastAPI app and database lifespan
│   ├── email_routes.py         # Analysis and history endpoints
│   ├── email_forensics.py      # Header/authentication/relay analysis
│   ├── geolocation.py          # IP geolocation and masking assessment
│   ├── phishing_classifier.py  # Bundled ML inference
│   ├── llm_verdict.py          # Groq LLM integration
│   └── db/
│       ├── database.py         # psycopg2 pool and persistence helpers
│       └── schema.sql          # PostgreSQL schema
├── frontend/
│   └── src/
│       ├── App.tsx             # Main investigation dashboard
│       └── components/         # Charts, map, timeline, and UI components
├── .env.example
├── docker-compose.yml
└── ML.md                      # Classifier details and training notes
```

## Testing and checks

Backend syntax and dependency checks:

```bash
backend/venv/bin/python -m compileall -q backend
backend/venv/bin/python -m pip check
```

Frontend checks:

```bash
cd frontend
pnpm run typecheck
pnpm run lint
pnpm run build
```

Example `.eml` files are available under `backend/test_emails/`. You can also export an original message from Gmail or Outlook and upload the resulting `.eml` file.

## Limitations

- A provider relay IP is not proof of the sender's actual location.
- DKIM, SPF, or DMARC failures are signals, not standalone proof of phishing.
- Geolocation depends on the external `ip-api.com` service.
- The LLM result depends on Groq availability and the configured model.
- This tool does not replace mailbox-provider logs, endpoint telemetry, threat-intelligence correlation, or human investigation.
