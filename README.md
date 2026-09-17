# Email Forensics POC

## Prerequisites

- Python 3.10+
- Node.js 18+ and pnpm
- Docker + Docker Compose

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/KrrishVardhan/mailTraceAI
cd mailTraceAI
```

### 2. Start PostgreSQL

```bash
docker compose up -d
```

### 3. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate      # macOS/Linux
# venv\Scripts\activate       # Windows
pip install fastapi uvicorn python-multipart requests
```

> If you have a `requirements.txt`: `pip install -r requirements.txt`

### 4. Frontend

```bash
cd frontend
pnpm install
```

---

## Running the App

Open two terminals:

```bash
# Terminal 1 — backend
cd backend
source venv/bin/activate
./venv/bin/python -m uvicorn main:app --reload
# → http://127.0.0.1:8000  (API docs at /docs)
```

```bash
# Terminal 2 — frontend
cd frontend
pnpm dev
# → http://localhost:5173
```

Open `http://localhost:5173`, upload a `.eml` file, and click **Analyze**.
