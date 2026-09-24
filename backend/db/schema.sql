CREATE TABLE IF NOT EXISTS analyses (
    id SERIAL PRIMARY KEY,
    email_hash TEXT UNIQUE NOT NULL,
    filename TEXT,
    uploaded_at TIMESTAMPTZ DEFAULT now(),
    result_json JSONB NOT NULL,
    risk_level TEXT,
    verdict TEXT,
    llm_verdict TEXT,
    ml_agreement TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyses_uploaded_at ON analyses (uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_email_hash ON analyses (email_hash);
