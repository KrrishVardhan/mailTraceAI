from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root, regardless of the process working directory.
# This must run before any module that reads os.environ (e.g. llm_verdict).
# override=False means an already-set shell variable takes precedence.
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env", override=False)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.database import close_pool, create_pool, initialize_schema
from email_routes import router as email_router

@asynccontextmanager
async def lifespan(application: FastAPI):
    pool = create_pool()
    initialize_schema(pool)
    application.state.db_pool = pool
    try:
        yield
    finally:
        close_pool(pool)


app = FastAPI(title="Email Forensics POC", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email_router)

@app.get("/")
def home():
    return {"message": "Email Forensics POC — see /docs"}
