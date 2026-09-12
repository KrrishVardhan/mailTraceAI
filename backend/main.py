from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from email_routes import router as email_router

app = FastAPI(title="Email Forensics POC")

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
