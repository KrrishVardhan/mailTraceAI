import hashlib

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi import Request

from email_forensics import analyze_eml, assess_origin_masking, synthesize_origin_assessment
from geolocation import geolocate_ips
from phishing_classifier import classify_email
from llm_verdict import get_llm_verdict, _extract_body_from_bytes
from db.database import get_cached_result, get_case, list_cases, store_analysis

router = APIRouter()


@router.post("/analyze-email")
async def analyze_email(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(400, "Please upload a .eml file")

    raw_bytes = await file.read()
    email_hash = hashlib.sha256(raw_bytes).hexdigest()
    cached_result = get_cached_result(
        getattr(request.app.state, "db_pool", None),
        email_hash,
    )
    if cached_result is not None:
        cached_result["cached"] = True
        return cached_result

    # --- Header forensics ---
    try:
        result = analyze_eml(raw_bytes)
    except Exception as e:
        raise HTTPException(400, f"Could not parse email: {e}")

    # --- Geolocation ---
    try:
        geo_results = geolocate_ips(result["probable_origin_ips"])
        for geo in geo_results:
            if geo.get("status") == "success":
                geo["masking"] = assess_origin_masking(geo)
        result["geolocation"] = geo_results
        result["origin_assessment"] = synthesize_origin_assessment(
            geo_results, result.get("sender_timezone")
        )
    except Exception as e:
        result["geolocation"] = []
        result["geolocation_error"] = str(e)

    # --- ML phishing classification ---
    result["phishing_analysis"] = classify_email(raw_bytes)

    # --- LLM verdict layer ---
    # Extract plain-text body from the raw bytes for the LLM prompt.
    # We pass the full result dict built so far so the LLM sees headers,
    # auth, relay chain, geolocation, and ML classifier output together.
    try:
        email_body = _extract_body_from_bytes(raw_bytes)
        llm_result = get_llm_verdict(email_body, result)
    except Exception:
        # Absolute last-resort guard — get_llm_verdict has its own internal
        # fallback, so this should never trigger in practice.
        llm_result = {
            "llm_verdict": None,
            "llm_confidence": None,
            "reasoning_summary": "LLM analysis unavailable — falling back to ML classifier result.",
            "evidence": [],
            "ml_agreement": "unavailable",
            "agreement_explanation": None,
            "final_recommended_risk_level": result["phishing_analysis"].get("risk_level", "unknown"),
            "llm_error": True,
        }

    result["llm_analysis"] = llm_result

    # primary_verdict: the single field the frontend uses for banner colour/text.
    # Prefers the LLM's recommended risk level; falls back to ML when LLM errored.
    if llm_result.get("llm_error"):
        result["primary_verdict"] = result["phishing_analysis"].get("risk_level", "unknown")
    else:
        result["primary_verdict"] = llm_result.get(
            "final_recommended_risk_level",
            result["phishing_analysis"].get("risk_level", "unknown"),
        )

    result["cached"] = False
    store_analysis(
        getattr(request.app.state, "db_pool", None),
        email_hash=email_hash,
        filename=file.filename,
        result=result,
    )
    return result


@router.get("/cases")
def cases(request: Request, limit: int = 20):
    return list_cases(
        getattr(request.app.state, "db_pool", None),
        max(1, min(limit, 100)),
    )


@router.get("/cases/{case_id}")
def case(case_id: int, request: Request):
    result = get_case(
        getattr(request.app.state, "db_pool", None),
        case_id,
    )
    if result is None:
        raise HTTPException(404, "Analysis case not found")
    return result
