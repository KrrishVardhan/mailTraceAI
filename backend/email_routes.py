from fastapi import APIRouter, UploadFile, File, HTTPException

from email_forensics import analyze_eml, assess_origin_masking, synthesize_origin_assessment
from geolocation import geolocate_ips
from phishing_classifier import classify_email
from llm_verdict import get_llm_verdict, _extract_body_from_bytes

router = APIRouter()


@router.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(400, "Please upload a .eml file")

    raw_bytes = await file.read()

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

    return result
