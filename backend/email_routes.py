from fastapi import APIRouter, UploadFile, File, HTTPException

from email_forensics import analyze_eml, assess_origin_masking, synthesize_origin_assessment
from geolocation import geolocate_ips
from phishing_classifier import classify_email

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

    return result
