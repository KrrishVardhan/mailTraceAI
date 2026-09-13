from fastapi import APIRouter, UploadFile, File, HTTPException

from email_forensics import analyze_eml, assess_origin_masking, synthesize_origin_assessment
from geolocation import geolocate_ips

router = APIRouter()


@router.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(400, "Please upload a .eml file")

    raw_bytes = await file.read()

    try:
        result = analyze_eml(raw_bytes)
    except Exception as e:
        raise HTTPException(400, f"Could not parse email: {e}")

    try:
        geo_results = geolocate_ips(result["probable_origin_ips"])
        # Tag each successful result with whether it's likely masked by
        # major provider infrastructure, so the frontend can display
        # that distinction rather than presenting every geolocation as
        # equally trustworthy.
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

    return result
