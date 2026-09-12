from fastapi import APIRouter, UploadFile, File, HTTPException

from email_forensics import analyze_eml
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

    # Geolocate whatever IP(s) we extracted as the probable origin.
    # This is a separate try/except so a geolocation failure (network
    # issue, rate limit) doesn't break the header analysis we already
    # have — the user still gets useful results either way.
    try:
        result["geolocation"] = geolocate_ips(result["probable_origin_ips"])
    except Exception as e:
        result["geolocation"] = []
        result["geolocation_error"] = str(e)

    return result
