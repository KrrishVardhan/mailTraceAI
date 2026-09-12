const API_URL = "http://127.0.0.1:8000";

export interface GeolocationResult {
  status: "success" | "fail";
  query: string;
  message?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  regionName?: string;
  city?: string;
  lat?: number;
  lon?: number;
  isp?: string;
  org?: string;
  as?: string;
  proxy?: boolean;
  hosting?: boolean;
}

export interface AnalysisResult {
  headers: {
    from: string | null;
    reply_to: string | null;
    return_path: string | null;
    subject: string | null;
    message_id: string | null;
  };
  authentication: {
    spf: string;
    dkim: string;
    dmarc: string;
    risk_level: "low" | "medium" | "high";
  };
  relay_chain: {
    hop: number;
    raw: string;
    ip_candidates: string[];
  }[];
  probable_origin_ips: string[];
  red_flags: string[];
  geolocation: GeolocationResult[];
  geolocation_error?: string;
}

export async function analyzeEmail(file: File): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_URL}/analyze-email`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(err.detail || "Failed to analyze email");
  }

  return res.json();
}
