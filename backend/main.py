from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
import time
import io
import requests
import numpy as np
import librosa
from typing import Optional
from collections import deque
from pydantic import BaseModel
from google import genai
from google.genai import types
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None
from config import (
    VIRUSTOTAL_API_KEY,
    GEMINI_API_KEYS,
    WHATSAPP_TOKEN,
    WHATSAPP_PHONE_ID,
    VERIFY_TOKEN,
)
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
processed_messages = deque(maxlen=500)
GEMINI_MODEL_NAME = "models/gemini-flash-latest"
_current_key_index = 0
def _make_client():
    key = GEMINI_API_KEYS[_current_key_index]
    return genai.Client(api_key=key)
client = _make_client()
def switch_gemini_key():
    global _current_key_index, client
    _current_key_index = (_current_key_index + 1) % len(GEMINI_API_KEYS)
    client = _make_client()
def call_gemini(contents):
    last_error = None

    for _ in range(len(GEMINI_API_KEYS)):
        try:
            return client.models.generate_content(
                model=GEMINI_MODEL_NAME,
                contents=contents,
            )
        except Exception as e:
            last_error = e
            msg = str(e)

            if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                switch_gemini_key()
                continue
            else:
                raise

    raise last_error if last_error else Exception("All Gemini keys failed")


class AnalysisResponse(BaseModel):
    status: str
    risk_level: Optional[str] = None
    reason: str
    suggestion: str


def send_whatsapp_text(to_number: str, message: str) -> None:
    url = f"https://graph.facebook.com/v22.0/{WHATSAPP_PHONE_ID}/messages"

    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }

    data = {
        "messaging_product": "whatsapp",
        "to": to_number,
        "type": "text",
        "text": {"body": message},
    }

    try:
        requests.post(url, json=data, headers=headers, timeout=20)
    except Exception as e:
        print("WhatsApp send error:", e)


def send_menu(to_number: str) -> None:
    text = (
        "👋 Hello! This is *EchoTrace AI*, your scam-safety assistant.\n\n"
        "1️⃣ Check a link\n"
        "Command: */url your-link-here*\n\n"
        "2️⃣ Check a PDF or document\n"
        "Send the file here.\n\n"
        "3️⃣ Check a voice message\n"
        "Send the audio file.\n\n"
        "4️⃣ Type */help* anytime."
    )

    send_whatsapp_text(to_number, text)


def download_whatsapp_media(media_id: str) -> bytes:
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}"}

    meta_url = f"https://graph.facebook.com/v22.0/{media_id}"
    meta_resp = requests.get(meta_url, headers=headers)
    meta_resp.raise_for_status()

    media_url = meta_resp.json().get("url")

    file_resp = requests.get(media_url, headers=headers)
    file_resp.raise_for_status()

    return file_resp.content


def parse_gemini_response(text: str) -> AnalysisResponse:
    risk = "Unknown"
    reason = "Could not parse AI response."
    suggestion = "Be careful."

    if text:
        for line in text.splitlines():
            if line.startswith("RISK="):
                risk = line.split("=", 1)[1].strip()
            elif line.startswith("REASON="):
                reason = line.split("=", 1)[1].strip()
            elif line.startswith("SUGGESTION="):
                suggestion = line.split("=", 1)[1].strip()

    return AnalysisResponse(
        status="success",
        risk_level=risk,
        reason=reason,
        suggestion=suggestion,
    )


def fallback_url_analysis(url: str) -> AnalysisResponse:
    u = url.lower()

    suspicious_words = [
        "login",
        "verify",
        "update",
        "bank",
        "account",
        "otp",
        "gift",
        "lottery",
        "winner",
        "free",
        "offer",
        "bonus",
        "payment",
        "refund",
        "urgent",
        "kyc",
    ]

    bad_tlds = [".xyz", ".top", ".click", ".loan", ".work", ".icu"]

    score = 0
    reasons = []

    if any(tld in u for tld in bad_tlds):
        score += 2
        reasons.append("uses risky domain extension")

    if "https://" not in u and "http://" in u:
        score += 1
        reasons.append("uses insecure http")

    if "@" in u:
        score += 2
        reasons.append("contains suspicious @ symbol")

    if u.count("-") >= 3:
        score += 1
        reasons.append("contains many hyphens")

    if any(word in u for word in suspicious_words):
        score += 1
        reasons.append("contains scam-related words")

    if score >= 4:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("no major phishing indicators found")

    return AnalysisResponse(
        status="backup",
        risk_level=risk,
        reason="; ".join(reasons),
        suggestion="Avoid entering sensitive information unless verified.",
    )


def fallback_pdf_analysis(pdf_bytes: bytes) -> AnalysisResponse:
    if PdfReader is None:
        return AnalysisResponse(
            status="backup",
            risk_level="Unknown",
            reason="PDF library not installed.",
            suggestion="Avoid suspicious files.",
        )

    try:
        text_content = ""
        reader = PdfReader(io.BytesIO(pdf_bytes))

        for page in reader.pages:
            text_content += page.extract_text() or ""

        lower = text_content.lower()

        scam_words = [
            "otp",
            "verify your account",
            "bank",
            "kyc",
            "lottery",
            "winner",
            "urgent payment",
            "bitcoin",
            "gift card",
        ]

        score = sum(1 for w in scam_words if w in lower)

        if score >= 5:
            risk = "High"
        elif score >= 2:
            risk = "Medium"
        else:
            risk = "Low"

        return AnalysisResponse(
            status="backup",
            risk_level=risk,
            reason="Scam phrase analysis completed.",
            suggestion="Verify document source before acting.",
        )

    except Exception:
        return AnalysisResponse(
            status="backup_error",
            risk_level="Unknown",
            reason="Could not analyse PDF.",
            suggestion="Avoid suspicious files.",
        )


def analyze_url_with_gemini(url: str) -> AnalysisResponse:
    prompt = f"""
You are a cybersecurity expert. Analyse this URL: {url}
Respond exactly in:
RISK=<Low/Medium/High>
REASON=<one sentence>
SUGGESTION=<one sentence>
"""

    try:
        resp = call_gemini(prompt)
        return parse_gemini_response(resp.text)
    except Exception:
        return fallback_url_analysis(url)


def analyze_pdf_with_gemini(pdf_bytes: bytes) -> AnalysisResponse:
    prompt = (
        "Analyse this PDF for scam, fraud or phishing content.\n"
        "Respond exactly in:\n"
        "RISK=<Low/Medium/High>\n"
        "REASON=<one sentence>\n"
        "SUGGESTION=<one sentence>\n"
    )

    try:
        resp = call_gemini([
            prompt,
            types.Part.from_bytes(
                data=pdf_bytes,
                mime_type="application/pdf",
            ),
        ])

        return parse_gemini_response(resp.text)

    except Exception:
        return fallback_pdf_analysis(pdf_bytes)


def analyze_audio_with_gemini(audio_bytes: bytes) -> AnalysisResponse:
    prompt = (
        "Analyse whether this phone call or audio sounds like a scam.\n"
        "Respond in:\n"
        "RISK=<Low/Medium/High>\n"
        "REASON=<one sentence>\n"
        "SUGGESTION=<one sentence>\n"
    )

    try:
        resp = call_gemini([
            prompt,
            types.Part.from_bytes(
                data=audio_bytes,
                mime_type="audio/ogg",
            ),
        ])

        return parse_gemini_response(resp.text)

    except Exception:
        return AnalysisResponse(
            status="error",
            risk_level="Error",
            reason="AI unavailable",
            suggestion="Try again later.",
        )


def analyze_audio_with_librosa(audio_bytes: bytes) -> dict:
    try:
        audio_file = io.BytesIO(audio_bytes)
        y, sr = librosa.load(audio_file, sr=None, mono=True)

        if y.size == 0:
            raise ValueError("empty audio")

        zcr = float(np.mean(librosa.feature.zero_crossing_rate(y)))
        flatness = float(np.mean(librosa.feature.spectral_flatness(y=y)))
        energy_std = float(np.std(np.abs(y)))

        max_amp = float(np.max(np.abs(y))) + 1e-6
        threshold = 0.02 * max_amp
        silence_ratio = float(np.mean(np.abs(y) < threshold))

        score = 0

        if energy_std < 0.02:
            score += 1

        if flatness < 0.1:
            score += 1

        if silence_ratio < 0.2:
            score += 1

        voice_nature = "possibly_synthetic" if score >= 2 else "likely_human"

        return {
            "status": "ok",
            "voice_nature": voice_nature,
            "zcr": zcr,
            "flatness": flatness,
            "energy_std": energy_std,
            "silence_ratio": silence_ratio,
        }

    except Exception:
        return {
            "status": "error",
            "voice_nature": "unknown",
        }


def analyze_audio_combined(audio_bytes: bytes):
    gemini_res = analyze_audio_with_gemini(audio_bytes)
    librosa_res = analyze_audio_with_librosa(audio_bytes)
    return gemini_res, librosa_res


def scan_file_with_virustotal(file_bytes: bytes, filename: str, mime_type: str) -> str:
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal key missing."

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (filename, file_bytes, mime_type)}

    try:
        upload = requests.post(url, headers=headers, files=files).json()
        analysis_id = upload["data"]["id"]

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        for _ in range(10):
            result = requests.get(analysis_url, headers=headers).json()
            attributes = result["data"]["attributes"]

            status = attributes.get("status")
            stats = attributes.get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)

            if status == "completed":
                risk = "High" if malicious > 0 or suspicious > 0 else "Low"

                return (
                    "VirusTotal scan finished.\n"
                    f"Malicious engines: {malicious}\n"
                    f"Suspicious engines: {suspicious}\n"
                    f"Undetected: {undetected}\n"
                    f"Risk: {risk}"
                )

            time.sleep(3)

        return "VirusTotal scan still running."

    except Exception:
        return "VirusTotal scan failed."


@app.get("/health")
def health():
    return {"status": "running"}


@app.get("/webhook")
async def verify_webhook(request: Request):
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return PlainTextResponse(challenge or "")

    raise HTTPException(status_code=403, detail="verification failed")


@app.post("/webhook")
async def webhook(request: Request):
    body = await request.json()

    try:
        value = body["entry"][0]["changes"][0]["value"]

        if "messages" not in value:
            return {"status": "ignored"}

        msg = value["messages"][0]
        msg_id = msg["id"]

        if msg_id in processed_messages:
            return {"status": "duplicate_ignored"}

        processed_messages.append(msg_id)

        from_number = msg["from"]
        msg_type = msg["type"]

        if msg_type == "text":
            text = msg["text"]["body"].strip()
            lower = text.lower()

            is_url = (
                lower.startswith("/url")
                or lower.startswith("url ")
                or "http://" in lower
                or "https://" in lower
            )

            if is_url:
                url = text.replace("/url", "").replace("URL", "").strip()

                send_whatsapp_text(from_number, "Scanning link...")

                res = analyze_url_with_gemini(url)

                reply = (
                    "Link check result\n\n"
                    f"Risk: {res.risk_level}\n"
                    f"Reason: {res.reason}\n"
                    f"Advice: {res.suggestion}"
                )

                send_whatsapp_text(from_number, reply)

            else:
                send_menu(from_number)

        elif msg_type == "document":
            doc = msg["document"]

            file_id = doc["id"]
            mime = doc["mime_type"]
            name = doc["filename"]

            send_whatsapp_text(from_number, "Downloading file...")

            file_bytes = download_whatsapp_media(file_id)

            if "pdf" in mime:
                send_whatsapp_text(from_number, "Analysing PDF...")

                res = analyze_pdf_with_gemini(file_bytes)

                reply = (
                    "Document check result\n\n"
                    f"Risk: {res.risk_level}\n"
                    f"Reason: {res.reason}\n"
                    f"Advice: {res.suggestion}"
                )
                send_whatsapp_text(from_number, reply)
            else:
                vt_text = scan_file_with_virustotal(file_bytes, name, mime)
                send_whatsapp_text(from_number, vt_text)
        elif msg_type == "audio":
            audio_id = msg["audio"]["id"]
            send_whatsapp_text(from_number, "Processing audio...")
            audio_bytes = download_whatsapp_media(audio_id)
            gemini_res, librosa_res = analyze_audio_combined(audio_bytes)
            vn = librosa_res.get("voice_nature", "unknown")
            if vn == "possibly_synthetic":
                voice_line = "Voice pattern: Possibly AI-generated."
            elif vn == "likely_human":
                voice_line = "Voice pattern: Likely human."
            else:
                voice_line = "Voice pattern: Unknown."
            reply = (
                "Call or Voice check result\n\n"
                f"Scam risk: {gemini_res.risk_level}\n"
                f"Reason: {gemini_res.reason}\n"
                f"Advice: {gemini_res.suggestion}\n\n"
                f"{voice_line}"
            )

            send_whatsapp_text(from_number, reply)
    except Exception as e:
        print("Webhook error:", e)
    return {"status": "ok"}