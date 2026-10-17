"""PhishLens API.  Run:  uvicorn main:app --reload --port 8000"""
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from services import db, risk_engine

app = FastAPI(title="PhishLens", version="1.0", description="Real-time phishing detection API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class UrlIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class TextIn(BaseModel):
    text: str = Field(min_length=3, max_length=20000)


class FeedbackIn(BaseModel):
    scan_id: Optional[int] = None
    kind: str = Field(pattern="^(url|text|qr)$")
    target: str = Field(max_length=2048)
    user_label: str = Field(pattern="^(phishing|safe)$")
    predicted: str = ""


@app.get("/health")
def health():
    return {
        "ok": True,
        "url_model": risk_engine._load("url_model.joblib") is not None,
        "text_model": risk_engine._load("text_model.joblib") is not None,
    }


@app.post("/scan-url")
def scan_url(body: UrlIn):
    return risk_engine.scan_url(body.url)


@app.post("/scan-text")
def scan_text(body: TextIn):
    return risk_engine.scan_text(body.text)


@app.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(413, "Image is larger than 8 MB.")
    try:
        return risk_engine.scan_qr(data)
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.post("/feedback")
def feedback(body: FeedbackIn):
    risk_engine.learn_from_feedback(body.scan_id, body.kind, body.target, body.user_label, body.predicted)
    return {"ok": True}


@app.get("/history")
def history(limit: int = 50):
    return db.history(min(limit, 200))


@app.get("/stats")
def stats():
    return db.stats()


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
