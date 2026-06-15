from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from joblib import load
from pydantic import BaseModel, Field

from .feature_extractor import FEATURE_NAMES, extract_many, load_tld_stats


ROOT_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT_DIR / "lgb_model.joblib"
TLD_STATS_PATH = Path(__file__).resolve().parent / "tld_stats.json"
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"
DEMO_PATH = ROOT_DIR / "demo" / "sms_guard.html"

DEFAULT_THRESHOLD = 0.5119020229513724
MAX_ROWS_PER_REQUEST = 50_000

app = FastAPI(title="Malicious URL Detector", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = load(MODEL_PATH)
tld_stats = load_tld_stats(TLD_STATS_PATH)


class PredictRequest(BaseModel):
    urls: list[str] = Field(min_length=1)
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)


def current_threshold(value: float | None) -> float:
    return DEFAULT_THRESHOLD if value is None else value


def read_uploaded_table(file: UploadFile, content: bytes) -> pd.DataFrame:
    filename = (file.filename or "").lower()
    stream = BytesIO(content)

    if filename.endswith(".csv"):
        return pd.read_csv(stream)
    if filename.endswith((".xlsx", ".xls")):
        return pd.read_excel(stream)

    raise HTTPException(status_code=400, detail="Format file harus .csv, .xlsx, atau .xls.")


def find_url_column(df: pd.DataFrame) -> str | None:
    normalized = {str(column).strip().lower(): column for column in df.columns}
    for candidate in ["url", "urls", "link", "website"]:
        if candidate in normalized:
            return normalized[candidate]
    return None


def dataframe_from_input(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    has_model_features = all(feature in df.columns for feature in FEATURE_NAMES)
    if has_model_features:
        features = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
        urls = df[find_url_column(df)].astype(str).tolist() if find_url_column(df) else [""] * len(df)
        return features, urls

    url_column = find_url_column(df)
    if url_column is None:
        raise HTTPException(
            status_code=400,
            detail="File harus memiliki kolom URL bernama url, urls, link, atau website.",
        )

    urls = df[url_column].dropna().astype(str).tolist()
    if not urls:
        raise HTTPException(status_code=400, detail="Kolom URL kosong.")
    return extract_many(urls, tld_stats), urls


def predict_features(features: pd.DataFrame, urls: list[str], threshold: float) -> dict[str, Any]:
    if len(features) > MAX_ROWS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"Maksimum {MAX_ROWS_PER_REQUEST:,} URL per request.",
        )

    probabilities = model.predict(features[FEATURE_NAMES])
    labels = (probabilities >= threshold).astype(int)

    results = []
    for index, (url, probability, label) in enumerate(zip(urls, probabilities, labels), start=1):
        risk_label = "Malicious" if int(label) == 1 else "Not Malicious"
        results.append(
            {
                "id": index,
                "url": url,
                "probability": round(float(probability), 6),
                "percentage": round(float(probability) * 100, 2),
                "predicted_label": int(label),
                "risk_label": risk_label,
            }
        )

    malicious_count = int(np.sum(labels))
    total = len(results)
    average_probability = float(np.mean(probabilities)) if total else 0.0

    return {
        "threshold": threshold,
        "total": total,
        "malicious": malicious_count,
        "not_malicious": total - malicious_count,
        "average_probability": round(average_probability, 6),
        "results": results,
    }


@app.get("/demo")
def demo() -> FileResponse:
    if DEMO_PATH.exists():
        return FileResponse(DEMO_PATH)
    raise HTTPException(status_code=404, detail="Demo SMS Guard tidak ditemukan.")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model": "LightGBM",
        "features": len(FEATURE_NAMES),
        "threshold": DEFAULT_THRESHOLD,
        "tld_stats_loaded": bool(tld_stats.get("tld_freq")),
    }


@app.post("/api/predict")
def predict(payload: PredictRequest) -> dict[str, Any]:
    urls = [url for url in payload.urls if str(url).strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="Masukkan minimal satu URL.")

    features = extract_many(urls, tld_stats)
    return predict_features(features, urls, current_threshold(payload.threshold))


@app.post("/api/predict-file")
async def predict_file(
    file: UploadFile = File(...),
    threshold: float | None = Form(default=None),
) -> dict[str, Any]:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="File kosong.")

    df = read_uploaded_table(file, content)
    if df.empty:
        raise HTTPException(status_code=400, detail="File tidak memiliki data.")

    features, urls = dataframe_from_input(df)
    response = predict_features(features, urls, current_threshold(threshold))
    response["filename"] = file.filename
    return response


if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/{full_path:path}")
def serve_frontend(full_path: str) -> FileResponse:
    index_path = FRONTEND_DIST / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="Frontend belum dibuild. Jalankan npm run build.")
