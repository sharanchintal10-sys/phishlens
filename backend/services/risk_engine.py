"""Combines link analysis, message analysis and threat intel into one risk score."""
import re
from pathlib import Path

import joblib

from . import content_analyzer as ca
from . import db, explainer
from . import threat_intel as ti
from . import url_features as uf

MODELS = Path(__file__).resolve().parents[1] / "models"
_cache = {}


def _load(name):
    if name not in _cache:
        path = MODELS / name
        _cache[name] = joblib.load(path) if path.exists() else None
    return _cache[name]


def reload_models():
    _cache.clear()


def verdict_for(pct):
    return "dangerous" if pct >= 65 else "suspicious" if pct >= 35 else "safe"


def _url_model_score(feats):
    bundle = _load("url_model.joblib")
    if not bundle:
        return None
    row = [[feats[n] for n in bundle["features"]]]
    return float(bundle["model"].predict_proba(row)[0][1])


def _score_url(url):
    feats, info = uf.extract(url)
    h_score, h_find = uf.heuristic(feats, info)
    m_score = _url_model_score(feats)
    link = h_score if m_score is None else 0.4 * h_score + 0.6 * m_score
    intel = ti.analyze(info, url)

    score = 1 - (1 - link) * (1 - intel["score"])
    if intel["blocklisted"]:
        score = max(score, 0.97)
    elif intel["allowlisted"]:
        score = min(score, 0.05)
    elif intel["trusted"]:
        score = min(score, 0.08)

    if feats["shortener"] and not (intel["blocklisted"] or intel["allowlisted"]):
        score = max(score, 0.38)  # destination is hidden, so never call it plainly safe

    findings = intel["findings"] + ([] if intel["trusted"] or intel["allowlisted"] else h_find)
    return {
        "url": url, "score": score, "link": link, "intel": intel["score"], "model": m_score,
        "findings": findings, "info": info,
        "anatomy": {k: info[k] for k in ("scheme", "subdomain", "domain", "path")},
    }


def _finish(kind, target, score, signals, findings, anatomy=None, extra=None):
    pct = round(score * 100)
    verdict = verdict_for(pct)
    if not findings and verdict == "safe":
        findings = ["No warning signs found in the link, the wording or the threat checks"]
    result = {
        "kind": kind, "target": target[:500], "score": pct, "verdict": verdict,
        "signals": {k: round(v * 100) for k, v in signals.items()},
        "reasons": findings[:8], "anatomy": anatomy,
    }
    result.update(extra or {})
    result.update(explainer.explain(result))
    result["id"] = db.add_scan(kind, target, pct, verdict)
    return result


def scan_url(url, kind="url", extra=None):
    r = _score_url(url)
    return _finish(kind, url, r["score"], {"link": r["link"], "intel": r["intel"]}, r["findings"], r["anatomy"], extra)


def scan_text(text, kind="text", extra=None):
    c = ca.analyze(text, _load("text_model.joblib"))
    results = [_score_url(u) for u in c["urls"][:5]]
    worst = max(results, key=lambda r: r["score"], default=None)
    link = worst["score"] if worst else 0.0
    score = 1 - (1 - c["score"]) * (1 - 0.9 * link)

    findings = list(c["findings"])
    for r in results:
        if r["score"] >= 0.35 and r["findings"]:
            findings.append(f"Link to {r['info']['host']}: {r['findings'][0]}")
    links = [{"url": r["url"], "score": round(r["score"] * 100)} for r in results]
    return _finish(
        kind, text, score, {"wording": c["score"], "link": link}, findings,
        worst["anatomy"] if worst else None, {**(extra or {}), "links": links},
    )


def decode_qr(data: bytes) -> str:
    import cv2
    import numpy as np

    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("That file isn’t a readable image.")
    detector = cv2.QRCodeDetector()
    value, _, _ = detector.detectAndDecode(img)
    if not value:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        big = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        value, _, _ = detector.detectAndDecode(big)
    if not value:
        raise ValueError("No QR code found. Try a sharper, closer photo.")
    return value


def scan_qr(data: bytes):
    payload = decode_qr(data)
    extra = {"decoded": payload}
    if payload.lower().startswith("upi://"):
        return _finish(
            "qr", payload, 0.4, {"link": 0.4},
            ["This is a UPI payment code. Scanning it sends money; you never need to scan a code to receive money."],
            None, extra,
        )
    if re.match(r"^(https?://|www\.)", payload, re.I) or re.match(r"^[\w-]+(\.[\w-]+)+(/|$)", payload):
        return scan_url(payload, kind="qr", extra=extra)
    return scan_text(payload, kind="qr", extra=extra)


def learn_from_feedback(scan_id, kind, target, user_label, predicted):
    domain = None
    if kind in ("url", "qr") and target:
        domain = uf.extract(target)[1]["domain"]
    db.add_feedback(scan_id, kind, target, user_label, predicted, domain)
