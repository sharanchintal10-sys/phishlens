# PhishLens: AI-powered real-time phishing detection

Detects phishing in links, messages (email/SMS/chat) and QR codes, explains the verdict in plain
language, warns users while they browse, and learns from corrections.

```
 Chrome extension ─┐                    ┌─ url_features  (20 URL features + rules)
 Web dashboard ────┼─► FastAPI ─► risk_engine ─┼─ content_analyzer (cues + TF-IDF model)
 QR image upload ──┘   (backend)        │       └─ threat_intel (blocklist, brand look-alikes,
                                        │                        Safe Browsing, domain age)
                                        ├─ ML models: Random Forest (URL), Logistic Regression (text)
                                        ├─ explainer  (template, or Claude if API key set)
                                        └─ SQLite: history, feedback, learned allow/block list
```

## Quick start

```bash
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd .. && python ml/train_url_model.py && python ml/train_text_model.py && cd backend
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000. The dashboard is served by the API. Check everything works without a server:
`python tests/smoke_test.py`.

## Chrome extension

1. Chrome → `chrome://extensions` → turn on **Developer mode** → **Load unpacked** → choose the `extension/` folder.
2. Keep the backend running. Open any site: the badge shows ✓ / ! / ✕, and risky pages get a warning.
3. Deploying the backend elsewhere? Paste its address into the extension popup.

## API

| Method | Path | Body | Purpose |
|---|---|---|---|
| POST | `/scan-url` | `{"url": "..."}` | Score a link |
| POST | `/scan-text` | `{"text": "..."}` | Score a message (also scores links inside it) |
| POST | `/scan-qr` | multipart `file` | Decode a QR image and score its content |
| POST | `/feedback` | `{kind, target, user_label: "phishing"/"safe", scan_id}` | Correction; also updates the learned allow/block list |
| GET | `/history`, `/stats`, `/health` | | Dashboard data |

Interactive docs: http://localhost:8000/docs

## How scoring works

- **Link score** = 0.4 × rule score + 0.6 × Random Forest probability (rules only if no model is trained).
- **Threat intel** covers blocklists, brand look-alikes (`paypa1`, `paypal.com.evil.xyz`), Google Safe Browsing and domain age.
- **Final** = noisy-OR of both. Known-trusted domains are capped low, blocklisted ones high, shortened links never score below *suspicious*.
- **Message score** = 0.5 × social-engineering cues + 0.5 × text model, combined with its worst embedded link.
- Verdicts: under 35 safe, 35–64 suspicious, 65 and above dangerous.

## Adaptive learning

Every “It’s phishing / It’s safe” click is stored. The domain is added to a learned list immediately (latest label wins), and
`python ml/train_url_model.py --feedback` retrains the model with those corrections weighted ×3. Schedule it (cron/GitHub Actions)
for continuous adaptation. In production, require several independent votes or moderation before a domain is blocked or allowed globally.

## Optional configuration (environment variables)

| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` | Explanations written by Claude (needs `pip install anthropic`). Falls back to a template. |
| `GSB_API_KEY` | Enables Google Safe Browsing lookups |
| `ENABLE_WHOIS=1` | Domain-age check (needs `pip install python-whois`; slow, so results are cached) |

## Honest limitations (say these in your presentation)

- **The bundled models are trained on synthetic data** so the project runs immediately. Their 100% test score only shows the pipeline works.
  For real accuracy, put real data in `backend/data/urls.csv` (`url,label`) and `backend/data/emails.csv` (`text,label`) using PhishTank/OpenPhish
  versus Tranco top sites, plus SpamAssassin/Enron and LLM-generated phishing, then retrain and report precision/recall on a held-out set.
- Scoring does not fetch or render the target page, so it cannot see cloned page content. Next step: headless-browser page analysis (forms asking for passwords, logos, hidden iframes).
- Brand list is small; extend `BRANDS` in `threat_intel.py`.
- No authentication or rate limiting on the API. Add both before public deployment.

## Demo script (3 minutes)

1. Scan `https://github.com/login` (safe) and `http://hdfc-secure-kyc.xyz/login` (dangerous). Point at the “real website” breakdown.
2. Paste the Prize SMS example into **Message**. Show wording plus link signals.
3. Upload a QR image of a bad URL.
4. Open a bad link in Chrome with the extension and show the warning page.
5. Mark a false positive as safe, rescan, and show the history page. That is the adaptive loop.

## Deploy

Backend: Render/Railway (`uvicorn main:app --host 0.0.0.0 --port $PORT`, root `backend/`). Since the API serves the dashboard, that is a single deployment.
