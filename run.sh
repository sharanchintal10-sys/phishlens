#!/usr/bin/env bash
# One-command setup and start (Linux/macOS). Windows: run the steps in README.md.
set -e
cd "$(dirname "$0")"
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -q -r backend/requirements.txt
[ -f backend/models/url_model.joblib ] || python ml/train_url_model.py
[ -f backend/models/text_model.joblib ] || python ml/train_text_model.py
cd backend && uvicorn main:app --reload --port 8000
