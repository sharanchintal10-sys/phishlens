"""Train the message classifier (TF-IDF + logistic regression).

Real data: put `text,label` rows (1=phishing, 0=legit) in backend/data/emails.csv, for example from
SpamAssassin/Enron plus phishing corpora, and add LLM-generated phishing samples so the model sees
polished, AI-written lures too.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import synth_data  # noqa: E402

csv = ROOT / "backend" / "data" / "emails.csv"
if csv.exists():
    df = pd.read_csv(csv)[["text", "label"]]
    print(f"Loaded {len(df)} rows from {csv}")
else:
    df = pd.DataFrame(synth_data.texts(), columns=["text", "label"])
    print(f"No emails.csv found, using {len(df)} synthetic rows (demo only)")

X_tr, X_te, y_tr, y_te = train_test_split(df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"])
pipe = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True),
    LogisticRegression(max_iter=1000, class_weight="balanced"),
)
pipe.fit(X_tr, y_tr)
print(classification_report(y_te, pipe.predict(X_te), target_names=["legit", "phishing"]))

out = ROOT / "backend" / "models" / "text_model.joblib"
out.parent.mkdir(exist_ok=True)
joblib.dump(pipe, out)
print("Saved", out)
