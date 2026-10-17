"""Train the URL classifier.

    python ml/train_url_model.py                # synthetic data (demo)
    python ml/train_url_model.py --feedback     # also learn from corrections stored in the DB

Real data: put `url,label` rows (1=phishing, 0=legit) in backend/data/urls.csv.
"""
import argparse
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from services.url_features import FEATURE_NAMES, extract  # noqa: E402
import synth_data  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--feedback", action="store_true", help="include user feedback from the database")
args = ap.parse_args()

csv = ROOT / "backend" / "data" / "urls.csv"
if csv.exists():
    df = pd.read_csv(csv)[["url", "label"]]
    print(f"Loaded {len(df)} rows from {csv}")
else:
    df = pd.DataFrame(synth_data.urls(), columns=["url", "label"])
    print(f"No urls.csv found, using {len(df)} synthetic rows (demo only)")

if args.feedback:
    from services import db

    rows = [(r["target"], 1 if r["user_label"] == "phishing" else 0) for r in db.feedback_rows()]
    if rows:
        extra = pd.DataFrame(rows, columns=["url", "label"])
        df = pd.concat([df, extra, extra, extra], ignore_index=True)  # weight real corrections x3
        print(f"Added {len(rows)} feedback rows (weighted x3)")

X = [[extract(u)[0][n] for n in FEATURE_NAMES] for u in df["url"]]
y = df["label"].tolist()
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=200, max_depth=14, class_weight="balanced", random_state=42, n_jobs=-1)
model.fit(X_tr, y_tr)
print(classification_report(y_te, model.predict(X_te), target_names=["legit", "phishing"]))
for name, imp in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1])[:8]:
    print(f"  {name:<22}{imp:.3f}")

out = ROOT / "backend" / "models" / "url_model.joblib"
out.parent.mkdir(exist_ok=True)
joblib.dump({"model": model, "features": FEATURE_NAMES}, out)
print("Saved", out)
