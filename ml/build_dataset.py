import random
import string
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "backend" / "data" / "raw"
rng = random.Random(1)

def read_urls(path):
    if not path.exists():
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.startswith("http") and len(l) < 400]

phish = sorted(set(read_urls(RAW / "openphish.txt")) | set(read_urls(RAW / "phishing_db.txt")))
tranco = pd.read_csv(RAW / "tranco.csv", header=None, names=["rank", "domain"])
domains = tranco["domain"].head(100000).tolist()

n = min(len(phish), 20000)
phish = rng.sample(phish, n)

WORDS = ("india pune weather update heavy rain expected week market report city government school college "
         "review launch price new best guide how to learn python data science budget cricket match results "
         "festival travel food recipe health tips technology startup funding election policy railway "
         "airport metro traffic news today live").split()

def slug(k=None):
    return "-".join(rng.choice(WORDS) for _ in range(k or rng.randint(3, 10)))

def rid(k=None):
    return "".join(rng.choice(string.digits) for _ in range(k or rng.randint(5, 9)))

def token(k=11):
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(k))

PATH_MAKERS = [
    lambda: "",
    lambda: "/",
    lambda: "/login",
    lambda: "/signin?next=/home",
    lambda: "/account/settings",
    lambda: "/support",
    lambda: "/billing/invoices",
    lambda: f"/news/{rng.choice(['national','world','sports','business','city'])}/{slug()}/article{rid()}.ece",
    lambda: f"/{rng.choice(['news','story','article','blog'])}/{rng.randint(2019,2026)}/{rng.randint(1,12):02d}/{slug()}",
    lambda: f"/products/{slug(4)}-{rid(6)}",
    lambda: f"/watch?v={token()}&list=PL{token(10)}&index={rng.randint(1,30)}&t={rng.randint(5,900)}s",
    lambda: f"/search?q={slug(3).replace('-', '+')}&page={rng.randint(1,9)}&sort=relevance",
    lambda: f"/{slug(2)}/{slug(3)}/{rid()}",
    lambda: f"/en/docs/{slug(2)}/getting-started#{slug(2)}",
    lambda: f"/restaurants/{slug(3)}-{rid(6)}?utm_source={rng.choice(['newsletter','twitter','google'])}&utm_medium=social",
]

good = []
for d in rng.sample(domains, n):
    host = ("www." if rng.random() < 0.45 else "") + d
    scheme = "http" if rng.random() < 0.08 else "https"
    good.append(f"{scheme}://{host}{rng.choice(PATH_MAKERS)()}")

df = pd.DataFrame({"url": phish + good, "label": [1] * n + [0] * n}).sample(frac=1, random_state=1)
df.to_csv(ROOT / "backend" / "data" / "urls.csv", index=False)
print(f"Wrote {len(df)} rows ({n} phishing, {n} legitimate)")
