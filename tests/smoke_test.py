"""Quick end-to-end check of the scoring pipeline (no web server needed).  python tests/smoke_test.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from services import risk_engine as R  # noqa: E402

URLS = [
    ("https://www.google.com/search?q=python", "safe"),
    ("https://github.com/login", "safe"),
    ("https://nptel.ac.in/courses", "safe"),
    ("http://paypa1-secure-login.xyz/verify/account", "dangerous"),
    ("http://192.168.10.5/signin.php?session=ab12cd", "dangerous"),
    ("https://paypal.com.account-verify.top/login", "dangerous"),
    ("https://sbi-kyc-update.online/kyc", "dangerous"),
    ("https://bit.ly/3xAmple", "suspicious"),
]
TEXTS = [
    ("Hi team, the sprint review is at 3pm tomorrow. Agenda is in the shared doc.", "safe"),
    ("Your OTP is 482913. Do not share it with anyone.", "safe"),
    ("URGENT: Dear customer, your bank account is suspended. Verify your account immediately at http://hdfc-secure-kyc.xyz/login or it will be blocked.", "dangerous"),
]

ok = True
for url, want in URLS:
    r = R.scan_url(url)
    flag = "OK " if r["verdict"] == want else "?? "
    ok &= r["verdict"] == want
    print(f"{flag}{r['score']:>3} {r['verdict']:<10} {url}")
for text, want in TEXTS:
    r = R.scan_text(text)
    flag = "OK " if r["verdict"] == want else "?? "
    ok &= r["verdict"] == want
    print(f"{flag}{r['score']:>3} {r['verdict']:<10} {text[:70]}")
print("\nALL AS EXPECTED" if ok else "\nSOME DIFFER, review above")
