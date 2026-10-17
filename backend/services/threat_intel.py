"""Threat-intelligence layer: blocklists, brand impersonation, Safe Browsing, domain age."""
import difflib
import os
import re
from functools import lru_cache
from pathlib import Path

import requests

from . import db

DATA = Path(__file__).resolve().parents[1] / "data"

# brand keyword -> official registered domains
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "dropbox": {"dropbox.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "sbi": {"onlinesbi.sbi", "sbi.co.in"},
    "irctc": {"irctc.co.in"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}
TRUSTED = set().union(*BRANDS.values()) | {
    "wikipedia.org", "twitter.com", "x.com", "openai.com", "anthropic.com", "claude.ai",
    "stackoverflow.com", "reddit.com", "python.org", "flipkart.com", "zoom.us", "slack.com",
    "oracle.com", "mozilla.org", "bbc.com", "nytimes.com", "medium.com", "gov.in", "nic.in",
}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
BRAND_SUFFIXES = {"secure", "login", "support", "verify", "account", "help", "service", "pay", "bank", "online", "update", "care", "alert"}


@lru_cache(maxsize=1)
def _static_blocklist():
    path = DATA / "blocklist.txt"
    if not path.exists():
        return frozenset()
    return frozenset(
        line.strip().lower() for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    )


def brand_check(info):
    """Return (risk, findings) if the domain imitates a known brand."""
    reg, label, sub = info["domain"], info["label"], info["subdomain"].lower()
    if reg in TRUSTED:
        return 0.0, []
    parts = [p for p in re.split(r"[-_]", label.translate(LEET)) if p]
    path = info["path"].lower()
    for brand, official in BRANDS.items():
        match = None
        for part in parts:
            if part == brand:
                match = "name"
            elif len(brand) >= 5 and part.startswith(brand) and part[len(brand):] in BRAND_SUFFIXES:
                match = "name"
            elif len(brand) >= 5 and part != brand and difflib.SequenceMatcher(None, part, brand).ratio() >= 0.84:
                match = "lookalike"
            if match:
                break
        if match:
            real = sorted(official)[0]
            return 0.6, [f"The domain imitates {brand.title()} but isn’t an official {brand.title()} site (the real one is {real})"]
        if brand in sub:
            return 0.6, [f"{brand.title()} appears in the subdomain, but the real website is ‘{reg}’"]
        if brand in path:
            return 0.35, [f"{brand.title()} is mentioned in the page path of an unrelated site (‘{reg}’)"]
    return 0.0, []


def safe_browsing_hit(url):
    key = os.getenv("GSB_API_KEY")
    if not key:
        return None
    body = {
        "client": {"clientId": "phishlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=3)
        return bool(r.json().get("matches"))
    except Exception:
        return None


@lru_cache(maxsize=512)
def domain_age_days(domain):
    if os.getenv("ENABLE_WHOIS") != "1":
        return None
    try:
        import datetime
        import whois  # python-whois

        created = whois.whois(domain).creation_date
        created = created[0] if isinstance(created, list) else created
        return (datetime.datetime.now() - created).days if created else None
    except Exception:
        return None


def analyze(info, url):
    out = {"score": 0.0, "findings": [], "blocklisted": False, "allowlisted": False, "trusted": False}
    reg = info["domain"]

    learned = db.learned_label(reg)
    if learned == "allow":
        out.update(allowlisted=True, findings=["This site was marked safe by user feedback"])
        return out
    if learned == "block" or reg in _static_blocklist():
        out.update(score=1.0, blocklisted=True, findings=["This domain is on the phishing blocklist"])
        return out

    if safe_browsing_hit(url):
        out.update(score=1.0, blocklisted=True, findings=["Google Safe Browsing flags this page as unsafe"])
        return out

    risk, findings = brand_check(info)
    out["score"], out["findings"] = risk, findings

    age = domain_age_days(reg)
    if age is not None:
        if age < 30:
            out["score"] = 1 - (1 - out["score"]) * 0.6
            out["findings"].append(f"The domain was registered only {age} days ago")
        elif age < 180:
            out["score"] = 1 - (1 - out["score"]) * 0.85
            out["findings"].append("The domain is less than six months old")

    out["trusted"] = reg in TRUSTED
    return out
