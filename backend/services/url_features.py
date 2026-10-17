"""URL parsing, feature extraction and a rule-based scorer.

The same feature vector feeds the ML model (ml/train_url_model.py) and the
heuristic scorer below, so the app still works before a model is trained.
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "support",
    "zip", "mov", "rest", "country", "kim", "loan", "men", "online", "site", "icu",
    "buzz", "cam", "monster",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}
KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking", "confirm",
    "password", "wallet", "suspend", "unlock", "invoice", "payment", "billing",
    "support", "helpdesk", "recover", "validate", "authenticate", "kyc", "refund",
    "prize", "bonus",
]
MULTI_TLDS = {
    "co.in", "co.uk", "com.au", "co.jp", "com.br", "org.in", "gov.in", "ac.in",
    "net.in", "co.za", "edu.in", "res.in",
}

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "dots", "host_hyphens", "host_digits",
    "subdomains", "has_at", "has_ip", "is_https", "has_punycode", "bad_tld",
    "shortener", "keywords", "host_entropy", "params", "odd_port", "digit_ratio",
    "redirect_in_path", "long_subdomain_chain", "path_keywords",
]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def split_host(host: str):
    """Return (subdomain, registered_domain, tld, main_label)."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, "", host
    if ".".join(labels[-2:]) in MULTI_TLDS and len(labels) >= 3:
        return ".".join(labels[:-3]), ".".join(labels[-3:]), ".".join(labels[-2:]), labels[-3]
    return ".".join(labels[:-2]), ".".join(labels[-2:]), labels[-1], labels[-2]


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) or re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))


def extract(url: str):
    """Return (features: dict, info: dict) for a URL string."""
    u = normalize_url(url)
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        p, host, port = urlparse("http://invalid.invalid"), "invalid.invalid", None

    has_ip = _is_ip(host)
    if has_ip:
        sub, reg, tld, label = "", host, "", host
    else:
        sub, reg, tld, label = split_host(host)
    path_q = p.path + ("?" + p.query if p.query else "")
    haystack = (host + p.path).lower()
    digits = sum(ch.isdigit() for ch in u)
    netloc = u.split("://", 1)[-1].split("/")[0].split("?")[0]

    feats = {
        "url_len": len(u),
        "host_len": len(host),
        "path_len": len(p.path),
        "dots": host.count("."),
        "host_hyphens": host.count("-"),
        "host_digits": sum(ch.isdigit() for ch in host),
        "subdomains": len(sub.split(".")) if sub else 0,
        "has_at": int("@" in netloc),
        "has_ip": int(has_ip),
        "is_https": int(p.scheme == "https"),
        "has_punycode": int("xn--" in host),
        "bad_tld": int(tld in SUSPICIOUS_TLDS),
        "shortener": int(reg in SHORTENERS),
        "keywords": sum(1 for k in KEYWORDS if k in host),
        "host_entropy": round(entropy(label), 3),
        "params": p.query.count("=") if p.query else 0,
        "odd_port": int(port not in (None, 80, 443)),
        "digit_ratio": round(digits / max(len(u), 1), 3),
        "redirect_in_path": int(bool(re.search(r"(https?:|//)", path_q[1:]))),
        "long_subdomain_chain": int(len(sub) > 25),
        "path_keywords": sum(1 for k in KEYWORDS if k in p.path.lower()),
    }
    info = {
        "host": host, "subdomain": sub, "domain": reg, "tld": tld, "label": label,
        "scheme": p.scheme, "path": path_q or "/",
    }
    return feats, info


def heuristic(f: dict, info: dict):
    """Rule-based risk 0..1 plus human-readable findings."""
    pts, findings = 0.0, []

    def add(points, msg):
        nonlocal pts
        pts += points
        findings.append(msg)

    if f["has_ip"]:
        add(0.45, "The link uses a raw IP address instead of a website name")
    if f["has_at"]:
        add(0.35, "The link contains an ‘@’ symbol, which can hide the real destination")
    if f["has_punycode"]:
        add(0.35, "The domain uses look-alike (punycode) characters")
    if f["bad_tld"]:
        add(0.2, f"The ‘.{info['tld']}’ ending is common on throwaway phishing sites")
    if f["shortener"]:
        add(0.2, "A link shortener hides where this really goes")
    if f["keywords"] >= 2:
        add(0.25, "The domain is stuffed with words like login, verify or secure")
    elif f["keywords"] == 1:
        add(0.1, "The domain name contains a sensitive keyword (login, verify, account…)")
    if f["host_hyphens"] >= 2:
        add(0.15, "The domain has several hyphens, a common trick to imitate real brands")
    if f["subdomains"] >= 3:
        add(0.2, "The address has an unusually long chain of subdomains")
    if not f["is_https"]:
        add(0.1, "The page doesn’t use HTTPS")
    if f["host_digits"] >= 4:
        add(0.1, "The domain name contains many digits")
    if f["redirect_in_path"]:
        add(0.15, "Another web address is embedded inside this link")
    if f["odd_port"]:
        add(0.1, "The link uses an unusual network port")
    if f["host_entropy"] > 3.8:
        add(0.1, "The domain name looks randomly generated")
    return min(1.0, pts), findings
