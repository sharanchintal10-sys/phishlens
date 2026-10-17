"""Message-content analysis: social-engineering cues plus an optional trained text model."""
import re

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.I)

# name: (regex, weight, explanation)
PATTERNS = {
    "urgency": (r"\b(urgent(ly)?|immediately|within \d+ (hours?|minutes?)|act now|last warning|final notice|expires? (today|soon|in)|right away|asap|limited time)\b", 0.18, "It pressures you to act immediately"),
    "credentials": (r"\b(verify your (account|identity|password|details)|confirm your (password|identity|account|details)|enter your (password|otp|pin|card)|log ?in (here|now)|sign ?in (here|now)|update your (payment|billing|account|kyc)|re-?activate)\b", 0.28, "It asks you to verify or enter account details"),
    "threat": (r"\b(suspended|locked|blocked|terminated|deactivated|unauthori[sz]ed|unusual (activity|sign.?in)|legal action|arrest|penalty)\b", 0.2, "It threatens an account problem or a penalty"),
    "reward": (r"\b(you(’|')?ve won|winner|prize|lottery|gift card|free (iphone|gift)|cashback|claim your|refund)\b", 0.2, "It promises a prize, cashback or refund"),
    "sensitive": (r"\b(otp|cvv|pin|password|aadhaar|pan card|card number|bank details|upi pin)\b", 0.15, "It mentions sensitive details such as OTP, PIN or password"),
    "generic": (r"\b(dear (customer|user|member|client|sir|madam)|valued customer)\b", 0.1, "It uses a generic greeting instead of your name"),
    "payment": (r"\b(wire transfer|gift cards?|bitcoin|crypto|western union|pay (the )?(fee|fine|charges))\b", 0.2, "It asks for an unusual form of payment"),
    "authority": (r"\b(income tax|police|customs|security team|it department|helpdesk|bank manager)\b", 0.08, "It claims to come from an authority"),
}
_COMPILED = {k: (re.compile(rx, re.I), w, msg) for k, (rx, w, msg) in PATTERNS.items()}


def extract_urls(text):
    seen, out = set(), []
    for u in URL_RE.findall(text):
        u = u.rstrip(".,;:!?")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def analyze(text, model=None):
    findings, remain = [], 1.0
    for _, (rx, weight, msg) in _COMPILED.items():
        if rx.search(text):
            remain *= 1 - weight
            findings.append(msg)

    letters = [c for c in text if c.isalpha()]
    if len(letters) > 30 and sum(c.isupper() for c in letters) / len(letters) > 0.45:
        remain *= 0.9
        findings.append("It is written mostly in capital letters")
    if text.count("!") >= 3:
        remain *= 0.95
        findings.append("It uses a lot of exclamation marks")

    rules = 1 - remain
    score = rules
    model_score = None
    if model is not None:
        try:
            model_score = float(model.predict_proba([text])[0][1])
            score = 0.5 * rules + 0.5 * model_score
            if model_score >= 0.8 and not findings:
                findings.append("The wording closely matches known phishing messages")
        except Exception:
            pass
    return {"score": min(1.0, score), "rules": rules, "model": model_score, "findings": findings, "urls": extract_urls(text)}
