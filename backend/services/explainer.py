"""Turns raw findings into a plain-language explanation and next steps.

Uses Claude when ANTHROPIC_API_KEY is set (and the `anthropic` package is installed);
otherwise falls back to a template so the app never depends on an external service.
"""
import os

ADVICE = {
    "dangerous": [
        "Don’t open the link or reply to the message.",
        "Never enter passwords, OTPs or card details on this page.",
        "If it claims to be from your bank or an employer, contact them using the number on their official website.",
        "Report it: in India, use cybercrime.gov.in or call 1930 if you lost money.",
    ],
    "suspicious": [
        "Don’t click yet. Open the official website by typing its address yourself.",
        "Check the sender or domain carefully for small spelling changes.",
        "If you’re unsure, ask the person or company through another channel.",
    ],
    "safe": [
        "No warning signs found, but stay careful with any page that asks for passwords or payments.",
        "Check for the padlock and make sure the address matches the site you expect.",
    ],
}
LEAD = {
    "dangerous": "This looks like phishing.",
    "suspicious": "This has several warning signs.",
    "safe": "This looks safe.",
}


def _template(result):
    reasons = result["reasons"][:3]
    text = LEAD[result["verdict"]]
    if result["verdict"] != "safe" and reasons:
        text += " " + " ".join(r.rstrip(".") + "." for r in reasons)
    return text


def _claude(result):
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=key)
        facts = "\n".join(f"- {r}" for r in result["reasons"])
        msg = client.messages.create(
            model=os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"),
            max_tokens=220,
            system=(
                "You explain phishing scan results to non-technical users. Use 2-3 short plain sentences, "
                "no jargon, no markdown. Only use the facts provided; never invent details."
            ),
            messages=[{
                "role": "user",
                "content": f"Scan type: {result['kind']}\nVerdict: {result['verdict']} (risk {result['score']}/100)\nFindings:\n{facts}",
            }],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip() or None
    except Exception:
        return None


def explain(result):
    return {
        "explanation": _claude(result) or _template(result),
        "advice": ADVICE[result["verdict"]],
    }
