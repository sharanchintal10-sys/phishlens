"""Synthetic training data so the project runs out of the box.

Replace with real data for any serious evaluation: put a CSV with columns `url,label`
(1 = phishing, 0 = legitimate) at backend/data/urls.csv, e.g. built from PhishTank/OpenPhish
(phishing) and Tranco top sites (legitimate). Likewise `text,label` at backend/data/emails.csv.
"""
import random
import string

GOOD = ["google.com", "wikipedia.org", "github.com", "amazon.in", "flipkart.com", "irctc.co.in", "microsoft.com",
        "apple.com", "youtube.com", "linkedin.com", "stackoverflow.com", "python.org", "medium.com", "bbc.com",
        "nytimes.com", "reddit.com", "zoom.us", "slack.com", "oracle.com", "mozilla.org", "paypal.com", "netflix.com",
        "hdfcbank.com", "icicibank.com", "onlinesbi.sbi", "swiggy.com", "zomato.com", "coursera.org", "udemy.com",
        "nptel.ac.in", "mit.edu", "nic.in", "sppu.ac.in", "cloudflare.com", "dropbox.com", "notion.so", "figma.com"]
GOOD_PATHS = ["", "/", "/login", "/account/settings", "/support", "/search?q=python+tutorial", "/products/12345",
              "/blog/how-to-learn-sql", "/en/docs/getting-started", "/signin?next=/dashboard", "/wiki/Phishing",
              "/billing/invoices", "/help/contact-us", "/watch?v=dQw4w9WgXcQ", "/2024/05/new-features-announced"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook", "whatsapp", "sbi", "hdfc", "icici",
          "paytm", "irctc", "linkedin", "dhl", "fedex", "instagram", "dropbox"]
KW = ["login", "secure", "verify", "account", "update", "signin", "support", "billing", "confirm", "wallet", "kyc", "refund"]
BAD_TLD = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "support", "online", "site", "icu", "buzz"]
OK_TLD = ["com", "net", "info", "org", "co", "in"]
PHISH_PATHS = ["/login", "/verify/account", "/secure/update?id={n}", "/signin.php?session={r}", "/auth/confirm?token={r}",
               "/account/recover", "/kyc/update.html", "/wp-includes/login/index.php", "/", "/webscr?cmd=_login&id={n}"]
LEET = {"o": "0", "l": "1", "e": "3", "a": "4", "i": "1"}


def _rand(rng, n=8):
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _leet(rng, word):
    chars = list(word)
    idx = [i for i, c in enumerate(chars) if c in LEET]
    if idx:
        i = rng.choice(idx)
        chars[i] = LEET[chars[i]]
    return "".join(chars)


def benign(rng):
    host = rng.choice(GOOD)
    if rng.random() < 0.35:
        host = rng.choice(["www", "mail", "docs", "support", "accounts", "blog", "m"]) + "." + host
    scheme = "http" if rng.random() < 0.12 else "https"
    path = rng.choice(GOOD_PATHS)
    if rng.random() < 0.15:
        path += "?utm_source=newsletter&utm_campaign=" + _rand(rng, 6)
    return f"{scheme}://{host}{path}"


def phishing(rng):
    brand, kw = rng.choice(BRANDS), rng.choice(KW)
    tld = rng.choice(BAD_TLD + OK_TLD)
    style = rng.randint(0, 9)
    if style == 0:
        host = f"{brand}-{kw}.{tld}"
    elif style == 1:
        host = f"{brand}.{kw}-{rng.choice(KW)}.{tld}"
    elif style == 2:
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4))
    elif style == 3:
        host = f"{brand}.com.{kw}-{_rand(rng, 5)}.{tld}"
    elif style == 4:
        host = f"{_leet(rng, brand)}-{kw}.{tld}"
    elif style == 5:
        host = f"{kw}{brand}{rng.randint(1, 999)}.{tld}"
    elif style == 6:
        host = f"secure.{kw}.{brand}-{_rand(rng, 4)}.{tld}"
    elif style == 7:
        host = f"xn--{_rand(rng, 7)}.{tld}"
    elif style == 8:
        host = f"{brand}{kw}.{tld}"
    else:
        host = f"{_leet(rng, brand)}.{_rand(rng, 6)}.{tld}"
    path = rng.choice(PHISH_PATHS).format(n=rng.randint(1000, 99999), r=_rand(rng, 14))
    scheme = "https" if rng.random() < 0.6 else "http"
    url = f"{scheme}://{host}{path}"
    if rng.random() < 0.08:
        url = f"{scheme}://{brand}.com@{host}{path}"
    return url


def urls(n_each=2500, seed=7):
    rng = random.Random(seed)
    rows = [(benign(rng), 0) for _ in range(n_each)] + [(phishing(rng), 1) for _ in range(n_each)]
    rng.shuffle(rows)
    return rows


# ---------------- text -----------------
P_OPEN = ["Dear customer,", "Dear user,", "Hello valued member,", "ALERT:", "Final notice:", "Security team here.", "Attention,", "Dear account holder,"]
P_THREAT = ["Your account has been suspended due to unusual activity.", "We detected an unauthorized sign-in to your account.",
            "Your KYC is incomplete and your account will be blocked.", "Your payment failed and your subscription will be terminated.",
            "A package could not be delivered and will be returned.", "Your mailbox storage is full and emails will be deleted.",
            "You have won a cash prize in our lottery.", "Your income tax refund is ready to be credited.",
            "Your bank account will be locked within 24 hours."]
P_ASK = ["Verify your account immediately at {u}", "Click here to confirm your password: {u}", "Update your details now: {u}",
         "Log in here to avoid suspension: {u}", "Share your OTP to complete verification.", "Claim your reward here: {u}",
         "Pay the small fee via gift card to release your funds.", "Confirm your card number and PIN to continue."]
P_LINKS = ["http://secure-login-verify.xyz/auth", "http://bit.ly/3xAmple", "https://paypa1-support.top/login", "http://192.168.44.12/verify"]
B_TEXT = ["Hi team, the sprint review is moved to 3pm tomorrow. Agenda is in the shared doc.",
          "Your order #48213 has shipped and will arrive on Thursday. Track it in the app.",
          "Thanks for your payment of the electricity bill. Your receipt is attached.",
          "Reminder: your dentist appointment is on Monday at 10:30 am.",
          "Your OTP is 482913. Do not share it with anyone. It is valid for 10 minutes.",
          "Hey, are we still on for lunch on Saturday? Let me know what time works.",
          "Weekly newsletter: five new tutorials on Python, SQL and data visualization.",
          "Your monthly statement is ready. Sign in to the official app to view it.",
          "Congrats on the new job! Let's catch up this weekend.",
          "The library book you reserved is available for pickup until Friday.",
          "Please find attached the minutes of today's meeting. Action items are highlighted.",
          "Your flight check-in opens 24 hours before departure. Have a great trip!",
          "Assignment 3 is due on Friday. Office hours are on Wednesday from 2 to 4 pm.",
          "We have updated our privacy policy. No action is needed from you."]


def texts(n_each=500, seed=11):
    rng = random.Random(seed)
    rows = []
    for _ in range(n_each):
        parts = [rng.choice(P_OPEN), rng.choice(P_THREAT), rng.choice(P_ASK).format(u=rng.choice(P_LINKS))]
        if rng.random() < 0.5:
            parts.insert(2, rng.choice(["Act now.", "This is urgent.", "You have 24 hours.", "Failure to respond will result in penalty."]))
        rows.append((" ".join(parts), 1))
    for _ in range(n_each):
        t = rng.choice(B_TEXT)
        if rng.random() < 0.3:
            t += " " + rng.choice(["Thanks!", "Regards, Priya", "See you soon.", "Best, Rahul"])
        rows.append((t, 0))
    rng.shuffle(rows)
    return rows
