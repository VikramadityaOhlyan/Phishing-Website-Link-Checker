"""Scoring: ML model on the hostname + explainable URL rules."""
import re, joblib
from urllib.parse import urlparse
from features import BRANDS, KEYWORDS, parse, to_frame

MODEL = joblib.load("model.joblib")
TRUSTED = set(open("trusted.txt").read().split())
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}

def rule_signals(url: str):
    """URL-level checks a hostname model can't see. Returns [(risk, reason)]."""
    raw = url if "://" in url else "http://" + url
    u = urlparse(raw)
    host, e = parse(raw)
    reg = e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix") else e.registered_domain
    tail = (u.path + "?" + u.query).lower()
    out = []
    if "xn--" in host:
        out.append((0.4, "Uses look-alike (punycode) characters to imitate another site"))
    if u.username is not None:
        out.append((0.8, "Contains '@' — the real destination is hidden after it"))
    if reg in SHORTENERS:
        out.append((0.2, "Link shortener hides the real destination"))
    for b, owners in BRANDS.items():
        if b in tail and reg not in owners:
            risk = 0.55 if any(k in tail for k in KEYWORDS) else 0.35
            out.append((risk, f"Mentions “{b}” in the path but isn't a {b} domain")); break
    if re.search(r"/wp-(content|includes|admin)/", tail) and any(k in tail for k in KEYWORDS):
        out.append((0.3, "Login/verify page inside a WordPress folder (common on hacked sites)"))
    elif sum(k in tail for k in KEYWORDS) >= 2:
        out.append((0.15, "Path asks for login, verification or account details"))
    if u.scheme == "http" and any(k in tail for k in ("login", "signin", "password", "verify")):
        out.append((0.1, "Asks for credentials over unencrypted HTTP"))
    if re.search(r"\.(exe|apk|scr|zip)$", u.path.lower()):
        out.append((0.3, "Links straight to a downloadable file"))
    return out

from detector_hosts import FREE_HOSTS

def subdomain_signals(f: dict, reg: str):
    """Subdomain tricks, e.g. paypal.com.secure-login.example.xyz"""
    sub, out = f["subdomain"], []
    labels = [x for x in sub.split(".") if x]
    brand = next((b for b, owners in BRANDS.items() if b in sub and reg not in owners), None)
    kw = sum(k in sub for k in KEYWORDS)
    if brand: out.append((0.45, f"Subdomain imitates “{brand}” but the real domain is {reg}"))
    if kw >= 2: out.append((0.3, "Subdomain packed with words like login, secure, verify"))
    elif kw == 1 and reg in FREE_HOSTS: out.append((0.2, "Credential-style name on a free hosting service"))
    if len(labels) >= 4: out.append((0.25, f"Unusually many subdomains ({len(labels)})"))
    if sub.count("-") >= 3: out.append((0.15, "Many hyphens in the subdomain"))
    if re.search(r"(^|\.)(\w+\.(com|net|org))(\.|$)", sub): out.append((0.3, "Subdomain contains a fake domain like “paypal.com”"))
    return out

def explain(f: dict):
    r = []
    if f["is_ip"]: r.append("Uses a raw IP address instead of a domain name")
    if f["brand_mismatch"]: r.append("Contains a well-known brand name but isn't that brand's domain")
    if f["hyphens"] >= 3: r.append("Many hyphens in the domain")
    if f["keywords"] >= 2: r.append("Domain stuffed with words like login, secure, verify")
    if f["len"] > 40: r.append("Very long domain name")
    if f["digit_ratio"] > 0.3 and not f["is_ip"]: r.append("Domain is full of digits")
    return r

def analyze(url: str) -> dict:
    url = url.strip()
    host, _ = parse(url)
    if not host or "." not in host:
        raise ValueError("Enter a valid URL, e.g. https://example.com/login")
    row = to_frame([url])
    p_model = float(MODEL.predict_proba(row)[0, 1])
    f = row.iloc[0].to_dict()
    trusted = f["domain"] in TRUSTED
    if trusted: p_model = min(p_model, 0.05)
    signals = rule_signals(url) + subdomain_signals(f, f["domain"])
    keep = 1 - p_model
    for risk, _ in signals: keep *= (1 - risk)
    score = 1 - keep
    reasons = explain(f) + [t for _, t in signals]
    if trusted and not reasons: reasons = ["Well-known, long-established domain"]
    verdict = "phishing" if score >= 0.85 else "suspicious" if score >= 0.6 else "safe"
    return {"url": url, "host": host, "domain": f["domain"], "score": round(score, 3), "model_score": round(p_model, 3),
            "verdict": verdict, "reasons": reasons}
