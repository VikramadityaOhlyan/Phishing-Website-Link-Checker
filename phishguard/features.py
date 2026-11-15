"""Feature extraction: turns a URL into a hostname-level feature table."""
import math, re
from urllib.parse import urlparse
import pandas as pd
import tldextract

_ext = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled suffix list

# brand keyword -> the registrable domains that legitimately own it
BRANDS = {
    "paypal": ["paypal.com"], "apple": ["apple.com", "icloud.com"], "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"], "amazon": ["amazon.com", "amazon.in"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"], "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"], "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"], "hsbc": ["hsbc.com"], "sbi": ["sbi.co.in"],
    "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"], "paytm": ["paytm.com"],
    "coinbase": ["coinbase.com"], "binance": ["binance.com"], "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"], "ebay": ["ebay.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "usps": ["usps.com"], "yahoo": ["yahoo.com"],
    "outlook": ["outlook.com", "live.com"], "adobe": ["adobe.com"], "docusign": ["docusign.com"],
}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking",
            "wallet", "support", "billing", "password", "auth", "recover", "suspend", "unlock"]
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def parse(url: str):
    """Return (hostname, tldextract result) from a URL or bare domain."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    host = host[4:] if host.startswith("www.") else host
    return host, _ext(host)

def entropy(s: str) -> float:
    if not s: return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in map(s.count, set(s)))

def registrable(e, host):
    return (getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain) or host

def featurize(url: str) -> dict:
    """Model features use ONLY the registrable domain (e.g. bbc.co.uk), because the
    legit training list has no subdomains/paths and would otherwise bias the model."""
    host, e = parse(url)
    dom = registrable(e, host)
    is_ip = bool(IP_RE.match(host))
    return {
        "domain": dom, "host": host, "subdomain": "" if is_ip else e.subdomain,
        "len": len(dom),
        "hyphens": dom.count("-"),
        "digit_ratio": sum(c.isdigit() for c in dom) / max(len(dom), 1),
        "is_ip": int(is_ip),
        "longest_label": max(map(len, dom.split("."))),
        "entropy": entropy(e.domain),
        "punycode": int("xn--" in dom),
        "keywords": sum(k in e.domain for k in KEYWORDS),
        "brand_mismatch": int(any(b in e.domain and dom not in owners for b, owners in BRANDS.items())),
        "tld_len": len(e.suffix),
    }

def to_frame(urls) -> pd.DataFrame:
    return pd.DataFrame([featurize(u) for u in urls])
