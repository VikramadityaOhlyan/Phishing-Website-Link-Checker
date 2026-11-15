# Phishing-Website-Link-Checker
PhishGuard is a lightweight web app that checks whether a link looks like phishing before you click it. Paste any URL and it returns a verdict (Looks safe, Be careful, or Likely phishing), a risk meter and plain-language reasons. It analyses the link’s text only and never opens the page, so checking a dangerous link is safe. 
Concept note
The problem

Phishing sites imitate banks, payment services and email providers to steal passwords and payment details. Most victims never inspect the address bar, and attackers rely on tricks that are easy to miss, such as paypal.com.secure-login.verify-account.xyz, where the real owner is verify-account.xyz. PhishGuard gives ordinary users a quick second opinion on a link.

The core idea

Combine a trained machine-learning model with transparent rules and a reputation list, then explain the verdict. Each layer covers a weakness of the others:

The model learns statistical patterns of malicious domains.
The rules catch tricks the model can’t see, like @ redirection and brand names in the path.
The trusted list stops well-known sites from being wrongly flagged.
The reasons shown let users learn what to look for.
How it works
Input. The user pastes a link. The frontend sends it to the Flask API at /api/check.
Parsing. The link is split into its parts. The registrable domain (for example bbc.co.uk) is what really identifies the owner. Subdomains and the path are treated separately, because anyone can put any text there.
ML model. A scikit-learn pipeline (character n-gram TF-IDF, a scaler and logistic regression) scores the domain. It was trained on about 60,000 live phishing domains from the Phishing.Database feed and about 97,000 legitimate domains from the top-1M list. The features include length, hyphens, digits, randomness (entropy), look-alike characters, credential keywords, brand-name misuse and raw IP addresses.
Reputation layer. About 20,000 top sites that aren’t abused in the phishing feed or free hosting services are treated as trusted, which removes most false alarms on popular sites.
Rules layer. Explainable checks look for:
@ tricks such as google.com@evil.ru
fake brand names in subdomains or paths
look-alike (punycode) characters
login pages inside hacked WordPress folders
link shorteners
credential pages over plain HTTP
Scoring. The model score and each triggered rule are combined into a single risk score from 0 to 1. Below 0.6 is safe, 0.6 to 0.85 is suspicious and 0.85 or above is phishing.
Output. The UI shows the verdict, a risk meter, the real owner domain highlighted inside the address, and the specific reasons.
Pipeline at a glance
URL → parse → domain features → ML model → trusted-list check → URL & subdomain rules → risk score → verdict + reasons
Intended use
Everyday users can check a suspicious link from an email, SMS or chat message.
Students and teams can use it for security-awareness training, because the reasons show how phishing links are built.
Developers can reuse it as a small API, or retrain it on newer data with python train.py.
Honest limits

In my testing, PhishGuard flagged about 73% of live phishing URLs and passed 99.7% of top-20k legitimate sites. About 1 in 11 less-popular legitimate sites gets a “be careful” warning. It is weakest on compromised legitimate websites, whose domain looks normal and where the evidence is in the page content, which this version deliberately doesn’t fetch. It is a decision aid, not a guarantee. When in doubt, type the site’s address yourself instead of clicking.

Future improvements
Analyse page content (login forms, logo and favicon mismatch) as a second pipeline stage.
Check domain age and registration data.
Retrain automatically on a schedule from fresh phishing feeds.
Add a browser extension that warns before a page loads.
