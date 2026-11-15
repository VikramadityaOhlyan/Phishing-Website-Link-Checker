# PhishGuard
    pip install -r requirements.txt
    python app.py          # open http://localhost:5000
    python train.py        # optional: re-download live data and retrain

Pipeline: URL -> features.py (registrable-domain features) -> TF-IDF + scaler + LogisticRegression (model.joblib)
          -> detector.py (trusted-domain list + explainable URL/subdomain rules) -> verdict + reasons.
Links are analysed as text and never visited.
