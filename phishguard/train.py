"""Train the phishing detector: python train.py  ->  model.joblib"""
import random, joblib, numpy as np, pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from features import to_frame, parse

random.seed(0)
NUM = ["len", "hyphens", "digit_ratio", "is_ip", "longest_label", "entropy",
       "punycode", "keywords", "brand_mismatch", "tld_len"]

SOURCES = {
    "data/phishing.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "data/legit.txt": "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains",
}

def download():
    import os, urllib.request
    os.makedirs("data", exist_ok=True)
    for path, url in SOURCES.items():
        if not os.path.exists(path):
            print("downloading", url); urllib.request.urlretrieve(url, path)

def load():
    download()
    phish = [l.strip() for l in open("data/phishing.txt", errors="ignore") if l.strip()]
    legit = [l.strip() for l in open("data/legit.txt") if l.strip()]
    phish = random.sample(phish, 150_000)
    legit = random.sample(legit, 100_000)
    df = pd.concat([to_frame(phish).assign(y=1), to_frame(legit).assign(y=0)], ignore_index=True)
    df = df[df.domain != ""].drop_duplicates("domain")   # one row per registrable domain
    df = df[~df.domain.isin(set(df[df.y == 0].domain) & set(df[df.y == 1].domain))]  # drop ambiguous
    df["group"] = df.domain
    return df

def build_trusted(top=20_000):
    """Reputation list: top sites that are NOT abused in the phishing feed or multi-tenant hosts."""
    from collections import Counter
    from detector_hosts import FREE_HOSTS
    from features import registrable
    seen = Counter(registrable(parse(u)[1], "") for u in (l.strip() for l in open("data/phishing.txt", errors="ignore")))
    keep = [d for d in (l.strip() for l in list(open("data/legit.txt"))[:top])
            if seen[d] < 5 and d not in FREE_HOSTS]
    open("trusted.txt", "w").write("\n".join(keep))
    print("trusted domains:", len(keep))

def build():
    pre = ColumnTransformer([
        ("txt", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=5, sublinear_tf=True), "domain"),
        ("num", StandardScaler(), NUM)])
    return Pipeline([("pre", pre), ("clf", LogisticRegression(C=4, max_iter=2000, class_weight="balanced"))])

if __name__ == "__main__":
    df = load()
    print("samples:", df.y.value_counts().to_dict())
    tr, te = next(GroupShuffleSplit(test_size=0.2, random_state=0).split(df, df.y, df.group))
    pipe = build().fit(df.iloc[tr], df.y.iloc[tr])
    p = pipe.predict_proba(df.iloc[te])[:, 1]
    print("ROC-AUC (unseen domains):", round(roc_auc_score(df.y.iloc[te], p), 4))
    print(classification_report(df.y.iloc[te], p > 0.5, target_names=["legit", "phishing"], digits=3))
    pipe.fit(df, df.y)                      # final model uses all data
    joblib.dump(pipe, "model.joblib")
    print("saved model.joblib")
    build_trusted()
