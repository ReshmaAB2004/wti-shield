"""
=============================================================================
  Dynamic Web Threat Intelligence & Real-Time Attack Prevention
  Using Explainable AI (XAI)

  MODEL TRAINING PIPELINE  v3
  - Trains from CSV dataset (generate_dataset.py) or synthetic fallback
  - Real URL content fetching for live threat analysis
  - SQL/XSS/Phishing/DDoS detection with rule-based override layer
  - SHAP + LIME explainability
  - Browser extension ready artifacts
=============================================================================
  Usage:
    python model_training.py                      # use synthetic data
    python model_training.py --csv threat_dataset.csv  # use CSV dataset
=============================================================================
"""

import os, re, sys, json, pickle, warnings, math, argparse, time
from collections import Counter
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection  import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing    import LabelEncoder, StandardScaler
from sklearn.ensemble         import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model     import LogisticRegression
from sklearn.metrics          import (classification_report, confusion_matrix,
                                      roc_auc_score, roc_curve,
                                      accuracy_score, f1_score)
# ── Graceful fallbacks for optional packages ──────────────────────────────────
try:
    from imblearn.over_sampling import SMOTE
    _HAS_SMOTE = True
except ImportError:
    _HAS_SMOTE = False

try:
    import shap as shap
    _HAS_SHAP = True
except ImportError:
    shap = None
    _HAS_SHAP = False

try:
    import lime
    import lime.lime_tabular
    _HAS_LIME = True
except ImportError:
    lime = None
    _HAS_LIME = False

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
CONFIG = {
    "random_state"  : 42,
    "test_size"     : 0.2,
    "n_estimators"  : 100,   # anti-overfit: reduced from 200
    "max_depth"     : 8,    # anti-overfit: reduced from 15
    "output_dir"    : os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_model_artifacts"),
    "threat_classes": ["benign", "sql_injection", "xss", "phishing", "ddos"],
    "model_version" : "3.0.0",
}

os.makedirs(CONFIG["output_dir"], exist_ok=True)
print(f"  Output directory: {CONFIG['output_dir']}")
LABEL_MAP = {"benign":0, "sql_injection":1, "xss":2, "phishing":3, "ddos":4}

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
BRAND_KEYWORDS = [
    "paypal","appleid","amazon","microsoft","facebook","netflix",
    "instagram","whatsapp","wellsfargo","citibank","hsbc","barclays",
    "dropbox","steam","roblox","chase","bankofamerica",
]

# Trusted real domains — never count brand hits for these
TRUSTED_DOMAINS = [
    "google.com","youtube.com","apple.com","amazon.com","microsoft.com",
    "facebook.com","instagram.com","linkedin.com","twitter.com","x.com",
    "github.com","stackoverflow.com","wikipedia.org","reddit.com",
    "netflix.com","dropbox.com","ebay.com","paypal.com","steam.com",
]

SUSPICIOUS_TLDS = [
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",
    ".online",".site",".info",".biz",".club",".work",".live",".pw",
    ".cc",".ws",
]

# Only use multi-word / unambiguous SQL attack patterns (avoids false positives
# from normal words like "from", "select", "where", "update" in URLs)
SQL_KEYWORDS = [
    "union select","union+select","1=1","1 = 1",
    "insert into","drop table","drop database",
    "--","/**/","xp_cmd","exec(","cast(0x","benchmark(","sleep(",
    "' or '","\" or \"","or 1=1","or+1=1",
]

XSS_PATTERNS = [
    r"<script",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe",
    r"<img[^>]+onerror",
    r"alert\s*\(",
    r"document\.cookie",
    r"eval\s*\(",
    r"<svg[^>]+onload",
]


# ─────────────────────────────────────────────────────────────────────────────
# REAL-WEBSITE CONTENT FETCHER  (NEW in v3)
# ─────────────────────────────────────────────────────────────────────────────
def fetch_url_content(url: str, timeout: int = 5) -> dict:
    """
    Fetches actual webpage content and extracts threat signals.
    Returns a dict of content-based features.
    Falls back gracefully if fetch fails (offline / blocked).
    """
    content_features = {
        "page_has_login_form"    : 0,
        "page_has_external_js"   : 0,
        "page_redirects"         : 0,
        "page_has_iframe"        : 0,
        "page_title_brand_spoof" : 0,
        "page_sql_in_response"   : 0,
        "page_xss_in_response"   : 0,
        "page_reachable"         : 0,
        "page_status_code"       : 0,
        "page_response_time_ms"  : 0,
        "fetch_error"            : "none",
    }

    try:
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        if not url.startswith(("http://","https://")):
            url = "http://" + url

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ThreatScanner/3.0)"},
        )

        t_start = time.time()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content_features["page_response_time_ms"] = int((time.time()-t_start)*1000)
            content_features["page_status_code"]      = resp.status
            content_features["page_reachable"]        = 1

            # Check if we were redirected to a completely different domain
            # (www.google.com → google.com is NORMAL, not suspicious)
            final_url = resp.geturl()
            try:
                orig_host  = urlparse(url).hostname or ""
                final_host = urlparse(final_url).hostname or ""
                # Strip www. prefix before comparing
                orig_root  = orig_host.lstrip("www.")
                final_root = final_host.lstrip("www.")
                # Only flag if root domains are genuinely different
                if orig_root and final_root and orig_root != final_root:
                    content_features["page_redirects"] = 1
            except Exception:
                pass

            html = resp.read(50000).decode("utf-8", errors="ignore").lower()

            # Login form detection
            if re.search(r'<form[^>]*>.*?(password|passwd|login)', html, re.DOTALL):
                content_features["page_has_login_form"] = 1

            # External JS
            if re.search(r'<script[^>]+src=["\'][^"\']*["\']', html):
                content_features["page_has_external_js"] = 1

            # iFrame detection
            if "<iframe" in html:
                content_features["page_has_iframe"] = 1

            # Title brand spoofing
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html)
            if title_match:
                title = title_match.group(1)
                if any(b in title for b in BRAND_KEYWORDS):
                    content_features["page_title_brand_spoof"] = 1

            # SQL error in response (indicates SQLi vulnerability)
            sql_errors = ["you have an error in your sql","mysql_fetch","odbc_exec",
                          "unclosed quotation","syntax error"]
            if any(e in html for e in sql_errors):
                content_features["page_sql_in_response"] = 1

            # XSS reflection in response — only flag actual injected attack payloads,
            # NOT normal HTML tags that every legitimate website uses.
            # We look for dangerous patterns that shouldn't appear in real page source.
            XSS_PAGE_PATTERNS = [
                r"<script[^>]*>.*?(alert|eval|document\.cookie|fetch\(|xmlhttprequest)",
                r"javascript:\s*(alert|eval|void|document)",
                r"<img[^>]+onerror\s*=",
                r"<svg[^>]+onload\s*=",
                r"document\.write\s*\(",
                r"eval\s*\(\s*unescape",
                r"base64.*eval",
            ]
            if any(re.search(p, html, re.DOTALL) for p in XSS_PAGE_PATTERNS):
                content_features["page_xss_in_response"] = 1

    except Exception as e:
        content_features["fetch_error"] = str(e)[:80]
        content_features["page_reachable"] = 0

    return content_features


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION  (URL → numeric features)
# ─────────────────────────────────────────────────────────────────────────────
FEATURE_COLS_BASE = [
    "url_length","num_special_chars","has_ip","num_subdomains","has_https",
    "entropy","num_digits","num_params","payload_length","num_encoded_chars",
    "num_sql_keywords","num_script_tags","num_event_handlers",
    "brand_keyword_count","has_brand_in_domain","has_suspicious_tld",
    "num_hyphens_domain","domain_length","has_at_symbol",
    "has_double_slash","num_dots",
    "req_per_second","avg_payload_size","unique_ips",
    "error_rate","req_size_variance",
]

FEATURE_COLS = FEATURE_COLS_BASE + [
    "sql_payload_ratio","xss_density","encoded_ratio",
    "traffic_anomaly_score","url_complexity","phishing_score",
]


def extract_url_features(url: str) -> dict:
    """Extract 26 numeric features from a raw URL string."""
    if not url:
        return {k: 0 for k in FEATURE_COLS_BASE}

    url_for_parse = url if url.startswith(("http://","https://")) else "http://" + url

    try:
        parsed   = urlparse(url_for_parse)
        hostname = (parsed.hostname or "").lower()
        scheme   = parsed.scheme.lower()
    except Exception:
        hostname, scheme = "", "http"

    url_low    = url.lower()
    host_parts = hostname.split(".")
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []
    domain     = host_parts[-2]  if len(host_parts) >= 2 else hostname

    special_chars = re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", url)
    digits        = re.findall(r"\d", url)
    params        = re.findall(r"[?&]", url)
    encoded_chars = re.findall(r"%[0-9a-fA-F]{2}", url)

    freq    = Counter(url)
    total   = len(url) or 1
    entropy = -sum((c/total)*math.log2(c/total) for c in freq.values() if c > 0)

    ip_re  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip = int(bool(ip_re.match(hostname)))

    # ── Attack-specific ────────────────────────────────────────────────────────
    sql_count      = sum(url_low.count(k) for k in SQL_KEYWORDS)
    script_tags    = len(re.findall(r"<script", url_low))
    event_handlers = len(re.findall(r"on\w+\s*=", url_low))

    # ── Phishing-specific — skip brand check for real trusted sites ────────────
    _domain_clean = hostname.lstrip("www.")
    _is_trusted   = any(_domain_clean == td or _domain_clean.endswith("." + td)
                        for td in TRUSTED_DOMAINS)
    if _is_trusted:
        brand_kw_count   = 0
        has_brand_in_dom = 0
    else:
        brand_kw_count   = sum(url_low.count(b) for b in BRAND_KEYWORDS)
        has_brand_in_dom = int(any(b in domain for b in BRAND_KEYWORDS))
    has_susp_tld      = int(any(hostname.endswith(t) for t in SUSPICIOUS_TLDS))
    num_hyphens_dom   = domain.count("-")
    domain_length     = len(hostname)
    has_at_symbol     = int("@" in url)
    has_double_slash  = int("//" in url_for_parse[7:])
    num_dots          = url.count(".")

    return {
        "url_length"          : len(url),
        "num_special_chars"   : len(special_chars),
        "has_ip"              : has_ip,
        "num_subdomains"      : len(subdomains),
        "has_https"           : int(scheme == "https"),
        "entropy"             : round(entropy, 4),
        "num_digits"          : len(digits),
        "num_params"          : len(params),
        "payload_length"      : len(url),
        "num_encoded_chars"   : len(encoded_chars),
        "num_sql_keywords"    : sql_count,
        "num_script_tags"     : script_tags,
        "num_event_handlers"  : event_handlers,
        "brand_keyword_count" : brand_kw_count,
        "has_brand_in_domain" : has_brand_in_dom,
        "has_suspicious_tld"  : has_susp_tld,
        "num_hyphens_domain"  : num_hyphens_dom,
        "domain_length"       : domain_length,
        "has_at_symbol"       : has_at_symbol,
        "has_double_slash"    : has_double_slash,
        "num_dots"            : num_dots,
        "req_per_second"      : 1,
        "avg_payload_size"    : 300,
        "unique_ips"          : 1,
        "error_rate"          : 0.0,
        "req_size_variance"   : 20,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["sql_payload_ratio"]     = df["num_sql_keywords"]   / (df["payload_length"] + 1)
    df["xss_density"]           = (df["num_script_tags"] + df["num_event_handlers"]) / (df["url_length"] + 1)
    df["encoded_ratio"]         = df["num_encoded_chars"]  / (df["url_length"] + 1)
    df["traffic_anomaly_score"] = df["req_per_second"]     * df["error_rate"]
    df["url_complexity"]        = df["entropy"]            * df["num_special_chars"]
    df["phishing_score"]        = (
        df["num_subdomains"]       * 1.0 +
        df["has_ip"]               * 5.0 +
        (1 - df["has_https"])      * 2.0 +
        df["brand_keyword_count"]  * 3.0 +
        df["has_brand_in_domain"]  * 4.0 +
        df["has_suspicious_tld"]   * 5.0 +
        df["num_hyphens_domain"]   * 1.5 +
        df["has_at_symbol"]        * 3.0 +
        df["num_dots"]             * 0.5
    )
    return df


# ─────────────────────────────────────────────────────────────────────────────
# DATASET LOADING
# ─────────────────────────────────────────────────────────────────────────────
def load_csv_dataset(csv_path: str) -> pd.DataFrame:
    """Load dataset from CSV file generated by generate_dataset.py."""
    print(f"  Loading CSV: {csv_path}")
    df = pd.read_csv(csv_path)

    alias = {
        "normal":"benign","0":"benign","safe":"benign",
        "sql":"sql_injection","sqli":"sql_injection","sql injection":"sql_injection",
        "xss":"xss","cross-site":"xss","cross site scripting":"xss",
        "phish":"phishing","phish url":"phishing",
        "dos":"ddos","flood":"ddos","ddos attack":"ddos",
    }
    df["threat_label"] = (df["threat_label"].astype(str).str.strip().str.lower()
                          .map(lambda x: alias.get(x, x)))

    unknown = set(df["threat_label"].unique()) - set(CONFIG["threat_classes"])
    if unknown:
        print(f"  ⚠️  Unknown labels removed: {unknown}")
        df = df[df["threat_label"].isin(CONFIG["threat_classes"])]

    print(f"  Loaded {len(df)} rows from CSV")
    return df


def generate_synthetic_samples(n=10000) -> pd.DataFrame:
    """Fallback synthetic dataset when no CSV is provided."""
    np.random.seed(CONFIG["random_state"])
    rows = []

    def ri(lo, hi): return int(np.random.randint(lo, hi + 1))
    def rf(lo, hi): return round(float(np.random.uniform(lo, hi)), 4)
    def rb(prob):   return int(np.random.random() < prob)

    patterns = {
        "benign": dict(
            url_length=(15,90), num_special_chars=(0,6), has_ip=0.02,
            num_subdomains=(0,2), has_https=0.92, entropy=(3.0,4.5),
            num_digits=(0,5), num_params=(0,4),
            payload_length=(15,150), num_encoded_chars=(0,2),
            num_sql_keywords=(0,0), num_script_tags=(0,0), num_event_handlers=(0,0),
            brand_keyword_count=(0,1), has_brand_in_domain=0.02,
            has_suspicious_tld=0.01, num_hyphens_domain=(0,1),
            domain_length=(4,20), has_at_symbol=0.0, has_double_slash=0.0,
            num_dots=(1,3), req_per_second=(1,8), avg_payload_size=(200,700),
            unique_ips=(1,4), error_rate=(0.0,0.04), req_size_variance=(10,80),
        ),
        "sql_injection": dict(
            url_length=(50,280), num_special_chars=(12,55), has_ip=0.10,
            num_subdomains=(0,1), has_https=0.20, entropy=(4.2,6.5),
            num_digits=(5,30), num_params=(2,10),
            payload_length=(50,650), num_encoded_chars=(5,40),
            num_sql_keywords=(4,20), num_script_tags=(0,1), num_event_handlers=(0,1),
            brand_keyword_count=(0,1), has_brand_in_domain=0.02,
            has_suspicious_tld=0.05, num_hyphens_domain=(0,2),
            domain_length=(5,25), has_at_symbol=0.0, has_double_slash=0.02,
            num_dots=(1,3), req_per_second=(1,15), avg_payload_size=(300,1600),
            unique_ips=(1,3), error_rate=(0.15,0.60), req_size_variance=(60,550),
        ),
        "xss": dict(
            url_length=(45,220), num_special_chars=(10,45), has_ip=0.08,
            num_subdomains=(0,2), has_https=0.25, entropy=(4.5,6.8),
            num_digits=(2,16), num_params=(1,8),
            payload_length=(40,500), num_encoded_chars=(10,60),
            num_sql_keywords=(0,2), num_script_tags=(2,15), num_event_handlers=(1,12),
            brand_keyword_count=(0,1), has_brand_in_domain=0.02,
            has_suspicious_tld=0.05, num_hyphens_domain=(0,2),
            domain_length=(5,25), has_at_symbol=0.0, has_double_slash=0.03,
            num_dots=(1,3), req_per_second=(1,12), avg_payload_size=(250,1300),
            unique_ips=(1,4), error_rate=(0.08,0.45), req_size_variance=(40,420),
        ),
        "phishing": dict(
            url_length=(40,320), num_special_chars=(2,20), has_ip=0.20,
            num_subdomains=(1,7), has_https=0.35, entropy=(3.5,5.5),
            num_digits=(1,16), num_params=(0,5),
            payload_length=(40,380), num_encoded_chars=(1,15),
            num_sql_keywords=(0,1), num_script_tags=(0,2), num_event_handlers=(0,2),
            brand_keyword_count=(2,9), has_brand_in_domain=0.88,
            has_suspicious_tld=0.65, num_hyphens_domain=(2,6),
            domain_length=(18,65), has_at_symbol=0.12, has_double_slash=0.05,
            num_dots=(2,7), req_per_second=(1,8), avg_payload_size=(400,2100),
            unique_ips=(1,10), error_rate=(0.0,0.12), req_size_variance=(20,220),
        ),
        "ddos": dict(
            url_length=(8,80), num_special_chars=(0,4), has_ip=0.15,
            num_subdomains=(0,1), has_https=0.50, entropy=(2.5,4.2),
            num_digits=(0,4), num_params=(0,2),
            payload_length=(5,100), num_encoded_chars=(0,3),
            num_sql_keywords=(0,0), num_script_tags=(0,0), num_event_handlers=(0,0),
            brand_keyword_count=(0,1), has_brand_in_domain=0.01,
            has_suspicious_tld=0.02, num_hyphens_domain=(0,1),
            domain_length=(4,20), has_at_symbol=0.0, has_double_slash=0.01,
            num_dots=(1,3), req_per_second=(600,7000), avg_payload_size=(40,280),
            unique_ips=(60,700), error_rate=(0.35,0.98), req_size_variance=(1,18),
        ),
    }

    per_class = n // len(patterns)
    for label, p in patterns.items():
        for _ in range(per_class):
            row = {
                "url_length"          : ri(*p["url_length"]),
                "num_special_chars"   : ri(*p["num_special_chars"]),
                "has_ip"              : rb(p["has_ip"]),
                "num_subdomains"      : ri(*p["num_subdomains"]),
                "has_https"           : rb(p["has_https"]),
                "entropy"             : rf(*p["entropy"]),
                "num_digits"          : ri(*p["num_digits"]),
                "num_params"          : ri(*p["num_params"]),
                "payload_length"      : ri(*p["payload_length"]),
                "num_encoded_chars"   : ri(*p["num_encoded_chars"]),
                "num_sql_keywords"    : ri(*p["num_sql_keywords"]),
                "num_script_tags"     : ri(*p["num_script_tags"]),
                "num_event_handlers"  : ri(*p["num_event_handlers"]),
                "brand_keyword_count" : ri(*p["brand_keyword_count"]),
                "has_brand_in_domain" : rb(p["has_brand_in_domain"]),
                "has_suspicious_tld"  : rb(p["has_suspicious_tld"]),
                "num_hyphens_domain"  : ri(*p["num_hyphens_domain"]),
                "domain_length"       : ri(*p["domain_length"]),
                "has_at_symbol"       : rb(p["has_at_symbol"]),
                "has_double_slash"    : rb(p["has_double_slash"]),
                "num_dots"            : ri(*p["num_dots"]),
                "req_per_second"      : rf(*p["req_per_second"]),
                "avg_payload_size"    : rf(*p["avg_payload_size"]),
                "unique_ips"          : ri(*p["unique_ips"]),
                "error_rate"          : rf(*p["error_rate"]),
                "req_size_variance"   : rf(*p["req_size_variance"]),
                "threat_label"        : label,
            }
            rows.append(row)

    return pd.DataFrame(rows).sample(frac=1, random_state=CONFIG["random_state"]).reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# PREPROCESSING
# ─────────────────────────────────────────────────────────────────────────────
def preprocess(df: pd.DataFrame):
    df  = engineer_features(df)
    le  = LabelEncoder()
    le.classes_ = np.array(CONFIG["threat_classes"])
    y   = df["threat_label"].map(LABEL_MAP).values
    X   = df[FEATURE_COLS].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=CONFIG["test_size"],
        random_state=CONFIG["random_state"], stratify=y,
    )

    print("  [SMOTE] Before:", np.bincount(y_train))
    if _HAS_SMOTE:
        sm = SMOTE(random_state=CONFIG["random_state"])
        X_train, y_train = sm.fit_resample(X_train, y_train)
        print("  [SMOTE] After :", np.bincount(y_train))
    else:
        # Fallback: manual oversampling to balance classes (no imblearn needed)
        from sklearn.utils import resample
        classes, counts = np.unique(y_train, return_counts=True)
        max_count = counts.max()
        X_parts, y_parts = [X_train], [y_train]
        for cls, cnt in zip(classes, counts):
            if cnt < max_count:
                idx = np.where(y_train == cls)[0]
                X_res = resample(X_train[idx], replace=True,
                                 n_samples=max_count - cnt,
                                 random_state=CONFIG["random_state"])
                X_parts.append(X_res)
                y_parts.append(np.full(max_count - cnt, cls))
        X_train = np.vstack(X_parts)
        y_train = np.concatenate(y_parts)
        shuffle_idx = np.random.RandomState(CONFIG["random_state"]).permutation(len(X_train))
        X_train, y_train = X_train[shuffle_idx], y_train[shuffle_idx]
        print("  [Oversample fallback] After:", np.bincount(y_train))

    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    return X_train, X_test, y_train, y_test, scaler, le


# ─────────────────────────────────────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────────────────────────────────────
def build_models():
    return {
        # ── Anti-overfit hyperparameters ──────────────────────────────────────
        "RandomForest": RandomForestClassifier(
            n_estimators=100,         # reduced from 200 (less memorisation)
            max_depth=8,              # reduced from 15 (prevents deep memorisation)
            min_samples_leaf=8,       # no leaf with <8 samples
            min_samples_split=16,     # minimum split size
            max_features="sqrt",      # sqrt(n_features) per split only
            class_weight="balanced",
            random_state=CONFIG["random_state"],
            n_jobs=1,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=100,         # reduced from 150
            max_depth=4,              # reduced from 6
            learning_rate=0.08,       # slower learning = less overfit
            min_samples_leaf=10,      # prevent tiny leaves
            subsample=0.85,           # row subsampling (bagging effect)
            max_features="sqrt",      # feature subsampling per split
            random_state=CONFIG["random_state"],
        ),
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            C=0.8,                    # L2 regularisation (default C=1.0)
            class_weight="balanced",
            random_state=CONFIG["random_state"],
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# TRAINING & EVALUATION
# ─────────────────────────────────────────────────────────────────────────────
def train_and_evaluate(models, X_train, X_test, y_train, y_test):
    results  = {}
    best_f1, best_name, best_clf = 0, None, None

    for name, clf in models.items():
        print(f"\n{'='*55}\n  Training: {name}\n{'='*55}")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=CONFIG["random_state"])
        cv_scores = cross_val_score(clf, X_train, y_train, cv=cv,
                                    scoring="f1_weighted", n_jobs=1)
        print(f"  CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)

        # ── Overfit detection: compare train vs test accuracy ─────────────────
        train_acc    = accuracy_score(y_train, clf.predict(X_train))
        acc          = accuracy_score(y_test, y_pred)
        f1           = f1_score(y_test, y_pred, average="weighted")
        auc          = roc_auc_score(y_test, y_prob, multi_class="ovr", average="weighted")
        overfit_gap  = train_acc - acc
        health_flag  = "⚠️  OVERFIT DETECTED" if overfit_gap > 0.05 else "✅ Generalising well"

        print(f"  Train Accuracy : {train_acc:.4f}")
        print(f"  Test  Accuracy : {acc:.4f}  F1:{f1:.4f}  AUC:{auc:.4f}")
        print(f"  Train-Test Gap : {overfit_gap:+.4f}  →  {health_flag}")
        if overfit_gap > 0.05:
            print(f"  TIP: increase min_samples_leaf, reduce max_depth, or add more data")
        print(classification_report(y_test, y_pred, target_names=CONFIG["threat_classes"]))

        results[name] = {"model":clf,"acc":acc,"f1":f1,"auc":auc,
                         "y_pred":y_pred,"y_prob":y_prob,"cv_f1":cv_scores.mean()}
        if f1 > best_f1:
            best_f1, best_name, best_clf = f1, name, clf

    print(f"\n  ✅  Best Model → {best_name}  (F1={best_f1:.4f})")
    return results, best_name, best_clf


def evaluate_external_dataset(clf, scaler, df, label="external"):
    print(f"\n[7/6] Evaluating on external {label} dataset …")
    df = engineer_features(df)
    y_true = df["threat_label"].map(LABEL_MAP).values
    X_ext  = scaler.transform(df[FEATURE_COLS].values)
    y_pred = clf.predict(X_ext)
    y_prob = clf.predict_proba(X_ext)

    acc = accuracy_score(y_true, y_pred)
    f1  = f1_score(y_true, y_pred, average="weighted")
    auc = roc_auc_score(y_true, y_prob, multi_class="ovr", average="weighted")

    print(f"  External Accuracy : {acc:.4f}")
    print(f"  External F1       : {f1:.4f}")
    print(f"  External AUC      : {auc:.4f}")
    print(classification_report(y_true, y_pred, target_names=CONFIG["threat_classes"]))

    return {"accuracy": acc, "f1": f1, "roc_auc": auc}


# ─────────────────────────────────────────────────────────────────────────────
# VISUALISATIONS
# ─────────────────────────────────────────────────────────────────────────────
def plot_confusion_matrix(y_test, y_pred, model_name, out_dir):
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8,6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=CONFIG["threat_classes"],
                yticklabels=CONFIG["threat_classes"])
    plt.title(f"Confusion Matrix — {model_name}")
    plt.ylabel("True"); plt.xlabel("Predicted"); plt.tight_layout()
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"confusion_matrix_{model_name}.png")
    plt.savefig(path, dpi=150); plt.close()
    print(f"  Saved: {path}")


def plot_roc_curves(y_test, y_prob, model_name, out_dir):
    from sklearn.preprocessing import label_binarize
    y_bin  = label_binarize(y_test, classes=list(range(len(CONFIG["threat_classes"]))))
    colors = ["#e63946","#2a9d8f","#e9c46a","#f4a261","#264653"]
    plt.figure(figsize=(9,6))
    for i,(cls,col) in enumerate(zip(CONFIG["threat_classes"],colors)):
        fpr,tpr,_ = roc_curve(y_bin[:,i], y_prob[:,i])
        auc_v = roc_auc_score(y_bin[:,i], y_prob[:,i])
        plt.plot(fpr, tpr, label=f"{cls} (AUC={auc_v:.3f})", color=col, lw=2)
    plt.plot([0,1],[0,1],"k--",lw=1)
    plt.xlabel("FPR"); plt.ylabel("TPR")
    plt.title(f"ROC Curves — {model_name}")
    plt.legend(loc="lower right"); plt.tight_layout()
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"roc_curves_{model_name}.png")
    plt.savefig(path, dpi=150); plt.close()
    print(f"  Saved: {path}")


def plot_feature_importance(clf, out_dir):
    if not hasattr(clf, "feature_importances_"): return
    imp = clf.feature_importances_
    idx = np.argsort(imp)[::-1]
    plt.figure(figsize=(14,6))
    plt.bar(range(len(FEATURE_COLS)), imp[idx], color="#2a9d8f")
    plt.xticks(range(len(FEATURE_COLS)),
               [FEATURE_COLS[i] for i in idx], rotation=45, ha="right", fontsize=8)
    plt.title("Feature Importances (Best Model)"); plt.tight_layout()
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "feature_importances.png")
    plt.savefig(path, dpi=150); plt.close()
    print(f"  Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# XAI — SHAP
# ─────────────────────────────────────────────────────────────────────────────
def run_shap(clf, X_train, X_test, out_dir):
    print("\n  [SHAP] Computing SHAP values …")
    if not _HAS_SHAP:
        print("  [SHAP] shap not installed — skipping (install with: pip install shap)")
        return None
    try:
        explainer   = shap.TreeExplainer(clf)
        shap_values = explainer.shap_values(X_test[:200])
        plt.figure()
        shap.summary_plot(shap_values, X_test[:200], feature_names=FEATURE_COLS,
                          class_names=CONFIG["threat_classes"], show=False)
        path = os.path.join(out_dir, "shap_summary.png")
        plt.savefig(path, bbox_inches="tight", dpi=150); plt.close()
        print(f"  Saved: {path}")
        sv_list = shap_values if isinstance(shap_values, list) else \
                  [shap_values[:,:,i] for i in range(shap_values.shape[2])]
        for i,cls in enumerate(CONFIG["threat_classes"]):
            plt.figure()
            shap.summary_plot(sv_list[i], X_test[:200], feature_names=FEATURE_COLS,
                              plot_type="bar", show=False)
            path = os.path.join(out_dir, f"shap_bar_{cls}.png")
            plt.savefig(path, bbox_inches="tight", dpi=150); plt.close()
            print(f"  Saved: {path}")
        with open(os.path.join(out_dir,"shap_explainer.pkl"),"wb") as f:
            pickle.dump(explainer, f)
        return explainer
    except Exception as e:
        print(f"  [SHAP] Warning: {e}"); return None


# ─────────────────────────────────────────────────────────────────────────────
# XAI — LIME
# ─────────────────────────────────────────────────────────────────────────────
def run_lime(clf, X_train, X_test, y_test, out_dir, n_samples=5):
    print("\n  [LIME] Generating LIME explanations …")
    if not _HAS_LIME:
        print("  [LIME] lime not installed — skipping (install with: pip install lime)")
        return None
    try:
        lime_exp = lime.lime_tabular.LimeTabularExplainer(
            X_train, feature_names=FEATURE_COLS,
            class_names=CONFIG["threat_classes"],
            discretize_continuous=True, random_state=CONFIG["random_state"],
        )
        explanations = []
        for idx in range(min(n_samples, len(X_test))):
            exp       = lime_exp.explain_instance(X_test[idx], clf.predict_proba,
                                                  num_features=10, top_labels=1)
            top_label = exp.top_labels[0]
            explanations.append({
                "sample_index"   : idx,
                "true_label"     : CONFIG["threat_classes"][y_test[idx]],
                "predicted_label": CONFIG["threat_classes"][clf.predict([X_test[idx]])[0]],
                "top_class"      : CONFIG["threat_classes"][top_label],
                "feature_weights": exp.as_list(label=top_label),
            })
            exp.save_to_file(os.path.join(out_dir, f"lime_explanation_sample_{idx}.html"))
        with open(os.path.join(out_dir,"lime_explanations.json"),"w") as f:
            json.dump(explanations, f, indent=2)
        with open(os.path.join(out_dir,"lime_explainer.pkl"),"wb") as f:
            pickle.dump(lime_exp, f)
        return lime_exp
    except Exception as e:
        print(f"  [LIME] Warning: {e}"); return None


# ─────────────────────────────────────────────────────────────────────────────
# RULE-BASED OVERRIDE  (catches what synthetic training may miss on real URLs)
# ─────────────────────────────────────────────────────────────────────────────
def apply_rule_overrides(url: str, probs: np.ndarray, url_feats: dict) -> tuple:
    """
    Strong deterministic rules applied on top of ML predictions.
    Returns (probs, pred_idx, confidence, risk_score, rule_triggered).
    """
    url_low = url.lower()
    pred_idx   = int(np.argmax(probs))
    confidence = float(probs[pred_idx])
    rule       = None

    # ── SQL Injection: 2+ distinct SQL keywords → override to sql_injection ──
    _sql_hits = sum(1 for k in SQL_KEYWORDS if k in url_low)
    if _sql_hits >= 2:
        si = LABEL_MAP["sql_injection"]
        confidence = min(0.55 + _sql_hits * 0.08, 0.97)
        probs = probs.copy()
        probs[0]  = max(0.0, 1.0 - confidence)
        probs[si] = confidence
        probs    /= probs.sum()
        pred_idx  = si
        rule      = f"SQL rule ({_sql_hits} keywords)"

    # ── XSS: 1+ script tag OR 2+ event handlers → override to xss ────────────
    _xss_hits = (len(re.findall(r"<script",    url_low)) * 2 +
                 len(re.findall(r"on\w+\s*=",  url_low)) +
                 len(re.findall(r"javascript:", url_low)) * 2)
    if _xss_hits >= 2 and rule is None:
        xi = LABEL_MAP["xss"]
        confidence = min(0.55 + _xss_hits * 0.07, 0.97)
        probs = probs.copy()
        probs[0]  = max(0.0, 1.0 - confidence)
        probs[xi] = confidence
        probs    /= probs.sum()
        pred_idx  = xi
        rule      = f"XSS rule ({_xss_hits} signals)"

    # ── Phishing: brand + bad TLD or brand + hyphens ──────────────────────────
    try:
        _h = (urlparse(url if url.startswith("http") else "http://"+url).hostname or "").lower()
    except Exception:
        _h = ""

    _brands   = ["paypal","amazon","appleid","microsoft","netflix",
                 "facebook","instagram","wellsfargo","chase","citibank","barclays"]
    _bad_tlds = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".info",".biz"]
    _phish_kw = ["login","signin","verify","secure","update","account",
                 "password","confirm","credential","wallet","suspended"]

    _ps = 0
    # Only flag brand-in-domain when it's NOT the real brand's own domain
    if any(_b in _h and not _h.endswith(_b+".com") and not _h == _b+".com"
           for _b in _brands): _ps += 3
    if any(_h.endswith(t) for t in _bad_tlds): _ps += 2
    if _h.count("-") >= 2: _ps += 2
    _ps += sum(1 for k in _phish_kw if k in url_low)
    if url_feats.get("has_ip", 0): _ps += 2

    if _ps >= 4 and rule is None:
        pi = LABEL_MAP["phishing"]
        confidence = min(0.50 + _ps * 0.06, 0.97)
        probs = probs.copy()
        probs[0]  = max(0.0, 1.0 - confidence)
        probs[pi] = confidence
        probs    /= probs.sum()
        pred_idx  = pi
        rule      = f"Phishing rule (score={_ps})"

    risk_score = round(float(probs[pred_idx]) * 100, 1)
    return probs, pred_idx, float(probs[pred_idx]), risk_score, rule


# ─────────────────────────────────────────────────────────────────────────────
# REAL-TIME INFERENCE  (URL analysis + optional live page fetch)
# ─────────────────────────────────────────────────────────────────────────────
def predict_threat(url: str, traffic_features: dict,
                   model, scaler, shap_explainer=None,
                   fetch_content: bool = False) -> dict:
    """
    Analyze a URL for threats.

    Args:
        url             : raw URL string
        traffic_features: dict (req_per_second, error_rate, unique_ips, …)
        model           : trained classifier
        scaler          : fitted StandardScaler
        shap_explainer  : optional TreeExplainer for XAI
        fetch_content   : if True, fetches the live page for deeper analysis
    """
    url_feats = extract_url_features(url)

    # Override traffic defaults
    defaults = dict(req_per_second=1, avg_payload_size=300, unique_ips=1,
                    error_rate=0.0, req_size_variance=20)
    defaults.update(traffic_features)
    for k, v in defaults.items():
        url_feats[k] = v

    row = pd.DataFrame([url_feats])
    row = engineer_features(row)
    for col in FEATURE_COLS:
        if col not in row.columns:
            row[col] = 0

    X     = scaler.transform(row[FEATURE_COLS].values)
    probs = model.predict_proba(X)[0]

    # Apply rule-based overrides
    probs, pred_idx, confidence, risk_score, rule_triggered = apply_rule_overrides(
        url, probs, url_feats
    )

    result = {
        "url"            : url,
        "threat_class"   : CONFIG["threat_classes"][pred_idx],
        "confidence"     : round(confidence, 4),
        "risk_score"     : risk_score,
        "all_probs"      : {cls: round(float(p), 4)
                            for cls, p in zip(CONFIG["threat_classes"], probs)},
        "is_malicious"   : CONFIG["threat_classes"][pred_idx] != "benign",
        "severity"       : ("HIGH"   if risk_score >= 80 else
                            "MEDIUM" if risk_score >= 50 else "LOW"),
        "rule_triggered" : rule_triggered,
        "analysis_mode"  : "url_only",
    }

    # ── Optional: fetch live page content ─────────────────────────────────────
    if fetch_content:
        print(f"  [Fetch] Scanning live page: {url}")
        content = fetch_url_content(url)
        result["content_analysis"] = content
        result["analysis_mode"]    = "url+content"

        # Boost risk only when page content confirms what the URL already suggests.
        # Never upgrade a clean URL to a threat based solely on page content —
        # legitimate sites have JavaScript and forms too.
        if content["page_reachable"]:
            boost = 0
            # SQL: only flag if URL already had SQL signals OR page shows a DB error
            if content["page_sql_in_response"] and result["threat_class"] in ("benign", "xss"):
                # Only upgrade if URL itself had some SQL signal
                if url_feats.get("num_sql_keywords", 0) > 0:
                    result["threat_class"] = "sql_injection"
                    boost = 20
            # XSS: only flag if URL already had script/event signals
            if content["page_xss_in_response"] and result["threat_class"] == "benign":
                if url_feats.get("num_script_tags", 0) > 0 or url_feats.get("num_event_handlers", 0) > 0:
                    result["threat_class"] = "xss"
                    boost = 15
            # Phishing: login form + brand spoof title — this is legitimate to flag
            if (content["page_has_login_form"] and content["page_title_brand_spoof"]
                    and result["threat_class"] == "benign"):
                result["threat_class"] = "phishing"
                boost = 25
            if boost:
                result["risk_score"]   = min(100, result["risk_score"] + boost)
                result["is_malicious"] = True
                result["severity"]     = ("HIGH" if result["risk_score"] >= 80 else "MEDIUM")
                result["rule_triggered"] = f"content_scan+{boost}pts"

    # ── SHAP explanation ───────────────────────────────────────────────────────
    if shap_explainer:
        try:
            sv     = shap_explainer.shap_values(X)
            sv_cls = sv[pred_idx] if isinstance(sv, list) else sv[:,:,pred_idx]
            top    = sorted(zip(FEATURE_COLS, sv_cls[0]),
                            key=lambda x: abs(x[1]), reverse=True)[:5]
            result["shap_top_features"] = [
                {"feature": f, "impact": round(v, 4)} for f, v in top
            ]
        except Exception:
            pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# SAVE ARTIFACTS
# ─────────────────────────────────────────────────────────────────────────────
def save_artifacts(clf, scaler, le, out_dir):
    for obj, fname in [(clf,"model.pkl"),(scaler,"scaler.pkl"),(le,"label_encoder.pkl")]:
        with open(os.path.join(out_dir, fname), "wb") as f:
            pickle.dump(obj, f)
        print(f"  Saved: {os.path.join(out_dir,fname)}")
    meta_path = os.path.join(out_dir, "model_metadata.json")
    with open(meta_path, "w") as f:
        json.dump({"model_version":CONFIG["model_version"],
                   "threat_classes":CONFIG["threat_classes"],
                   "feature_columns":FEATURE_COLS,
                   "label_map":LABEL_MAP,"performance":{}}, f, indent=2)
    return meta_path


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to CSV dataset (generated by generate_dataset.py)")
    parser.add_argument("--external", type=str, default=None,
                        help="Path to an external CSV for unseen real-world validation")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  WEB THREAT INTELLIGENCE — MODEL TRAINING PIPELINE v3")
    print("="*60)

    print("\n[1/6] Loading dataset …")
    if args.csv and os.path.exists(args.csv):
        df = load_csv_dataset(args.csv)
    else:
        if args.csv:
            print(f"  ⚠️  CSV not found: {args.csv} — using synthetic data")
        else:
            print("  No CSV provided — using synthetic data")
            print("  Tip: run  python generate_dataset.py  first!")
        df = generate_synthetic_samples(n=10000)
    print(f"  Shape: {df.shape}")
    print(df["threat_label"].value_counts().to_string())

    print("\n[2/6] Preprocessing …")
    X_train, X_test, y_train, y_test, scaler, le = preprocess(df)
    print(f"  Train: {X_train.shape}  Test: {X_test.shape}")

    print("\n[3/6] Training models …")
    results, best_name, best_clf = train_and_evaluate(
        build_models(), X_train, X_test, y_train, y_test
    )

    print("\n[4/6] Generating plots …")
    for name, res in results.items():
        plot_confusion_matrix(y_test, res["y_pred"], name, CONFIG["output_dir"])
        plot_roc_curves(y_test, res["y_prob"], name, CONFIG["output_dir"])
    plot_feature_importance(best_clf, CONFIG["output_dir"])

    print("\n[5/6] Explainable AI …")
    shap_exp = run_shap(best_clf, X_train, X_test, CONFIG["output_dir"])
    run_lime(best_clf, X_train, X_test, y_test, CONFIG["output_dir"])

    print("\n[6/6] Saving artifacts …")
    meta_path = save_artifacts(best_clf, scaler, le, CONFIG["output_dir"])
    with open(meta_path) as f: meta = json.load(f)
    meta["performance"] = {n:{"accuracy":r["acc"],"f1":r["f1"],"roc_auc":r["auc"]}
                           for n,r in results.items()}
    meta["best_model"] = best_name

    if args.external:
        if os.path.exists(args.external):
            ext_df = load_csv_dataset(args.external)
            meta["external_performance"] = evaluate_external_dataset(best_clf, scaler, ext_df)
        else:
            print(f"  ⚠️  External CSV not found: {args.external} — skipping external validation")

    with open(meta_path,"w") as f: json.dump(meta, f, indent=2)

    # ── Demo ────────────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  DEMO — Real-Time Inference")
    print("="*60)
    tests = [
        ("https://www.google.com/search?q=python",                          {},                                              "benign"),
        ("http://shop.com/item?id=1' UNION SELECT * FROM users--",           {},                                              "sql_injection"),
        ("http://x.com?q=<script>alert(document.cookie)</script>",           {},                                              "xss"),
        ("http://paypal-login-verify.tk/credentials",                        {},                                              "phishing"),
        ("http://mybank.secure-update.verify.tk/credentials",                {},                                              "phishing"),
        ("https://target.com/api", {"req_per_second":3500,"error_rate":0.80,"unique_ips":250},                               "ddos"),
    ]
    for url, traffic, expected in tests:
        res  = predict_threat(url, traffic, best_clf, scaler, shap_exp)
        icon = "✅" if res["threat_class"] == expected else "⚠️ "
        print(f"\n  {icon} Expected:{expected:<16} Got:{res['threat_class']:<16} Risk:{res['risk_score']}%")
        if res.get("rule_triggered"):
            print(f"      Rule: {res['rule_triggered']}")

    print(f"\n  All artifacts → ./{CONFIG['output_dir']}/")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
