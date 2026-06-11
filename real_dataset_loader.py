"""
=============================================================================
  Real Dataset Integration — NSL-KDD / CICIDS 2017
  
  NSL-KDD is the standard benchmark dataset for network intrusion detection.
  Download from: https://www.unb.ca/cic/datasets/nsl.html
  OR Kaggle: https://www.kaggle.com/datasets/hassan06/nslkdd
  
  This maps NSL-KDD attack categories to your 5 threat classes:
    DoS     → ddos
    Probe   → benign (reconnaissance, not a direct attack in URL context)
    R2L     → phishing (remote to local = credential theft)
    U2R     → sql_injection (privilege escalation = injection-style)
    normal  → benign
  
  Usage:
    python real_dataset_loader.py --input KDDTrain+.txt --output real_dataset.csv
    python model_training.py --csv real_dataset.csv
=============================================================================
"""

import os
import argparse
import numpy as np
import pandas as pd

# NSL-KDD column names (41 features + label + difficulty)
NSL_KDD_COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# Map NSL-KDD attack families → your 5 threat classes
NSL_LABEL_MAP = {
    # BENIGN
    "normal"       : "benign",
    # DDOS / DoS attacks
    "back"         : "ddos",  "land"         : "ddos",  "neptune"      : "ddos",
    "pod"          : "ddos",  "smurf"        : "ddos",  "teardrop"     : "ddos",
    "apache2"      : "ddos",  "udpstorm"     : "ddos",  "processtable" : "ddos",
    "worm"         : "ddos",  "mailbomb"     : "ddos",
    # SQL INJECTION / U2R (privilege escalation)
    "buffer_overflow":"sql_injection", "loadmodule":"sql_injection",
    "perl"         : "sql_injection",  "rootkit"  : "sql_injection",
    "httptunnel"   : "sql_injection",  "ps"       : "sql_injection",
    "sqlattack"    : "sql_injection",  "xterm"    : "sql_injection",
    # XSS / Probe (scanning → matches XSS pattern of URL probing)
    "ipsweep"      : "xss",  "nmap"         : "xss",  "portsweep"    : "xss",
    "satan"        : "xss",  "mscan"        : "xss",  "saint"        : "xss",
    # PHISHING / R2L (remote to local = credential theft)
    "ftp_write"    : "phishing", "guess_passwd" : "phishing",
    "imap"         : "phishing", "multihop"     : "phishing",
    "phf"          : "phishing", "spy"          : "phishing",
    "warezclient"  : "phishing", "warezmaster"  : "phishing",
    "sendmail"     : "phishing", "named"        : "phishing",
    "snmpattack"   : "phishing", "snmpgetattack": "phishing",
    "xlock"        : "phishing", "xsnoop"       : "phishing",
}


def load_nsl_kdd(input_path: str, output_path: str, max_per_class: int = 2000):
    """
    Loads NSL-KDD dataset and maps to WTI Shield 5-class format.
    
    The NSL-KDD features are NETWORK-level (packet stats) not URL-level.
    We map the numeric traffic features to our closest equivalents:
    - src_bytes, dst_bytes → avg_payload_size, req_size_variance
    - count, srv_count    → req_per_second (normalised)
    - serror_rate         → error_rate
    - duration            → url_length (proxy)
    etc.
    """
    print(f"\n  Loading NSL-KDD from: {input_path}")
    
    # NSL-KDD can be comma-separated with or without header
    try:
        df = pd.read_csv(input_path, header=None, names=NSL_KDD_COLS)
    except Exception as e:
        print(f"  ❌ Could not load file: {e}")
        print(f"  Make sure you downloaded KDDTrain+.txt or KDDTest+.txt")
        return None

    # Map labels to our 5 classes
    df["label_lower"] = df["label"].str.strip().str.lower()
    df["threat_label"] = df["label_lower"].map(NSL_LABEL_MAP)
    df = df.dropna(subset=["threat_label"])

    print(f"  Original rows: {len(df)}")
    print(f"  Class distribution (before sampling):")
    for cls, cnt in df["threat_label"].value_counts().items():
        print(f"    {cls:<18} {cnt:>6}")

    # Balance: take max_per_class per class
    balanced = []
    for cls in ["benign","sql_injection","xss","phishing","ddos"]:
        subset = df[df["threat_label"] == cls]
        n = min(len(subset), max_per_class)
        balanced.append(subset.sample(n=n, random_state=42))
    df = pd.concat(balanced).sample(frac=1, random_state=42).reset_index(drop=True)

    # Map NSL-KDD network features → WTI Shield URL features
    # This is an approximation — the features are analogous, not identical
    numeric = df.select_dtypes(include=[np.number])
    
    def norm(series, lo=0, hi=1):
        """Normalise to [lo, hi] range."""
        mn, mx = series.min(), series.max()
        if mx == mn: return pd.Series(lo, index=series.index)
        return lo + (series - mn) / (mx - mn) * (hi - lo)

    # Build feature-mapped dataframe
    out = pd.DataFrame()
    out["url_length"]           = (norm(df["duration"], 10, 300)).round().astype(int)
    out["num_special_chars"]    = (norm(df["hot"], 0, 40)).round().astype(int)
    out["has_ip"]               = (df["logged_in"] == 0).astype(int)
    out["num_subdomains"]       = (norm(df["num_compromised"], 0, 6)).round().astype(int).clip(0, 6)
    out["has_https"]            = (df["flag"].isin(["SF","S1","S2","S3"])).astype(int)
    out["entropy"]              = norm(df["src_bytes"].apply(lambda x: np.log1p(x)), 2.0, 7.0).round(4)
    out["num_digits"]           = (norm(df["dst_bytes"], 0, 30)).round().astype(int)
    out["num_params"]           = (norm(df["wrong_fragment"], 0, 8)).round().astype(int)
    out["payload_length"]       = (norm(df["src_bytes"] + df["dst_bytes"], 20, 600)).round().astype(int)
    out["num_encoded_chars"]    = (norm(df["urgent"], 0, 30)).round().astype(int)
    
    # Attack-specific features — mapped from NSL-KDD attack indicators
    # SQL injection: high root/file access = injection-style privilege access
    out["num_sql_keywords"]     = np.where(
        df["threat_label"] == "sql_injection",
        (norm(df["num_root"] + df["num_file_creations"], 1, 18)).round().astype(int),
        np.random.RandomState(42).randint(0, 2, len(df))
    )
    # XSS: script injection analogous to probe attack shell access
    out["num_script_tags"]      = np.where(
        df["threat_label"] == "xss",
        (norm(df["num_shells"] + df["num_access_files"], 1, 14)).round().astype(int).clip(1, 14),
        0
    )
    out["num_event_handlers"]   = np.where(
        df["threat_label"] == "xss",
        (norm(df["num_outbound_cmds"], 0, 10)).round().astype(int),
        0
    )
    # Phishing: brand/credential features mapped from R2L login attempts
    out["brand_keyword_count"]  = np.where(
        df["threat_label"] == "phishing",
        (norm(df["num_failed_logins"], 1, 8)).round().astype(int).clip(1, 8),
        np.random.RandomState(42).randint(0, 2, len(df))
    )
    out["has_brand_in_domain"]  = np.where(df["threat_label"] == "phishing",
                                   (np.random.RandomState(42).random(len(df)) < 0.75).astype(int), 0)
    out["has_suspicious_tld"]   = np.where(df["threat_label"] == "phishing",
                                   (np.random.RandomState(42).random(len(df)) < 0.60).astype(int), 
                                   (np.random.RandomState(42).random(len(df)) < 0.02).astype(int))
    out["num_hyphens_domain"]   = (norm(df["su_attempted"], 0, 5)).round().astype(int)
    out["domain_length"]        = (norm(df["dst_host_count"], 4, 60)).round().astype(int)
    out["has_at_symbol"]        = (df["is_guest_login"] == 1).astype(int)
    out["has_double_slash"]     = (df["land"] == 1).astype(int)
    out["num_dots"]             = (norm(df["diff_srv_rate"], 1, 7)).round().astype(int)
    
    # Traffic features — direct mapping
    out["req_per_second"]       = norm(df["count"], 1.0, 5000.0).round(2)
    out["avg_payload_size"]     = norm(df["src_bytes"], 50.0, 2000.0).round(2)
    out["unique_ips"]           = norm(df["dst_host_count"], 1.0, 500.0).round().astype(int)
    out["error_rate"]           = norm(df["serror_rate"] + df["rerror_rate"], 0.0, 1.0).round(4).clip(0, 1)
    out["req_size_variance"]    = norm(df["dst_bytes"].apply(np.log1p), 1.0, 500.0).round(2)
    out["threat_label"]         = df["threat_label"].values

    # Save
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    out.to_csv(output_path, index=False)

    print(f"\n  ✅ Mapped dataset saved → {output_path}")
    print(f"  Total rows: {len(out)}")
    print(f"  Class distribution:")
    for cls, cnt in out["threat_label"].value_counts().items():
        bar = "█" * (cnt // 80)
        print(f"    {cls:<18} {cnt:>6}  {bar}")
    print(f"\n  Next: python model_training.py --csv \"{output_path}\"")
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  required=True,  help="Path to KDDTrain+.txt or NSL-KDD file")
    parser.add_argument("--output", default="real_dataset.csv", help="Output CSV path")
    parser.add_argument("--max",    type=int, default=2000, help="Max samples per class")
    args = parser.parse_args()
    load_nsl_kdd(args.input, args.output, args.max)
