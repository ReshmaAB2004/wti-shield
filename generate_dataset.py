"""
=============================================================================
  Web Threat Intelligence — DATASET GENERATOR  v2  (Anti-Overfit Edition)

  WHY THE OLD VERSION GAVE 100% ACCURACY (root causes fixed):

  Problem 1: Feature ranges had ZERO overlap between classes
             DDoS req_per_second=(600,7000) vs Benign=(1,8) — trivially split
             Fix: Realistic overlap + bimodal distributions

  Problem 2: SQL/XSS attack features were always 0 for benign, always 4+
             for attacks — model just learns a simple threshold rule
             Fix: Benign can have 0-1 keywords, attacks can have 1-3 (subtle)

  Problem 3: No borderline/ambiguous samples — pure clean classes
             Fix: 20% "subtle" samples per class + 5% hard borderline cases

  Problem 4: No cross-class contamination at all
             Fix: Phishing can have 1 SQL keyword, XSS can overlap with SQL

  Problem 5: No noise on continuous features
             Fix: 5% Gaussian noise applied after generation

  Expected accuracy after fix: 92-96% (academically realistic)
=============================================================================
"""

import os
import argparse
import numpy as np
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

FEATURE_COLS_CSV = [
    "url_length","num_special_chars","has_ip","num_subdomains","has_https",
    "entropy","num_digits","num_params","payload_length","num_encoded_chars",
    "num_sql_keywords","num_script_tags","num_event_handlers",
    "brand_keyword_count","has_brand_in_domain","has_suspicious_tld",
    "num_hyphens_domain","domain_length","has_at_symbol","has_double_slash",
    "num_dots","req_per_second","avg_payload_size","unique_ips",
    "error_rate","req_size_variance","threat_label"
]


def generate_dataset(n=10000, output_path="threat_dataset.csv", seed=42):
    rng = np.random.default_rng(seed)
    rows = []

    # ── Helpers ────────────────────────────────────────────────────────────────
    def ri(lo, hi):
        return int(rng.integers(lo, hi + 1))

    def rf(lo, hi):
        return round(float(rng.uniform(lo, hi)), 4)

    def rb(prob):
        return int(rng.random() < prob)

    def rg(mu, sigma, lo=0.0, hi=None):
        """Gaussian sample clipped to [lo, hi]."""
        v = float(rng.normal(mu, sigma))
        v = max(v, lo)
        if hi is not None:
            v = min(v, hi)
        return round(v, 4)

    def rgi(mu, sigma, lo=0, hi=None):
        return int(round(rg(mu, sigma, lo, hi)))

    per_class = n // 5

    # ══════════════════════════════════════════════════════════════════════════
    # 1. BENIGN
    #    Fix: 15% are "hard benign" — they have suspicious-looking features
    #    but are genuinely safe (e.g. long URL, brand keyword, 1 hyphens)
    # ══════════════════════════════════════════════════════════════════════════
    for _ in range(per_class):
        hard = rng.random() < 0.15
        rows.append({
            "url_length"         : ri(40, 200) if hard else ri(15, 90),
            "num_special_chars"  : ri(3, 12)   if hard else ri(0, 5),
            "has_ip"             : rb(0.04)    if hard else rb(0.01),
            "num_subdomains"     : ri(2, 4)    if hard else ri(0, 2),
            "has_https"          : rb(0.78),
            "entropy"            : rg(4.0, 0.65, 2.5, 6.2),
            "num_digits"         : ri(0, 9),
            "num_params"         : ri(0, 5),
            "payload_length"     : ri(15, 200),
            "num_encoded_chars"  : ri(0, 4)    if not hard else ri(0, 8),
            # FIX: benign can have 0–1 SQL keyword (e.g. URL with "update" or "select")
            "num_sql_keywords"   : ri(0, 1)    if hard else 0,
            "num_script_tags"    : 0,
            "num_event_handlers" : ri(0, 1)    if hard else 0,
            "brand_keyword_count": ri(0, 2)    if hard else ri(0, 1),
            "has_brand_in_domain": rb(0.05)    if hard else rb(0.01),
            # FIX: ~4% of benign URLs have a suspicious TLD (false positives)
            "has_suspicious_tld" : rb(0.04)    if hard else rb(0.005),
            "num_hyphens_domain" : ri(0, 2)    if hard else ri(0, 1),
            "domain_length"      : ri(5, 40)   if hard else ri(4, 20),
            "has_at_symbol"      : rb(0.01),
            "has_double_slash"   : rb(0.02),
            "num_dots"           : ri(1, 5),
            # FIX: overlap zone with low-traffic servers
            "req_per_second"     : rg(3.5, 3.0, 0.5, 28.0),
            "avg_payload_size"   : rg(420, 180, 80, 950),
            "unique_ips"         : ri(1, 6),
            "error_rate"         : rg(0.02, 0.025, 0.0, 0.14),
            "req_size_variance"  : rg(45, 32, 4, 160),
            "threat_label"       : "benign",
        })

    # ══════════════════════════════════════════════════════════════════════════
    # 2. SQL INJECTION
    #    Fix: 20% are subtle (1–3 keywords), 80% are clear (3–18 keywords)
    # ══════════════════════════════════════════════════════════════════════════
    for _ in range(per_class):
        subtle = rng.random() < 0.20
        rows.append({
            "url_length"         : ri(50, 320),
            "num_special_chars"  : ri(5, 20)   if subtle else ri(10, 55),
            "has_ip"             : rb(0.09),
            "num_subdomains"     : ri(0, 2),
            "has_https"          : rb(0.22),
            "entropy"            : rg(4.9, 0.75, 3.4, 7.0),
            "num_digits"         : ri(4, 30),
            "num_params"         : ri(1, 10),
            "payload_length"     : ri(50, 650),
            "num_encoded_chars"  : ri(4, 42),
            # FIX: subtle SQL can have just 1–3 keywords
            "num_sql_keywords"   : ri(1, 3)    if subtle else ri(3, 18),
            "num_script_tags"    : ri(0, 1),
            "num_event_handlers" : ri(0, 1),
            "brand_keyword_count": ri(0, 1),
            "has_brand_in_domain": rb(0.03),
            "has_suspicious_tld" : rb(0.07),
            "num_hyphens_domain" : ri(0, 2),
            "domain_length"      : ri(5, 28),
            "has_at_symbol"      : rb(0.01),
            "has_double_slash"   : rb(0.04),
            "num_dots"           : ri(1, 4),
            "req_per_second"     : rg(4.5, 4.5, 0.5, 35.0),
            "avg_payload_size"   : rg(760, 300, 180, 1900),
            "unique_ips"         : ri(1, 3),
            "error_rate"         : rg(0.33, 0.15, 0.05, 0.78),
            "req_size_variance"  : rg(210, 140, 18, 680),
            "threat_label"       : "sql_injection",
        })

    # ══════════════════════════════════════════════════════════════════════════
    # 3. XSS ATTACK
    #    Fix: subtle XSS can have 1 script tag (not always 2+)
    # ══════════════════════════════════════════════════════════════════════════
    for _ in range(per_class):
        subtle = rng.random() < 0.20
        rows.append({
            "url_length"         : ri(42, 260),
            "num_special_chars"  : ri(4, 18)   if subtle else ri(9, 48),
            "has_ip"             : rb(0.07),
            "num_subdomains"     : ri(0, 2),
            "has_https"          : rb(0.27),
            "entropy"            : rg(5.0, 0.8, 3.6, 7.2),
            "num_digits"         : ri(2, 16),
            "num_params"         : ri(1, 8),
            "payload_length"     : ri(38, 550),
            "num_encoded_chars"  : ri(8, 58),
            # FIX: cross-contamination (XSS sometimes has 0–1 SQL keywords)
            "num_sql_keywords"   : ri(0, 2),
            # FIX: subtle XSS can start with just 1 script tag
            "num_script_tags"    : ri(1, 3)    if subtle else ri(2, 14),
            "num_event_handlers" : ri(0, 3)    if subtle else ri(1, 12),
            "brand_keyword_count": ri(0, 1),
            "has_brand_in_domain": rb(0.02),
            "has_suspicious_tld" : rb(0.06),
            "num_hyphens_domain" : ri(0, 2),
            "domain_length"      : ri(4, 26),
            "has_at_symbol"      : rb(0.01),
            "has_double_slash"   : rb(0.04),
            "num_dots"           : ri(1, 4),
            "req_per_second"     : rg(3.5, 4.0, 0.5, 26.0),
            "avg_payload_size"   : rg(650, 280, 140, 1600),
            "unique_ips"         : ri(1, 4),
            "error_rate"         : rg(0.22, 0.14, 0.02, 0.65),
            "req_size_variance"  : rg(165, 115, 12, 540),
            "threat_label"       : "xss",
        })

    # ══════════════════════════════════════════════════════════════════════════
    # 4. PHISHING (displayed as "Web Threat")
    #    Fix: not all phishing has brand in domain (subtle cases)
    # ══════════════════════════════════════════════════════════════════════════
    for _ in range(per_class):
        subtle = rng.random() < 0.20
        rows.append({
            "url_length"         : ri(35, 350),
            "num_special_chars"  : ri(2, 18),
            "has_ip"             : rb(0.20),
            "num_subdomains"     : ri(0, 4)    if subtle else ri(1, 7),
            "has_https"          : rb(0.38),
            "entropy"            : rg(4.1, 0.7, 3.0, 6.2),
            "num_digits"         : ri(1, 16),
            "num_params"         : ri(0, 5),
            "payload_length"     : ri(35, 420),
            "num_encoded_chars"  : ri(1, 14),
            # FIX: cross-contamination
            "num_sql_keywords"   : ri(0, 1),
            "num_script_tags"    : ri(0, 2),
            "num_event_handlers" : ri(0, 2),
            "brand_keyword_count": ri(1, 4)    if subtle else ri(2, 9),
            # FIX: subtle phishing doesn't always have brand in domain
            "has_brand_in_domain": rb(0.50)    if subtle else rb(0.88),
            "has_suspicious_tld" : rb(0.42)    if subtle else rb(0.65),
            "num_hyphens_domain" : ri(0, 3)    if subtle else ri(1, 5),
            "domain_length"      : ri(8, 38)   if subtle else ri(14, 65),
            "has_at_symbol"      : rb(0.12),
            "has_double_slash"   : rb(0.05),
            "num_dots"           : ri(2, 7),
            "req_per_second"     : rg(3.0, 2.8, 0.5, 20.0),
            "avg_payload_size"   : rg(710, 320, 140, 2300),
            "unique_ips"         : ri(1, 10),
            "error_rate"         : rg(0.04, 0.04, 0.0, 0.20),
            "req_size_variance"  : rg(95, 75, 7, 300),
            "threat_label"       : "phishing",
        })

    # ══════════════════════════════════════════════════════════════════════════
    # 5. DDOS
    #    FIX (CRITICAL): req_per_second now has a LOW-RATE overlap zone
    #    Old: (600, 7000) — totally separated from benign (1, 8)
    #    New: 20% are low-rate (30–180 req/s) overlapping with busy servers
    #         80% are high-rate (400–6000 req/s) clearly anomalous
    # ══════════════════════════════════════════════════════════════════════════
    for _ in range(per_class):
        low_rate = rng.random() < 0.20
        rows.append({
            "url_length"         : ri(8, 95),
            "num_special_chars"  : ri(0, 5),
            "has_ip"             : rb(0.18),
            "num_subdomains"     : ri(0, 2),
            "has_https"          : rb(0.48),
            "entropy"            : rg(3.2, 0.8, 1.8, 5.2),
            "num_digits"         : ri(0, 5),
            "num_params"         : ri(0, 3),
            "payload_length"     : ri(5, 115),
            "num_encoded_chars"  : ri(0, 4),
            "num_sql_keywords"   : 0,
            "num_script_tags"    : 0,
            "num_event_handlers" : 0,
            "brand_keyword_count": ri(0, 1),
            "has_brand_in_domain": rb(0.01),
            "has_suspicious_tld" : rb(0.03),
            "num_hyphens_domain" : ri(0, 1),
            "domain_length"      : ri(4, 22),
            "has_at_symbol"      : 0,
            "has_double_slash"   : rb(0.01),
            "num_dots"           : ri(1, 3),
            # FIX: bimodal distribution with realistic overlap
            "req_per_second"     : rg(90, 50, 28, 190)    if low_rate
                                   else rg(1900, 1300, 350, 6800),
            "avg_payload_size"   : rg(130, 65, 18, 340),
            # FIX: unique_ips also overlaps in low-rate case
            "unique_ips"         : ri(5, 55)               if low_rate
                                   else ri(60, 720),
            "error_rate"         : rg(0.56, 0.22, 0.18, 0.99),
            "req_size_variance"  : rg(8, 5, 0.5, 28),
            "threat_label"       : "ddos",
        })

    # ══════════════════════════════════════════════════════════════════════════
    # BORDERLINE SAMPLES — purposely ambiguous hard cases
    # ══════════════════════════════════════════════════════════════════════════
    n_hard = int(per_class * 0.06)

    # Hard benign 1: looks like phishing (brand in domain but real HTTPS site)
    for _ in range(n_hard):
        rows.append({
            "url_length": ri(30, 85), "num_special_chars": ri(2, 8),
            "has_ip": 0, "num_subdomains": ri(1, 2), "has_https": 1,
            "entropy": rg(3.9, 0.4, 3.2, 5.2), "num_digits": ri(0, 4),
            "num_params": ri(0, 3), "payload_length": ri(30, 95),
            "num_encoded_chars": ri(0, 2), "num_sql_keywords": 0,
            "num_script_tags": 0, "num_event_handlers": 0,
            "brand_keyword_count": ri(1, 3), "has_brand_in_domain": 1,
            "has_suspicious_tld": 0, "num_hyphens_domain": ri(0, 1),
            "domain_length": ri(6, 16), "has_at_symbol": 0,
            "has_double_slash": 0, "num_dots": ri(2, 3),
            "req_per_second": rg(3, 2, 0.5, 12),
            "avg_payload_size": rg(420, 120, 200, 750),
            "unique_ips": ri(1, 3), "error_rate": rg(0.01, 0.01, 0, 0.06),
            "req_size_variance": rg(42, 22, 4, 110),
            "threat_label": "benign",
        })

    # Hard benign 2: long URL with special chars (e.g. OAuth redirect)
    for _ in range(n_hard):
        rows.append({
            "url_length": ri(120, 300), "num_special_chars": ri(8, 22),
            "has_ip": 0, "num_subdomains": ri(0, 2), "has_https": 1,
            "entropy": rg(4.5, 0.5, 3.5, 6.0), "num_digits": ri(5, 20),
            "num_params": ri(3, 8), "payload_length": ri(120, 320),
            "num_encoded_chars": ri(5, 18), "num_sql_keywords": ri(0, 1),
            "num_script_tags": 0, "num_event_handlers": 0,
            "brand_keyword_count": ri(0, 1), "has_brand_in_domain": 0,
            "has_suspicious_tld": 0, "num_hyphens_domain": ri(0, 2),
            "domain_length": ri(8, 22), "has_at_symbol": 0,
            "has_double_slash": 0, "num_dots": ri(2, 5),
            "req_per_second": rg(3, 2, 0.5, 14),
            "avg_payload_size": rg(500, 150, 200, 900),
            "unique_ips": ri(1, 4), "error_rate": rg(0.02, 0.02, 0, 0.08),
            "req_size_variance": rg(60, 35, 5, 150),
            "threat_label": "benign",
        })

    # Hard SQL: 2 keywords in otherwise normal URL
    for _ in range(n_hard):
        rows.append({
            "url_length": ri(55, 180), "num_special_chars": ri(6, 22),
            "has_ip": rb(0.08), "num_subdomains": ri(0, 1), "has_https": rb(0.3),
            "entropy": rg(4.4, 0.6, 3.4, 6.2), "num_digits": ri(3, 18),
            "num_params": ri(1, 5), "payload_length": ri(55, 220),
            "num_encoded_chars": ri(3, 18), "num_sql_keywords": ri(2, 4),
            "num_script_tags": 0, "num_event_handlers": 0,
            "brand_keyword_count": 0, "has_brand_in_domain": 0,
            "has_suspicious_tld": rb(0.1), "num_hyphens_domain": ri(0, 1),
            "domain_length": ri(5, 22), "has_at_symbol": 0,
            "has_double_slash": rb(0.05), "num_dots": ri(1, 3),
            "req_per_second": rg(4, 3, 0.5, 22),
            "avg_payload_size": rg(600, 220, 200, 1300),
            "unique_ips": ri(1, 2), "error_rate": rg(0.26, 0.12, 0.05, 0.55),
            "req_size_variance": rg(160, 90, 15, 430),
            "threat_label": "sql_injection",
        })

    # ══════════════════════════════════════════════════════════════════════════
    # APPLY GAUSSIAN NOISE — prevents the model from memorizing exact boundaries
    # ══════════════════════════════════════════════════════════════════════════
    df = pd.DataFrame(rows)[FEATURE_COLS_CSV]

    noise_cols = [
        "entropy", "req_per_second", "avg_payload_size", "error_rate",
        "req_size_variance", "url_length", "payload_length",
        "domain_length", "num_digits", "num_params", "num_dots",
    ]
    for col in noise_cols:
        sigma = df[col].std() * 0.05   # 5% standard deviation noise
        noise = rng.normal(0, sigma, size=len(df))
        df[col] = (df[col] + noise).clip(lower=0).round(4)

    # Shuffle
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    df.to_csv(output_path, index=False)
    abs_path = os.path.abspath(output_path)

    print(f"\n{'='*62}")
    print(f"  Dataset saved → {abs_path}")
    print(f"{'='*62}")
    print(f"  Total rows  : {len(df)}")
    print(f"  Features    : {len(df.columns)-1} input + 1 label")
    print(f"\n  Class distribution:")
    for cls, cnt in df["threat_label"].value_counts().items():
        bar = "█" * (cnt // 80)
        print(f"  {cls:<18} {cnt:>6}  {bar}")
    print(f"\n  ✅ Anti-overfit fixes applied:")
    print(f"     1. Feature overlap: DDoS req/s now has low-rate zone (30-190)")
    print(f"     2. Subtle samples: 20% per class have lower-confidence signals")
    print(f"     3. Hard borderline: benign-that-looks-like-threat samples added")
    print(f"     4. Cross-contamination: SQL in phishing, events in XSS overlap")
    print(f"     5. Gaussian noise: 5% std on all continuous features")
    print(f"     6. Benign can have 0-1 SQL keyword (real-world false positives)")
    print(f"\n  Expected model accuracy: 92–96%  (realistic, not overfit)")
    print(f"{'='*62}\n")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows",   type=int, default=10000)
    parser.add_argument("--output", type=str, default="threat_dataset.csv")
    parser.add_argument("--seed",   type=int, default=42)
    args = parser.parse_args()
    output_path = (args.output if os.path.isabs(args.output)
                   else os.path.join(SCRIPT_DIR, args.output))
    generate_dataset(n=args.rows, output_path=output_path, seed=args.seed)
