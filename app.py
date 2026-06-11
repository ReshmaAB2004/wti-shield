"""
=============================================================================
  app.py — Flask API Bridge
  Connects your Chrome Extension (extension_v4) to model_training.py

  Run this BEFORE loading the extension:
    pip install flask flask-cors
    python model_training.py          ← generates model.pkl first
    python app.py                     ← starts the API on port 5000

  Extension sends:  POST http://localhost:5000/predict  { url, traffic }
  Extension gets:   { threat_class, confidence, risk_score, shap_top_features, ... }
=============================================================================
"""

import os
import pickle
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Import your ML pipeline ───────────────────────────────────────────────────
from model_training import predict_threat, CONFIG, FEATURE_COLS

app = Flask(__name__)

# Allow Chrome extension (chrome-extension://) to call this API
CORS(app, origins="*", supports_credentials=False)

# ── Load saved model artifacts ────────────────────────────────────────────────
ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "threat_model_artifacts")

def load_artifacts():
    """Load model, scaler, label encoder, and optional SHAP explainer."""
    artifacts = {}
    required  = ["model.pkl", "scaler.pkl", "label_encoder.pkl"]

    for fname in required:
        path = os.path.join(ARTIFACTS_DIR, fname)
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"\n\n  ❌ Missing artifact: {path}"
                f"\n  👉 Run  python model_training.py  first to generate model files.\n"
            )
        with open(path, "rb") as f:
            key = fname.replace(".pkl", "")
            artifacts[key] = pickle.load(f)
        print(f"  ✅ Loaded: {fname}")

    # SHAP explainer is optional — only available after running model_training.py
    shap_path = os.path.join(ARTIFACTS_DIR, "shap_explainer.pkl")
    if os.path.exists(shap_path):
        with open(shap_path, "rb") as f:
            artifacts["shap_explainer"] = pickle.load(f)
        print("  ✅ Loaded: shap_explainer.pkl (XAI enabled)")
    else:
        artifacts["shap_explainer"] = None
        print("  ⚠️  shap_explainer.pkl not found — SHAP explanations disabled")

    return artifacts

print("\n" + "="*55)
print("  WTI Shield — Flask API  (connecting extension to ML)")
print("="*55)
print("\n  Loading model artifacts …")
try:
    ARTIFACTS = load_artifacts()
    print("\n  ✅ All artifacts loaded. API is ready.\n")
except FileNotFoundError as e:
    print(e)
    exit(1)

# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check — extension pings this to see if Flask is running."""
    return jsonify({
        "status"         : "ok",
        "model"          : "loaded",
        "shap_available" : ARTIFACTS["shap_explainer"] is not None,
        "threat_classes" : CONFIG["threat_classes"],
        "feature_count"  : len(FEATURE_COLS),
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Main prediction endpoint.

    Request body (JSON):
        {
          "url"    : "http://example.com/page?q=test",
          "traffic": {                          ← optional
            "req_per_second"   : 1,
            "avg_payload_size" : 300,
            "unique_ips"       : 1,
            "error_rate"       : 0.0,
            "req_size_variance": 20
          }
        }

    Response (JSON):
        {
          "url"              : "...",
          "threat_class"     : "benign" | "sql_injection" | "xss" | "phishing" | "ddos",
          "confidence"       : 0.9312,
          "risk_score"       : 93.1,
          "is_malicious"     : false,
          "severity"         : "LOW" | "MEDIUM" | "HIGH",
          "rule_triggered"   : null | "SQL rule (3 keywords)",
          "all_probs"        : { "benign": 0.93, "sql_injection": 0.02, ... },
          "shap_top_features": [ { "feature": "...", "impact": 0.12 }, ... ],
          "source"           : "ml_model"
        }
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url     = str(data.get("url", "")).strip()
    traffic = data.get("traffic", {})

    if not url:
        return jsonify({"error": "URL is empty"}), 400

    # ── Run ML prediction ─────────────────────────────────────────────────────
    try:
        result = predict_threat(
            url             = url,
            traffic_features= traffic,
            model           = ARTIFACTS["model"],
            scaler          = ARTIFACTS["scaler"],
            shap_explainer  = ARTIFACTS["shap_explainer"],
            fetch_content   = False,   # keep it fast for real-time extension use
        )
        result["source"] = "ml_model"
        return jsonify(result)

    except Exception as e:
        print(f"  [ERROR] Prediction failed for {url[:60]}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    """
    Batch prediction for multiple URLs at once.

    Request: { "urls": ["http://...", "http://..."] }
    Response: { "results": [ {...}, {...} ] }
    """
    data = request.get_json(silent=True)
    if not data or "urls" not in data:
        return jsonify({"error": "Missing 'urls' in request body"}), 400

    urls    = data["urls"][:50]    # cap at 50 per batch
    results = []
    for url in urls:
        try:
            r = predict_threat(
                url              = str(url),
                traffic_features = {},
                model            = ARTIFACTS["model"],
                scaler           = ARTIFACTS["scaler"],
                shap_explainer   = None,   # skip SHAP for batch speed
            )
            r["source"] = "ml_model"
            results.append(r)
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return jsonify({"results": results, "count": len(results)})


@app.route("/model/info", methods=["GET"])
def model_info():
    """Return model metadata — useful for the popup's info panel."""
    meta_path = os.path.join(ARTIFACTS_DIR, "model_metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        return jsonify(meta)
    return jsonify({"error": "model_metadata.json not found"}), 404


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("  Starting Flask server on http://localhost:5000")
    print("  Extension will connect automatically when loaded in Chrome.\n")
    print("  Endpoints:")
    print("    GET  /health         — API status check")
    print("    POST /predict        — single URL prediction")
    print("    POST /predict/batch  — multiple URLs")
    print("    GET  /model/info     — model metadata")
    print("\n  Press Ctrl+C to stop.\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
