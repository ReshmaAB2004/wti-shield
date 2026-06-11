# WTI Shield — Web Threat Intelligence Chrome Extension

A final year B.Tech project that detects and classifies web threats in real time using Machine Learning. The system combines a trained ML model with a Chrome browser extension to protect users from threats like phishing, DDoS, SQL injection, and XSS attacks.

---

## Features

- Real-time web threat detection via Chrome extension
- Classifies threats into 5 categories: Phishing, DDoS, SQL Injection, XSS, and Benign
- ML model trained on KDD Cup dataset with multiple algorithms compared
- Visual threat reports with SHAP and LIME explainability
- Pop-up alert system when a threat is detected while browsing

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML Model | Python, Scikit-learn, Random Forest, Gradient Boosting, Logistic Regression, DNN |
| Explainability | SHAP, LIME |
| Backend API | Python, Flask |
| Chrome Extension | JavaScript, HTML, CSS |
| Dataset | KDD Cup NSL-KDD dataset + custom real dataset |

---

## Project Structure

```
wti-shield/
│
├── app.py                      # Flask backend API
├── model_training.py           # ML model training script
├── generate_dataset.py         # Dataset generation
├── real_dataset_loader.py      # Loads real-world dataset
├── dnn_comparison.py           # Deep Neural Network comparison
├── test_model.py               # Model testing and evaluation
│
├── threat_model_artifacts/     # Trained models and result graphs
│   ├── model.pkl               # Final trained model
│   ├── confusion_matrix_*.png  # Confusion matrices
│   ├── roc_curves_*.png        # ROC curves
│   ├── shap_bar_*.png          # SHAP explainability charts
│   └── model_metadata.json     # Model info and accuracy
│
└── wti_v9/                     # Chrome Extension
    ├── manifest.json           # Extension config
    ├── popup/                  # Extension popup UI
    ├── background/             # Background service worker
    ├── assistant/              # AI assistant module
    ├── warning/                # Threat warning page
    ├── report/                 # Detailed threat report
    └── icons/                  # Extension icons
```

---

## How to Run

### 1. Run the Flask backend
```bash
pip install flask scikit-learn pandas numpy shap lime
python app.py
```
The API will start at `http://localhost:5000`

### 2. Load the Chrome Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `wti_v9` folder
5. The WTI Shield icon will appear in your browser toolbar

---

## ML Model Performance

The project compared multiple ML algorithms on the NSL-KDD dataset:

- **Random Forest** — Best overall accuracy
- **Gradient Boosting** — Strong precision on rare threat classes
- **Logistic Regression** — Baseline comparison
- **DNN** — Deep learning comparison

Model explainability was implemented using SHAP and LIME to make predictions transparent and interpretable.

---

## Threat Categories Detected

| Threat | Description |
|---|---|
| Phishing | Fake websites attempting to steal credentials |
| DDoS | Distributed Denial of Service attack traffic |
| SQL Injection | Malicious SQL queries in web requests |
| XSS | Cross-Site Scripting attack patterns |
| Benign | Normal, safe web traffic |

---

## Dataset

- **KDD Cup NSL-KDD dataset** — Standard benchmark for network intrusion detection
- Custom real-world dataset collected and preprocessed for browser-based threat patterns
- Note: Dataset files are excluded from this repository due to size. Download NSL-KDD from [https://www.unb.ca/cic/datasets/nsl.html](https://www.unb.ca/cic/datasets/nsl.html)

---

## Author

**Reshma A B**
B.Tech — Artificial Intelligence & Data Science
Arunai Engineering College, Tiruvannamalai
GitHub: [ReshmaAB2004](https://github.com/ReshmaAB2004)

---

## Acknowledgements

- KDD Cup dataset — University of New Brunswick
- SHAP library — Scott Lundberg
- LIME library — Marco Tulio Ribeiro
- Developed as part of Final Year Project, 2026
