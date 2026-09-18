<div align="center">

# 🛡️ Sentinel
### Intelligent Cybersecurity Log Analytics & Anomaly Detection

*A layered anomaly detection pipeline that turns raw web server logs into behavioral threat signals — combining rules, statistics, and unsupervised ML.*

[![Live Dashboard](https://img.shields.io/badge/Live-Dashboard-blue?style=for-the-badge)](https://ipsdetection.streamlit.app/)

</div>

---

## 🎯 The Result

Three independent detection methods, one combined system, evaluated against a hand-verified reference set:

| | Stage 1<br>Rules | Stage 2<br>Statistics | Stage 3<br>Isolation Forest | 🏆 Combined |
|---|:---:|:---:|:---:|:---:|
| **Recall** | 66.7% | 80.0% | 46.7% | **100%** |
| **Precision** | 83.3% | 85.7% | 87.5% | **83.3%** |
| **F1** | 74.1% | 82.8% | 60.9% | **90.9%** |

**No single method catches everything — that's the whole point.** Stacking three imperfect detectors caught every known suspicious IP in the reference set, something none of them managed alone.

---

## 🧠 Why Layered Detection?

Real attacks don't look the same twice. Sentinel runs three genuinely different lenses over the same traffic:

```
Raw Apache Logs
      │
      ▼
  Parsing + Feature Engineering    (10.3M lines → 812K IP-minute behavioral records)
      │
      ├──────────────┬──────────────┐
      ▼              ▼              ▼
  Stage 1         Stage 2         Stage 3
  Rules           Statistics      Isolation Forest
  (thresholds)    (per-IP         (unsupervised,
                   baselines)      multi-dimensional)
      │              │              │
      └──────────────┴──────────────┘
                     ▼
            Combined Detection
                     ▼
          📊 Streamlit Dashboard
```

| Stage | Catches | Misses |
|---|---|---|
| **Rules** | Obvious, extreme spikes (220+ req/min) | Anything below a fixed threshold, no matter how odd for that IP |
| **Statistics** | "Unusual *for this specific IP*" — a quiet IP suddenly loud | A single suspicious request hidden among otherwise-normal traffic |
| **Isolation Forest** | Multi-dimensional combinations no hand-written rule anticipated | Needs a decent feature set to work with |

---

## 🔍 A Real Finding, Not a Toy Result

During development, three IPs (`74.82.x.x`) slipped past *every* statistical z-score — each had made 40-190 requests looking completely normal, with exactly **one** malformed, protocol-mismatched request buried in the middle. No amount of statistical baselining was ever going to catch that; it took the original rule-based `malformed_rate` check.

That's not a bug — it's the reason this project has three stages instead of one.

**Other honest limitations, found and documented rather than hidden:**
- Bot detection has a real ceiling — some legitimate crawlers (confirmed: parts of Google's IP ranges) send fully unmarked UA strings that no content-based check can catch. Closing this fully would need IP-range detection, not UA parsing.
- An early version of Stage 1 used additive scoring that let weak signals stack into false "high" alerts — including a confirmed Googlebot IP. Found via testing, fixed by requiring genuine multi-signal agreement instead.

---

## 📦 What's Inside

**9 behavioral features**, computed per IP per minute: request volume, user-agent diversity, path diversity, error rate, malformed-request rate, bot classification, response size (avg/total), and HTTP method diversity.

**812,061** IP-minute records · **258,606** distinct IPs analyzed · **30-IP** hand-verified evaluation set (15 suspicious, 15 legitimate)

```
Sentinel_Project/
├── data/{raw, processed, reference}/
├── src/{parsing, features, detection, analysis}/
├── dashboard/          ← Streamlit app
└── reports/            ← generated evaluation charts
```

---

## 🚀 Try It

**[Open the live dashboard →](https://ipsdetection.streamlit.app/)**

Explore per-stage detections, investigate individual IPs, and see the full evaluation breakdown — including where the system doesn't work as well as it looks at first glance.

### Run it locally

```bash
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install pandas numpy pyarrow scikit-learn
pip install -r dashboard/requirements.txt

# Pipeline: parsing → features → stage1 → stage2 → stage3 → final → evaluate
python src/detection/isolation_forest.py
python src/detection/final_detection.py
python src/detection/evaluate.py

# Dashboard
python -m streamlit run dashboard/app.py
```

---

## 🛠️ Built With

`Python` · `Pandas` · `NumPy` · `PyArrow` · `scikit-learn` · `Streamlit` · `Plotly`

---

<div align="center">

*Evaluation metrics reflect performance on a 30-IP hand-labeled reference set, not the full 812K-record dataset. See the dashboard's Evaluation tab and Limitations section for full context.*

</div>