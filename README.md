# Sentinel
## Intelligent Cybersecurity Log Analytics & Anomaly Detection System

Sentinel is a multi-stage cybersecurity log analytics and anomaly detection system designed to analyze large-scale web server access logs and identify suspicious IP-level activity.

The system combines three complementary detection approaches:

1. **Stage 1 — Rule-Based Detection**
2. **Stage 2 — Statistical Baseline Detection**
3. **Stage 3 — Isolation Forest Anomaly Detection**

The outputs from all three stages are combined into a final IP-level detection layer and evaluated against a manually labeled reference set.

---

## 1. Project Overview

Modern web servers generate large volumes of access logs. Suspicious activity can appear as high request volume, unusual user-agent rotation, elevated error or malformed-request rates, abnormal response behavior, or statistically unusual activity from an otherwise familiar IP address.

Sentinel addresses this problem using a layered detection pipeline rather than relying on a single detection technique.

The system first transforms raw Apache access logs into structured request records, aggregates those records into IP-minute behavioral features, applies rule-based and statistical detection techniques, and finally uses an unsupervised Isolation Forest model to identify additional anomalies.

The final system produces an IP-level view of detection activity, including which detection stages identified each IP.

---

## 2. Objectives

The main objectives of Sentinel are:

- Parse and structure large-scale Apache access logs.
- Convert raw requests into behavioral features at IP-minute granularity.
- Detect suspicious behavior using interpretable rule-based logic.
- Identify statistically unusual behavior relative to an IP's own baseline.
- Add unsupervised anomaly detection using Isolation Forest.
- Combine multiple detection stages into a final IP-level result.
- Evaluate the system using manually labeled suspicious and legitimate IP references.

---

## 3. System Architecture

```text
Apache Access Logs
        ↓
   Log Parsing
        ↓
 Feature Engineering
        ↓
 ┌─────────────────────────┐
 │                         │
 ▼                         ▼
Stage 1                  Stage 2
Rule-based               Statistical
Detection                Baseline
 │                         │
 └──────────┬──────────────┘
            ▼
         Stage 3
     Isolation Forest
            │
            ▼
     Final Detection
            │
            ▼
    IP-level Detection
       & Categories
            │
            ▼
     Evaluation Layer
```

### Pipeline flow

**Raw logs → Parsed logs → Behavioral features → Stage 1 / Stage 2 / Stage 3 → Final IP-level detections → Evaluation**

---

## 4. Dataset

Sentinel works with Apache web server access logs containing request-level information such as:

- Remote IP address
- Timestamp
- HTTP request method
- Requested URL path
- Response status
- Response size
- Referrer
- User-agent
- Malformed-request information

The project processes the raw request data into structured Parquet files for efficient downstream analysis.

The feature dataset contains **812,061 IP-minute records**.

---

## 5. Feature Engineering

Features are generated at the **IP-minute** level.

The current feature set contains:

| Feature | Description |
|---|---|
| `requests_per_minute` | Number of requests made by an IP during a minute |
| `unique_uas_per_ip` | Number of distinct user-agents used by the IP |
| `unique_paths_per_ip` | Number of distinct requested paths |
| `error_rate` | Proportion of requests associated with error responses |
| `malformed_rate` | Proportion of malformed requests |
| `bot_rate` | Estimated proportion of traffic identified as crawler/bot-like |
| `response_bytes_avg` | Average response size |
| `response_bytes_total` | Total response bytes during the minute |
| `method_diversity` | Number of distinct HTTP methods used |

These features provide behavioral signals that can be used by multiple detection strategies.

---

# 6. Detection Pipeline

## Stage 1 — Rule-Based Detection

Stage 1 uses interpretable behavioral rules and thresholds.

The main signals include:

- High request volume
- Medium request volume
- Suspicious user-agent rotation
- Elevated error rate
- Elevated malformed-request rate

Known bot/crawler traffic is excluded or gated from relevant rules using the project's bot-rate logic.

The stage assigns a descriptive threat tier based on the combination of rule signals.

### Purpose

Stage 1 is designed to capture obvious and interpretable suspicious behaviors.

### Output

```text
data/processed/stage1_flags.parquet
```

---

## Stage 2 — Statistical Baseline Detection

Stage 2 compares selected behavioral features against an IP-specific statistical baseline.

Per-IP z-scores are calculated for selected features including:

- `requests_per_minute`
- `unique_uas_per_ip`
- `response_bytes_avg`
- `response_bytes_total`

Additional absolute-value floors are used alongside z-score conditions because raw z-scores can become unstable for extremely low-variance IP behavior.

Stage 2 therefore looks for activity that is not only statistically unusual for an IP, but also meaningful in absolute terms.

### Purpose

Stage 2 is designed to detect behavior that deviates from an IP's historical or local baseline.

### Output

```text
data/processed/stage2_flags.parquet
```

---

## Stage 3 — Isolation Forest

Stage 3 introduces unsupervised machine-learning based anomaly detection.

The Isolation Forest uses the following raw behavioral features:

```text
requests_per_minute
unique_uas_per_ip
unique_paths_per_ip
error_rate
response_bytes_avg
response_bytes_total
malformed_rate
method_diversity
```

`bot_rate` was excluded from the first Isolation Forest implementation because the feature contained missing values associated with malformed requests.

The model configuration used in the current pipeline is:

```text
contamination = 0.005
random_state = 42
```

Isolation Forest assigns an anomaly prediction to each IP-minute record.

### Purpose

Stage 3 provides an additional unsupervised perspective and can identify behavior that is unusual in the multidimensional feature space even when it does not satisfy a Stage 1 or Stage 2 rule.

### Output

```text
data/processed/stage3_flags.parquet
```

---

# 7. Final Detection

The outputs from all three stages are combined at the **IP level**.

For each IP, Sentinel records:

```text
stage1_detected
stage2_detected
stage3_detected
```

Stage 3 also contributes anomaly statistics:

```text
anomaly_minutes
min_score
mean_score
```

The final output also contains:

```text
detected_in_any_stage
detection_stage_count
detection_category
```

### Detection categories

The final category is descriptive rather than a threat score:

| Category | Meaning |
|---|---|
| `none` | Not detected by any stage |
| `single_stage` | Detected by one stage |
| `two_stages` | Detected by two stages |
| `all_stages` | Detected by all three stages |

### Final output

```text
data/processed/final_detections.parquet
```

Current final detection category counts:

```text
none           240,163
single_stage    17,297
two_stages         960
all_stages         186
```

Total IPs represented in the final table:

```text
258,606
```

---

# 8. Evaluation Method

The evaluation uses a manually labeled reference set containing:

```text
15 suspicious IPs
15 legitimate IPs
30 total IPs
```

The suspicious reference set is stored in:

```text
data/reference/known_suspects.csv
```

The legitimate reference set is stored in:

```text
data/reference/known_legitimate.csv
```

The legitimate labels were established through documented request-level inspection and previously verified crawler/normal traffic observations.

The evaluation is performed at the **IP level**.

For each stage, an IP is considered detected when that stage has identified the IP in its corresponding output.

The combined detector considers an IP detected when it is detected by at least one of the three stages.

---

# 9. Final Evaluation Results

## Stage 1

```text
Accuracy:    76.67%
Precision:   83.33%
Recall:      66.67%
F1:          74.07%
Specificity: 86.67%
```

Confusion counts:

```text
TP = 10
TN = 13
FP = 2
FN = 5
```

---

## Stage 2

```text
Accuracy:    83.33%
Precision:   85.71%
Recall:      80.00%
F1:          82.76%
Specificity: 86.67%
```

Confusion counts:

```text
TP = 12
TN = 13
FP = 2
FN = 3
```

---

## Stage 3

```text
Accuracy:    70.00%
Precision:   87.50%
Recall:      46.67%
F1:          60.87%
Specificity: 93.33%
```

Confusion counts:

```text
TP = 7
TN = 14
FP = 1
FN = 8
```

---

## Combined Detection

```text
Accuracy:    90.00%
Precision:   83.33%
Recall:      100.00%
F1:          90.91%
Specificity: 80.00%
```

Confusion counts:

```text
TP = 15
TN = 12
FP = 3
FN = 0
```

### Summary table

| Metric | Stage 1 | Stage 2 | Stage 3 | Combined |
|---|---:|---:|---:|---:|
| Accuracy | 76.67% | 83.33% | 70.00% | **90.00%** |
| Precision | 83.33% | 85.71% | 87.50% | **83.33%** |
| Recall | 66.67% | 80.00% | 46.67% | **100.00%** |
| F1 | 74.07% | 82.76% | 60.87% | **90.91%** |
| Specificity | 86.67% | 86.67% | 93.33% | **80.00%** |

---

# 10. Interpretation of Results

The three stages serve different purposes.

### Stage 1

The rule-based stage provides interpretable detection based on clearly defined behavioral conditions.

### Stage 2

The statistical stage adds sensitivity to deviations from an IP-specific behavioral baseline.

### Stage 3

Isolation Forest introduces unsupervised anomaly detection and identifies multidimensional behavior that can differ from normal patterns.

### Combined System

The combined detection layer identifies an IP when any stage detects it.

On the current manually labeled 30-IP reference set, the combined system detected all 15 suspicious reference IPs.

---

# 11. Limitations

- Evaluation uses a manually labeled 30-IP reference set.
- The dataset is not fully ground-truth labeled.
- Metrics therefore do not represent dataset-wide performance.
- Legitimate labels were manually established from observed request behavior.
- Isolation Forest is unsupervised.
- Detection thresholds were selected from dataset analysis and are not universal security thresholds.

---

# 12. Project Structure

```text
Sentinel_Project/
│
├── data/
│   ├── raw/
│   │
│   ├── processed/
│   │   ├── parsed_logs.parquet
│   │   ├── features.parquet
│   │   ├── stage1_flags.parquet
│   │   ├── stage2_flags.parquet
│   │   ├── stage3_flags.parquet
│   │   └── final_detections.parquet
│   │
│   └── reference/
│       ├── known_suspects.csv
│       └── known_legitimate.csv
│
├── src/
│   ├── parsing/
│   │   └── ...
│   │
│   ├── features/
│   │   └── ...
│   │
│   └── detection/
│       ├── rules.py
│       ├── baseline.py
│       ├── isolation_forest.py
│       ├── final_detection.py
│       └── evaluate.py
│
├── reports/
│   └── final_evaluation.txt
│
└── README.md
```

---

# 13. Installation

Create and activate a Python virtual environment:

```bash
python -m venv .venv
```

### Windows

```bash
.venv\\Scripts\\activate
```

### Linux/macOS

```bash
source .venv/bin/activate
```

Install the required Python packages used by the project:

```bash
pip install pandas numpy pyarrow scikit-learn
```

Add any other dependencies required by the existing parsing scripts.

---

# 14. Running the Project

Run the project in pipeline order.

### Step 1 — Parse the raw logs

Run the existing parsing script from:

```text
src/parsing/
```

This produces:

```text
data/processed/parsed_logs.parquet
```

### Step 2 — Build behavioral features

Run the existing feature-generation script from:

```text
src/features/
```

This produces:

```text
data/processed/features.parquet
```

### Step 3 — Run Stage 1

Run the existing Stage 1 / baseline detection implementation.

Expected output:

```text
data/processed/stage1_flags.parquet
```

### Step 4 — Run Stage 2

Run the statistical baseline implementation.

Expected output:

```text
data/processed/stage2_flags.parquet
```

### Step 5 — Run Stage 3

Run:

```bash
python src/detection/isolation_forest.py
```

Expected output:

```text
data/processed/stage3_flags.parquet
```

### Step 6 — Build final detections

Run:

```bash
python src/detection/final_detection.py
```

Expected output:

```text
data/processed/final_detections.parquet
```

### Step 7 — Evaluate

Run:

```bash
python src/detection/evaluate.py
```

This evaluates Stage 1, Stage 2, Stage 3, and the combined detector against the reference IP sets.

---

# 15. Outputs

The main generated artifacts are:

```text
parsed_logs.parquet
features.parquet
stage1_flags.parquet
stage2_flags.parquet
stage3_flags.parquet
final_detections.parquet
```

The final IP-level detection table contains:

```text
remote_host
stage1_detected
stage2_detected
stage3_detected
anomaly_minutes
min_score
mean_score
detected_in_any_stage
detection_stage_count
detection_category
```

---

# 16. Technologies Used

```text
Python
Pandas
NumPy
PyArrow / Parquet
Scikit-learn
Apache Access Logs
Rule-based anomaly detection
Statistical anomaly detection
Isolation Forest
```

---

# 17. Design Principles

### Layered Detection

No single detector is expected to identify every type of suspicious behavior.

### Explainability

Rule-based signals and statistical features provide interpretable reasons for detection.

### Behavioral Analysis

The system works primarily from observed request behavior rather than relying on a single indicator.

### Multi-stage Corroboration

Detection results from multiple stages can be compared at the IP level.

### Reproducibility

Intermediate Parquet outputs allow each processing stage to be inspected and evaluated independently.

---

# 18. Future Improvements

Potential future work includes:

- Expanding the manually labeled evaluation set.
- Adding additional legitimate and suspicious reference samples.
- Improving bot/crawler identification.
- Testing additional statistical baselines.
- Hyperparameter analysis for Isolation Forest.
- Temporal behavioral modeling.
- Alert prioritization based on multiple independent signals.
- Visualization and interactive monitoring of detected IP activity.
- Continuous or streaming log ingestion.
- More extensive validation using independently labeled data.

---

# 19. Final Project Summary

Sentinel is a layered web-log anomaly detection pipeline that transforms raw Apache access logs into behavioral features and applies three complementary detection approaches: rule-based detection, statistical baseline analysis, and Isolation Forest anomaly detection.

The three stages are integrated into an IP-level final detection layer.

On the current manually labeled reference set of 30 IPs — 15 suspicious and 15 legitimate — the combined detector achieved:

```text
Accuracy:    90.00%
Precision:   83.33%
Recall:      100.00%
F1:          90.91%
Specificity: 80.00%
```

These results describe performance on the current manually labeled evaluation set and should not be interpreted as dataset-wide performance.
