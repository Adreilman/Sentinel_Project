# Sentinel Streamlit Dashboard

## Run

From the Sentinel project root:

```bash
pip install -r dashboard/requirements.txt
python -m streamlit run dashboard/app.py
```

The dashboard reads:

```text
data/processed/final_detections.parquet
data/processed/features.parquet
```

## Pages

- Overview — project KPIs, stage coverage, categories, and evaluation metrics
- IP Investigation — inspect one IP's stage detections and minute-level behavior
- Detection Results — filter IPs by stage and detection category
- Evaluation — view the final manually labeled reference-set metrics

## Folder

```text
Sentinel_Project/
├── dashboard/
│   ├── app.py
│   ├── requirements.txt
│   ├── run_dashboard.bat
│   ├── run_dashboard.sh
│   └── README.md
├── data/
│   └── processed/
│       ├── features.parquet
│       └── final_detections.parquet
└── ...
```
