from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


st.set_page_config(
    page_title="Sentinel | Cybersecurity Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# For Streamlit deployment, dashboard data is stored here:
DATA_DIR = PROJECT_ROOT / "dashboard" / "data"


# ------------------------------------------------------------
# Data loading
# ------------------------------------------------------------
def required_path(name: str) -> Path:
    path = DATA_DIR / name

    if not path.exists():
        raise FileNotFoundError(
            f"Required dashboard file not found: {path}\n"
            "Make sure the dashboard/data files are present in the repository."
        )

    return path


@st.cache_data(show_spinner="Loading Sentinel dashboard data...")
def load_final_detections() -> pd.DataFrame:
    return pd.read_parquet(
        required_path("final_detections.parquet")
    )


@st.cache_data(show_spinner="Loading Sentinel investigation data...")
def load_features() -> pd.DataFrame:
    return pd.read_parquet(
        required_path("features_dashboard.parquet")
    )