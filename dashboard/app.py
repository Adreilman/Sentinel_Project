from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# ============================================================
# Sentinel Dashboard
# ============================================================

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
DATA_DIR = PROJECT_ROOT / "data" / "processed"


# ------------------------------------------------------------
# Styling
# ------------------------------------------------------------
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    .sentinel-title {
        font-size: 2.4rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
    }

    .sentinel-subtitle {
        color: #6b7280;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }

    [data-testid="stMetric"] {
        border: 1px solid rgba(128, 128, 128, 0.22);
        border-radius: 14px;
        padding: 1rem;
        background: rgba(128, 128, 128, 0.035);
    }

    .status-card {
        border: 1px solid rgba(128, 128, 128, 0.22);
        border-radius: 14px;
        padding: 1rem 1.2rem;
        background: rgba(128, 128, 128, 0.035);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------
# Data loading
# ------------------------------------------------------------
def required_path(name: str) -> Path:
    path = DATA_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}\n"
            f"Run the Sentinel detection pipeline first."
        )
    return path


@st.cache_data(show_spinner="Loading Sentinel detection results...")
def load_final_detections() -> pd.DataFrame:
    return pd.read_parquet(required_path("final_detections.parquet"))


@st.cache_data(show_spinner="Loading Sentinel behavioral features...")
def load_features() -> pd.DataFrame:
    return pd.read_parquet(required_path("features.parquet"))


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def fmt_int(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def fmt_pct(value) -> str:
    return f"{float(value):.2f}%"


def normalize_boolean_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ["stage1_detected", "stage2_detected", "stage3_detected", "detected_in_any_stage"]:
        if col in df.columns:
            df[col] = df[col].fillna(False).astype(bool)
    return df


# ------------------------------------------------------------
# Load data
# ------------------------------------------------------------
try:
    final_df = normalize_boolean_columns(load_final_detections())
    features_df = load_features()
except FileNotFoundError as exc:
    st.error(str(exc))
    st.stop()
except Exception as exc:
    st.error(f"Could not load Sentinel data: {exc}")
    st.stop()


# ------------------------------------------------------------
# Current project metrics
# ------------------------------------------------------------
evaluation = {
    "Stage 1": {
        "Accuracy": 76.67,
        "Precision": 83.33,
        "Recall": 66.67,
        "F1": 74.07,
        "Specificity": 86.67,
    },
    "Stage 2": {
        "Accuracy": 83.33,
        "Precision": 85.71,
        "Recall": 80.00,
        "F1": 82.76,
        "Specificity": 86.67,
    },
    "Stage 3": {
        "Accuracy": 70.00,
        "Precision": 87.50,
        "Recall": 46.67,
        "F1": 60.87,
        "Specificity": 93.33,
    },
    "Combined": {
        "Accuracy": 90.00,
        "Precision": 83.33,
        "Recall": 100.00,
        "F1": 90.91,
        "Specificity": 80.00,
    },
}


# ------------------------------------------------------------
# Sidebar navigation
# ------------------------------------------------------------
st.sidebar.title("🛡️ Sentinel")
st.sidebar.caption("Intelligent Cybersecurity Log Analytics & Anomaly Detection")

page = st.sidebar.radio(
    "Navigation",
    ["Overview", "IP Investigation", "Detection Results", "Evaluation"],
)

st.sidebar.divider()
st.sidebar.caption(
    "Data source: final_detections.parquet + features.parquet"
)


# ============================================================
# OVERVIEW
# ============================================================
if page == "Overview":

    st.markdown('<div class="sentinel-title">Sentinel Dashboard</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sentinel-subtitle">'
        "Multi-stage cybersecurity log analytics and anomaly detection"
        "</div>",
        unsafe_allow_html=True,
    )

    total_ips = len(final_df)
    detected_ips = int(final_df["detected_in_any_stage"].sum())

    if "detection_category" in final_df.columns:
        all_stage_ips = int((final_df["detection_category"] == "all_stages").sum())
    else:
        all_stage_ips = int(
            (
                final_df[
                    ["stage1_detected", "stage2_detected", "stage3_detected"]
                ].all(axis=1)
            ).sum()
        )

    stage1_ips = int(final_df["stage1_detected"].sum())
    stage2_ips = int(final_df["stage2_detected"].sum())
    stage3_ips = int(final_df["stage3_detected"].sum())

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("Total IPs Analyzed", fmt_int(total_ips))

    with c2:
        st.metric("IPs Detected", fmt_int(detected_ips))

    with c3:
        st.metric("All-Stage Detections", fmt_int(all_stage_ips))

    with c4:
        st.metric("Reference Suspicious Detected", "15 / 15")

    st.subheader("Detection Stage Coverage")

    coverage_df = pd.DataFrame(
        {
            "Stage": ["Stage 1", "Stage 2", "Stage 3", "Combined"],
            "Detected IPs": [stage1_ips, stage2_ips, stage3_ips, detected_ips],
        }
    )

    fig = px.bar(
        coverage_df,
        x="Stage",
        y="Detected IPs",
        text="Detected IPs",
        title="IP-level detections by stage",
    )
    fig.update_traces(textposition="outside")
    fig.update_layout(
        height=420,
        margin=dict(l=20, r=20, t=60, b=20),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)

    with left:
        st.subheader("Final Detection Categories")

        category_order = ["none", "single_stage", "two_stages", "all_stages"]
        category_counts = (
            final_df["detection_category"]
            .value_counts()
            .reindex(category_order, fill_value=0)
            .reset_index()
        )
        category_counts.columns = ["Category", "IP Count"]

        fig = px.bar(
            category_counts,
            x="Category",
            y="IP Count",
            text="IP Count",
            title="IP distribution by detection category",
        )
        fig.update_traces(texttemplate="%{text:,}", textposition="outside")
        fig.update_yaxes(tickformat=",")
        fig.update_layout(
            height=420,
            margin=dict(l=20, r=20, t=60, b=20),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Current Reference Evaluation")

        performance_rows = []
        for stage, metrics in evaluation.items():
            performance_rows.append(
                {
                    "Stage": stage,
                    "Accuracy": metrics["Accuracy"],
                    "Precision": metrics["Precision"],
                    "Recall": metrics["Recall"],
                    "F1": metrics["F1"],
                    "Specificity": metrics["Specificity"],
                }
            )

        perf_df = pd.DataFrame(performance_rows)
        fig = px.bar(
            perf_df,
            x="Stage",
            y=["Accuracy", "Precision", "Recall", "F1", "Specificity"],
            barmode="group",
            title="Evaluation metrics",
            range_y=[0, 110],
        )
        fig.update_yaxes(title="Percentage (%)")
        fig.update_layout(height=420, margin=dict(l=20, r=20, t=60, b=20))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Highly Corroborated Detections")

    corroborated = final_df[
        final_df["detection_stage_count"] >= 2
    ].copy()

    if not corroborated.empty:
        cols = [
            c
            for c in [
                "remote_host",
                "stage1_detected",
                "stage2_detected",
                "stage3_detected",
                "detection_stage_count",
                "detection_category",
                "anomaly_minutes",
                "min_score",
                "mean_score",
            ]
            if c in corroborated.columns
        ]

        st.dataframe(
            corroborated.sort_values(
                ["detection_stage_count", "mean_score"],
                ascending=[False, True],
            )[cols].head(50),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# IP INVESTIGATION
# ============================================================
elif page == "IP Investigation":

    st.markdown('<div class="sentinel-title">IP Investigation</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sentinel-subtitle">'
        "Inspect the behavioral timeline and detection stages for an individual IP"
        "</div>",
        unsafe_allow_html=True,
    )

    default_ip = ""
    selected_ip = st.text_input(
        "Enter an IP address",
        value=default_ip,
        placeholder="Example: 151.239.241.163",
    ).strip()

    if not selected_ip:
        st.info("Enter an IP address to investigate.")
        st.stop()

    ip_final = final_df[final_df["remote_host"].astype(str) == selected_ip]

    if ip_final.empty:
        st.warning("This IP is not present in final_detections.parquet.")
        st.stop()

    ip_final = ip_final.iloc[0]

    ip_features = features_df[
        features_df["remote_host"].astype(str) == selected_ip
    ].copy()

    st.subheader(f"Investigation: {selected_ip}")

    d1, d2, d3, d4 = st.columns(4)

    with d1:
        st.metric("Stage 1", "Detected" if ip_final["stage1_detected"] else "Not detected")

    with d2:
        st.metric("Stage 2", "Detected" if ip_final["stage2_detected"] else "Not detected")

    with d3:
        st.metric("Stage 3", "Detected" if ip_final["stage3_detected"] else "Not detected")

    with d4:
        st.metric("Category", str(ip_final["detection_category"]))

    st.divider()

    s1, s2, s3, s4 = st.columns(4)

    with s1:
        st.metric(
            "Detection Stage Count",
            str(int(ip_final["detection_stage_count"])),
        )

    with s2:
        anomaly_minutes = ip_final.get("anomaly_minutes", 0)
        st.metric("Anomaly Minutes", fmt_int(anomaly_minutes))

    with s3:
        min_score = ip_final.get("min_score", None)
        st.metric(
            "Minimum IF Score",
            "N/A" if pd.isna(min_score) else f"{float(min_score):.5f}",
        )

    with s4:
        mean_score = ip_final.get("mean_score", None)
        st.metric(
            "Mean IF Score",
            "N/A" if pd.isna(mean_score) else f"{float(mean_score):.5f}",
        )

    if ip_features.empty:
        st.info("No IP-minute feature records are available for this IP.")
        st.stop()

    if "minute_bucket" in ip_features.columns:
        ip_features = ip_features.sort_values("minute_bucket")

    st.subheader("Behavioral Timeline")

    if "requests_per_minute" in ip_features.columns:
        chart_cols = ["minute_bucket", "requests_per_minute"] if "minute_bucket" in ip_features.columns else ["requests_per_minute"]
        chart_df = ip_features[chart_cols].copy()

        if "minute_bucket" in chart_df.columns:
            fig = px.line(
                chart_df,
                x="minute_bucket",
                y="requests_per_minute",
                markers=True,
                title="Requests per Minute",
            )
            fig.update_yaxes(title="Requests / minute")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Behavioral Metrics")

    metric_cols = [
        "minute_bucket",
        "requests_per_minute",
        "unique_uas_per_ip",
        "unique_paths_per_ip",
        "error_rate",
        "malformed_rate",
        "bot_rate",
        "response_bytes_avg",
        "response_bytes_total",
        "method_diversity",
    ]

    available = [c for c in metric_cols if c in ip_features.columns]

    st.dataframe(
        ip_features[available],
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# DETECTION RESULTS
# ============================================================
elif page == "Detection Results":

    st.markdown('<div class="sentinel-title">Detection Results</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sentinel-subtitle">'
        "Filter and inspect IP-level Sentinel detections"
        "</div>",
        unsafe_allow_html=True,
    )

    selected_stages = st.multiselect(
        "Show IPs detected by",
        ["Stage 1", "Stage 2", "Stage 3"],
        default=["Stage 1", "Stage 2", "Stage 3"],
    )

    categories = [
        "none",
        "single_stage",
        "two_stages",
        "all_stages",
    ]

    selected_categories = st.multiselect(
        "Detection category",
        categories,
        default=categories,
    )

    filtered = final_df[
        final_df["detection_category"].isin(selected_categories)
    ].copy()

    if selected_stages:
        stage_columns = {
            "Stage 1": "stage1_detected",
            "Stage 2": "stage2_detected",
            "Stage 3": "stage3_detected",
        }

        stage_mask = pd.Series(False, index=filtered.index)

        for stage in selected_stages:
            stage_mask |= filtered[stage_columns[stage]]

        # For a useful investigation table, selected stages act as an OR filter.
        filtered = filtered[stage_mask]
    else:
        filtered = filtered.iloc[0:0]

    st.metric("Matching IPs", fmt_int(len(filtered)))

    display_cols = [
        "remote_host",
        "stage1_detected",
        "stage2_detected",
        "stage3_detected",
        "detection_stage_count",
        "detection_category",
        "anomaly_minutes",
        "min_score",
        "mean_score",
    ]

    available_cols = [c for c in display_cols if c in filtered.columns]

    if filtered.empty:
        st.info("No IPs match the selected filters.")
    else:
        sort_col = (
            "detection_stage_count"
            if "detection_stage_count" in filtered.columns
            else "remote_host"
        )

        st.dataframe(
            filtered.sort_values(sort_col, ascending=False)[available_cols].head(1000),
            use_container_width=True,
            hide_index=True,
        )

        st.caption("Displaying up to 1,000 matching IPs.")


# ============================================================
# EVALUATION
# ============================================================
elif page == "Evaluation":

    st.markdown('<div class="sentinel-title">Evaluation</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sentinel-subtitle">'
        "Performance on the manually labeled reference set"
        "</div>",
        unsafe_allow_html=True,
    )

    st.info(
        "Reference set: 30 manually labeled IPs — 15 suspicious and 15 legitimate. "
        "These metrics are not dataset-wide performance estimates."
    )

    performance_rows = []

    for stage, metrics in evaluation.items():
        row = {"Stage": stage}
        row.update(metrics)
        performance_rows.append(row)

    performance_df = pd.DataFrame(performance_rows)

    st.dataframe(
        performance_df,
        use_container_width=True,
        hide_index=True,
    )

    left, right = st.columns(2)

    with left:
        st.subheader("Precision vs Recall")

        fig = go.Figure()

        fig.add_trace(
            go.Bar(
                name="Precision",
                x=performance_df["Stage"],
                y=performance_df["Precision"],
            )
        )

        fig.add_trace(
            go.Bar(
                name="Recall",
                x=performance_df["Stage"],
                y=performance_df["Recall"],
            )
        )

        fig.update_layout(
            barmode="group",
            yaxis_title="Percentage (%)",
            yaxis_range=[0, 110],
            height=420,
        )

        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("F1 and Specificity")

        fig = go.Figure()

        fig.add_trace(
            go.Bar(
                name="F1",
                x=performance_df["Stage"],
                y=performance_df["F1"],
            )
        )

        fig.add_trace(
            go.Bar(
                name="Specificity",
                x=performance_df["Stage"],
                y=performance_df["Specificity"],
            )
        )

        fig.update_layout(
            barmode="group",
            yaxis_title="Percentage (%)",
            yaxis_range=[0, 110],
            height=420,
        )

        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Evaluation Context")

    context_df = pd.DataFrame(
        {
            "Item": [
                "Suspicious reference IPs",
                "Legitimate reference IPs",
                "Total reference IPs",
                "Combined TP",
                "Combined TN",
                "Combined FP",
                "Combined FN",
            ],
            "Value": [
                15,
                15,
                30,
                15,
                12,
                3,
                0,
            ],
        }
    )

    st.dataframe(
        context_df,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Project Limitations")

    limitations = [
        "Evaluation uses a manually labeled 30-IP reference set.",
        "The dataset is not fully ground-truth labeled.",
        "Metrics therefore do not represent dataset-wide performance.",
        "Legitimate labels were manually established from observed request behavior.",
        "Isolation Forest is unsupervised.",
        "Detection thresholds were selected from dataset analysis and are not universal security thresholds.",
    ]

    for item in limitations:
        st.write(f"• {item}")
