import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_parquet("data/processed/features.parquet")
known_suspects = pd.read_csv("data/reference/known_suspects.csv")
s1 = pd.read_parquet("data/processed/stage1_flags.parquet")
s2 = pd.read_parquet("data/processed/stage2_flags.parquet")



features = ["requests_per_minute", "unique_uas_per_ip", "unique_paths_per_ip", "error_rate", "response_bytes_avg", "response_bytes_total", "malformed_rate","method_diversity"]


X = df[features].values
clf = IsolationForest(contamination = 0.005, random_state = 42)
clf.fit(X)

predictions = clf.predict(X)
anomaly_mask = predictions == -1
print(f"Number of anomalies found: {anomaly_mask.sum()}")
print(f"Anomalies found: {df[anomaly_mask]['remote_host'].unique()}")
anomaly_score = clf.decision_function(X)
df["anomaly_score"] = anomaly_score

all_ips = df["remote_host"].unique()
s1_matches = s1[
    s1["remote_host"].isin(all_ips)
]

s2_matches = s2[
    s2["remote_host"].isin(all_ips)
]


stage1_detected = (
    s1_matches
    .groupby("remote_host")
    .apply(
        lambda x: (x["threat_tier"] != "none").any()
    )
)

stage2_detected = (
    s2_matches
    .groupby("remote_host")
    .apply(
        lambda x:
            (
                x["flag_rpm_anomaly"]
                | x["flag_ua_zscore_anomaly"]
                | x["flag_response_bytes_avg_zscore_anomaly"]
                | x["flag_response_bytes_total_zscore_anomaly"]
            ).any()
    )
)

stage3_detected = (
    df[anomaly_mask & df["remote_host"].isin(df["remote_host"])]
    .groupby("remote_host")
    .apply(
        lambda x: (x["anomaly_score"] < 0).any()
    )
)


table = pd.DataFrame({
    "remote_host": all_ips,
    "stage1_detected": pd.Series(all_ips).map(stage1_detected).fillna(False).astype(bool),
    "stage2_detected": pd.Series(all_ips).map(stage2_detected).fillna(False).astype(bool),
    "stage3_detected": pd.Series(all_ips).map(stage3_detected).fillna(False).astype(bool)
})

stage3_only = (
    table["stage3_detected"]
    & ~table["stage1_detected"]
    & ~table["stage2_detected"]
).sum()

stage1_and_stage3 = (
    table["stage1_detected"]
    & table["stage3_detected"]
).sum()

stage2_and_stage3 = (
    table["stage2_detected"]
    & table["stage3_detected"]
).sum()

all_three = (
    table["stage1_detected"]
    & table["stage2_detected"]
    & table["stage3_detected"]
).sum()


print(f"\nStage 3 only: {stage3_only}")
print(f"Stage 1 and 3: {stage1_and_stage3}")
print(f"Stage 2 and 3: {stage2_and_stage3}")
print(f"All three: {all_three}")

table["anomaly_minutes"] = (
    table["remote_host"]
    .map(
        df[anomaly_mask]
        .groupby("remote_host")
        .size()
    )
    .fillna(0)
)

table["min_score"] = (
    table["remote_host"]
    .map(
        df[anomaly_mask]
        .groupby("remote_host")["anomaly_score"]
        .min()
    )
)

table["mean_score"] = (
    table["remote_host"]
    .map(
        df[anomaly_mask]
        .groupby("remote_host")["anomaly_score"]
        .mean()
    )
)

print("\nKnown suspects detected in stage 3:")

print(
    table.loc[
        table["remote_host"].isin(known_suspects["remote_host"])
        & table["stage3_detected"],
        ["remote_host", "anomaly_minutes", "min_score", "mean_score"]
    ]
)

stage3_only_summary = table.loc[
    table["stage3_detected"]
    & ~table["stage1_detected"]
    & ~table["stage2_detected"],
    ["remote_host", "anomaly_minutes", "min_score", "mean_score"]
].copy()

stage3_only_summary = stage3_only_summary.sort_values(["anomaly_minutes", "min_score"], ascending=[False,True])

print(stage3_only_summary.head(20).to_string(index=False))

print(df.loc[df["remote_host"] == "148.251.133.251", ["remote_host", "minute_bucket","anomaly_score"] + features].sort_values("anomaly_score",ascending=True).head(20).to_string(index=False))
print(df.loc[df["remote_host"] == "37.98.33.148", ["remote_host", "minute_bucket","anomaly_score"] + features].sort_values("anomaly_score",ascending=True).head(20).to_string(index=False))


stage3_anomalies = df[anomaly_mask]

final_table = (
    stage3_anomalies
    .groupby("remote_host")
    .agg(
        anomaly_minutes=("remote_host", "size"),
        min_score=("anomaly_score", "min"),
        mean_score=("anomaly_score", "mean")
    )
    .reset_index()
)

final_table["stage3_detected"] = True

final_table.to_parquet(
    "data/processed/stage3_flags.parquet",
    index=False
)

print(
    "\nStage 3 anomalies saved to "
    "data/processed/stage3_flags.parquet"
)

# print(df[anomaly_mask][["remote_host", "minute_bucket","anomaly_score"] + features].sort_values("anomaly_score",ascending=True).head(20).to_string(index=False))

