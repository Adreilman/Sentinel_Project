import pandas as pd

stage1 = pd.read_parquet("data/processed/stage1_flags.parquet")
stage2 = pd.read_parquet("data/processed/stage2_flags.parquet")
stage3 = pd.read_parquet("data/processed/stage3_flags.parquet")

# print(stage1.columns.tolist())
# print(stage2.columns.tolist())
# print(stage3.columns.tolist())
# print(stage1.shape)
# print(stage2.shape)
# print(stage3.shape)

stage1_detected = (
    stage1
    .groupby("remote_host")
    .apply(
        lambda x: (x["threat_tier"] != "none").any()
    )
)
stage2_detected = (
    stage2
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
    stage3
    .groupby("remote_host")["stage3_detected"]
    .any()
)
all_ips = pd.Index(
    stage1_detected.index
).union(
    stage2_detected.index
).union(
    stage3_detected.index
)

final_table = pd.DataFrame({
    "remote_host": all_ips
})

final_table["stage1_detected"] = (
    final_table["remote_host"]
    .map(stage1_detected)
    .fillna(False)
    .astype(bool)
)

final_table["stage2_detected"] = (
    final_table["remote_host"]
    .map(stage2_detected)
    .fillna(False)
    .astype(bool)
)

final_table["stage3_detected"] = (
    final_table["remote_host"]
    .map(stage3_detected)
    .fillna(False)
    .astype(bool)
)
final_table["anomaly_minutes"] = (
    final_table["remote_host"]
    .map(stage3.set_index("remote_host")["anomaly_minutes"])
    .fillna(0)
)

final_table["min_score"] = (
    final_table["remote_host"]
    .map(stage3.set_index("remote_host")["min_score"])
)

final_table["mean_score"] = (
    final_table["remote_host"]
    .map(stage3.set_index("remote_host")["mean_score"])
)

final_table["detected_in_any_stage"] = (
    final_table["stage1_detected"]
    | final_table["stage2_detected"]
    | final_table["stage3_detected"]
)

final_table["detection_stage_count"] = (
    final_table["stage1_detected"].astype(int)
    + final_table["stage2_detected"].astype(int)
    + final_table["stage3_detected"].astype(int)
)

final_table["detection_category"] = (
    final_table["detection_stage_count"]
    .map({
        0: "none",
        1: "single_stage",
        2: "two_stages",
        3: "all_stages"
    })
)
# print(final_table["detection_category"].value_counts())

final_table.to_parquet(
    "data/processed/final_detections.parquet",
    index=False
)

print("\nSaved: data/processed/final_detections.parquet")
print(final_table.shape)
print(final_table.head())


candidates = (
    final_table[
        (final_table["detection_stage_count"] == 0)
        & (final_table["stage3_detected"] == False)
    ]["remote_host"]
    .drop_duplicates()
    .sample(30, random_state=42)
)

print(candidates.to_list())