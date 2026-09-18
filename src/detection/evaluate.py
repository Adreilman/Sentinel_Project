
import pandas as pd

# =========================================================
# LOAD DATA
# =========================================================

s1 = pd.read_parquet("data/processed/stage1_flags.parquet")
s2 = pd.read_parquet("data/processed/stage2_flags.parquet")

known_suspects = pd.read_csv("data/reference/known_suspects.csv")


# =========================================================
# LOAD STAGE 3 SAFELY
# =========================================================

try:
    s3 = pd.read_parquet("data/processed/stage3_flags.parquet")

except FileNotFoundError:
    s3 = pd.DataFrame(
        columns=[
            "remote_host",
            "anomaly_minutes",
            "min_score",
            "mean_score",
            "stage3_detected"
        ]
    )


required_stage3_columns = [
    "remote_host",
    "anomaly_minutes",
    "min_score",
    "mean_score",
    "stage3_detected"
]

for column in required_stage3_columns:
    if column not in s3.columns:

        if column == "stage3_detected":
            s3[column] = False

        else:
            s3[column] = pd.NA


# =========================================================
# FILTER TO KNOWN SUSPECTS
# =========================================================

s1_matches = s1[
    s1["remote_host"].isin(known_suspects["remote_host"])
]

s2_matches = s2[
    s2["remote_host"].isin(known_suspects["remote_host"])
]

s3_matches = s3[
    s3["remote_host"].isin(known_suspects["remote_host"])
]


# =========================================================
# EXISTING INSPECTION OUTPUT
# =========================================================

print("\n=== STAGE 1 SAMPLE ===")

print(
    s1_matches[
        ["remote_host", "threat_tier"]
    ]
    .head(10)
    .to_string(index=False)
)


print("\n=== STAGE 2 SAMPLE ===")

print(
    s2_matches[
        [
            "remote_host",
            "flag_rpm_anomaly",
            "flag_ua_zscore_anomaly",
            "flag_response_bytes_avg_zscore_anomaly",
            "flag_response_bytes_total_zscore_anomaly"
        ]
    ]
    .head(10)
    .to_string(index=False)
)


# =========================================================
# STAGE 3 SAMPLE
# =========================================================

print("\n=== STAGE 3 SAMPLE ===")

print(
    s3_matches[
        [
            "remote_host",
            "anomaly_minutes",
            "min_score",
            "mean_score"
        ]
    ]
    .head(10)
    .to_string(index=False)
)


# =========================================================
# SPECIFIC STAGE 2 CHECK
# =========================================================

print("\n=== 104.222.32.84 RESPONSE-BYTES-AVG CHECK ===")

print(
    s2_matches[
        s2_matches["remote_host"] == "104.222.32.84"
    ]["flag_response_bytes_avg_zscore_anomaly"].sum()
)


# =========================================================
# STAGE 2 FLAG COUNTS PER IP
# =========================================================

summary = (
    s2_matches
    .groupby("remote_host")[
        [
            "flag_rpm_anomaly",
            "flag_ua_zscore_anomaly",
            "flag_response_bytes_avg_zscore_anomaly",
            "flag_response_bytes_total_zscore_anomaly"
        ]
    ]
    .sum()
)

print("\n=== STAGE 2 FLAG COUNTS PER IP ===")

print(summary)


# =========================================================
# STAGE 1 THREAT-TIER / MALFORMED CHECK
# =========================================================

summ = (
    s1_matches
    .groupby("remote_host")[
        ["threat_tier", "flag_malformed_anomaly"]
    ]
    .value_counts()
)

print("\n=== STAGE 1 THREAT TIER / MALFORMED COUNTS ===")

print(summ)


# =========================================================
# OPTIONAL INVESTIGATION OF 74.82.60.66
# =========================================================

# ft = pd.read_parquet("data/processed/features.parquet")
#
# print(
#     ft[
#         ft["remote_host"] == "74.82.60.66"
#     ][
#         [
#             "minute_bucket",
#             "requests_per_minute",
#             "malformed_rate"
#         ]
#     ]
#     .sort_values("minute_bucket")
#     .to_string(index=False)
# )


# =========================================================
# STAGE 1 IP-LEVEL DETECTION
# =========================================================

stage1_detected = (
    s1_matches
    .groupby("remote_host")
    .apply(
        lambda x: (x["threat_tier"] != "none").any()
    )
)


# =========================================================
# STAGE 2 IP-LEVEL DETECTION
# =========================================================

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


# =========================================================
# STAGE 3 IP-LEVEL DETECTION
# =========================================================

if len(s3_matches) == 0:

    stage3_detected = pd.Series(
        False,
        index=known_suspects["remote_host"]
    )

else:

    stage3_detected = (
        s3_matches
        .groupby("remote_host")["stage3_detected"]
        .any()
    )


# =========================================================
# BUILD FINAL EVALUATION TABLE
# =========================================================

evaluation = pd.DataFrame({
    "remote_host": known_suspects["remote_host"]
})


evaluation["detected_in_stage1"] = (
    evaluation["remote_host"]
    .map(stage1_detected)
    .fillna(False)
    .astype(bool)
)


evaluation["detected_in_stage2"] = (
    evaluation["remote_host"]
    .map(stage2_detected)
    .fillna(False)
    .astype(bool)
)


evaluation["detected_in_stage3"] = (
    evaluation["remote_host"]
    .map(stage3_detected)
    .fillna(False)
    .astype(bool)
)


evaluation["detected_in_any_stage"] = (
    evaluation["detected_in_stage1"]
    | evaluation["detected_in_stage2"]
    | evaluation["detected_in_stage3"]
)


# =========================================================
# PRINT IP-LEVEL TABLE
# =========================================================

print("\n=== IP-LEVEL EVALUATION ===")

print(
    evaluation.to_string(index=False)
)


# =========================================================
# COVERAGE COUNTS
# =========================================================

total_suspects = len(evaluation)


stage1_count = (
    evaluation["detected_in_stage1"]
    .sum()
)


stage2_count = (
    evaluation["detected_in_stage2"]
    .sum()
)


stage3_count = (
    evaluation["detected_in_stage3"]
    .sum()
)


combined_count = (
    evaluation["detected_in_any_stage"]
    .sum()
)


# =========================================================
# UNIQUE CONTRIBUTIONS / OVERLAPS
# =========================================================

stage1_only = (
    evaluation["detected_in_stage1"]
    & ~evaluation["detected_in_stage2"]
    & ~evaluation["detected_in_stage3"]
).sum()


stage2_only = (
    ~evaluation["detected_in_stage1"]
    & evaluation["detected_in_stage2"]
    & ~evaluation["detected_in_stage3"]
).sum()


stage3_only = (
    ~evaluation["detected_in_stage1"]
    & ~evaluation["detected_in_stage2"]
    & evaluation["detected_in_stage3"]
).sum()


stage1_and_stage2 = (
    evaluation["detected_in_stage1"]
    & evaluation["detected_in_stage2"]
).sum()


stage1_and_stage3 = (
    evaluation["detected_in_stage1"]
    & evaluation["detected_in_stage3"]
).sum()


stage2_and_stage3 = (
    evaluation["detected_in_stage2"]
    & evaluation["detected_in_stage3"]
).sum()


all_three = (
    evaluation["detected_in_stage1"]
    & evaluation["detected_in_stage2"]
    & evaluation["detected_in_stage3"]
).sum()


# =========================================================
# COVERAGE SUMMARY
# =========================================================

print("\n=== COVERAGE SUMMARY ===")

print(
    f"Stage 1 coverage: "
    f"{stage1_count}/{total_suspects} "
    f"({stage1_count / total_suspects:.2%})"
)


print(
    f"Stage 2 coverage: "
    f"{stage2_count}/{total_suspects} "
    f"({stage2_count / total_suspects:.2%})"
)


print(
    f"Stage 3 coverage: "
    f"{stage3_count}/{total_suspects} "
    f"({stage3_count / total_suspects:.2%})"
)


print(
    f"Combined coverage: "
    f"{combined_count}/{total_suspects} "
    f"({combined_count / total_suspects:.2%})"
)


print(f"\nStage 1 only: {stage1_only}")
print(f"Stage 2 only: {stage2_only}")
print(f"Stage 3 only: {stage3_only}")
print(f"Stage 1 + Stage 2: {stage1_and_stage2}")
print(f"Stage 1 + Stage 3: {stage1_and_stage3}")
print(f"Stage 2 + Stage 3: {stage2_and_stage3}")
print(f"All three: {all_three}")


# =========================================================
# LIST IPS UNIQUELY DETECTED BY EACH STAGE
# =========================================================

print("\n=== STAGE 1 ONLY ===")

print(
    evaluation.loc[
        evaluation["detected_in_stage1"]
        & ~evaluation["detected_in_stage2"]
        & ~evaluation["detected_in_stage3"],
        "remote_host"
    ].to_list()
)


print("\n=== STAGE 2 ONLY ===")

print(
    evaluation.loc[
        ~evaluation["detected_in_stage1"]
        & evaluation["detected_in_stage2"]
        & ~evaluation["detected_in_stage3"],
        "remote_host"
    ].to_list()
)


print("\n=== STAGE 3 ONLY ===")

print(
    evaluation.loc[
        ~evaluation["detected_in_stage1"]
        & ~evaluation["detected_in_stage2"]
        & evaluation["detected_in_stage3"],
        "remote_host"
    ].to_list()
)


print("\n=== DETECTED BY ALL THREE ===")

print(
    evaluation.loc[
        evaluation["detected_in_stage1"]
        & evaluation["detected_in_stage2"]
        & evaluation["detected_in_stage3"],
        "remote_host"
    ].to_list()
)

df = pd.read_parquet("data/processed/features.parquet")
known_legitimate = pd.read_csv("data/reference/known_legitimate.csv")

legit_ips = known_legitimate["remote_host"]

print("Legitimate IPs found in features:")
print(
    df[df["remote_host"].isin(legit_ips)]["remote_host"]
    .value_counts()
)

print("\nTotal legitimate IPs found:")
print(
    df[df["remote_host"].isin(legit_ips)]["remote_host"].nunique()
)
legit_stage1 = (
    s1[s1["remote_host"].isin(legit_ips)]
    .groupby("remote_host")
    .apply(lambda x: (x["threat_tier"] != "none").any())
)

legit_stage2 = (
    s2[s2["remote_host"].isin(legit_ips)]
    .groupby("remote_host")
    .apply(
        lambda x: (
            x["flag_rpm_anomaly"]
            | x["flag_ua_zscore_anomaly"]
            | x["flag_response_bytes_avg_zscore_anomaly"]
            | x["flag_response_bytes_total_zscore_anomaly"]
        ).any()
    )
)

legit_stage3 = (
    s3[s3["remote_host"].isin(legit_ips)]
    .groupby("remote_host")["stage3_detected"]
    .any()
)

legit_table = pd.DataFrame({
    "remote_host": legit_ips
})

legit_table["stage1_detected"] = (
    legit_table["remote_host"]
    .map(legit_stage1)
    .fillna(False)
    .astype(bool)
)

legit_table["stage2_detected"] = (
    legit_table["remote_host"]
    .map(legit_stage2)
    .fillna(False)
    .astype(bool)
)

legit_table["stage3_detected"] = (
    legit_table["remote_host"]
    .map(legit_stage3)
    .fillna(False)
    .astype(bool)
)

print(legit_table.to_string(index=False))
print("\nStage 1 false positives:", legit_table["stage1_detected"].sum())
print("Stage 2 false positives:", legit_table["stage2_detected"].sum())
print("Stage 3 false positives:", legit_table["stage3_detected"].sum())


# =========================================================
# BUILD LABELED EVALUATION SET
# =========================================================

suspect_eval = evaluation[
    [
        "remote_host",
        "detected_in_stage1",
        "detected_in_stage2",
        "detected_in_stage3"
    ]
].copy()

suspect_eval["actual_label"] = 1


legit_eval = legit_table[
    [
        "remote_host",
        "stage1_detected",
        "stage2_detected",
        "stage3_detected"
    ]
].copy()

legit_eval = legit_eval.rename(
    columns={
        "stage1_detected": "detected_in_stage1",
        "stage2_detected": "detected_in_stage2",
        "stage3_detected": "detected_in_stage3"
    }
)

legit_eval["actual_label"] = 0


labeled_eval = pd.concat(
    [suspect_eval, legit_eval],
    ignore_index=True
)


# =========================================================
# COMBINED DETECTOR
# =========================================================

labeled_eval["detected_in_any_stage"] = (
    labeled_eval["detected_in_stage1"]
    | labeled_eval["detected_in_stage2"]
    | labeled_eval["detected_in_stage3"]
)


# =========================================================
# METRIC CALCULATION
# =========================================================

def calculate_metrics(y_true, y_pred):

    tp = ((y_true == 1) & (y_pred == 1)).sum()
    tn = ((y_true == 0) & (y_pred == 0)).sum()
    fp = ((y_true == 0) & (y_pred == 1)).sum()
    fn = ((y_true == 1) & (y_pred == 0)).sum()

    accuracy = (tp + tn) / (tp + tn + fp + fn)

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0
    )

    specificity = (
        tn / (tn + fp)
        if (tn + fp) > 0
        else 0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "Specificity": specificity
    }


# =========================================================
# CALCULATE FOR EACH STAGE
# =========================================================

stage1_metrics = calculate_metrics(
    labeled_eval["actual_label"],
    labeled_eval["detected_in_stage1"]
)

stage2_metrics = calculate_metrics(
    labeled_eval["actual_label"],
    labeled_eval["detected_in_stage2"]
)

stage3_metrics = calculate_metrics(
    labeled_eval["actual_label"],
    labeled_eval["detected_in_stage3"]
)

combined_metrics = calculate_metrics(
    labeled_eval["actual_label"],
    labeled_eval["detected_in_any_stage"]
)


# =========================================================
# PRINT RESULTS
# =========================================================

metrics_table = pd.DataFrame({
    "Stage 1": stage1_metrics,
    "Stage 2": stage2_metrics,
    "Stage 3": stage3_metrics,
    "Combined": combined_metrics
})

print("\n=== CONFUSION / PERFORMANCE METRICS ===")

print(metrics_table)


print("\n=== PERCENTAGE METRICS ===")

for name, metrics in {
    "Stage 1": stage1_metrics,
    "Stage 2": stage2_metrics,
    "Stage 3": stage3_metrics,
    "Combined": combined_metrics
}.items():

    print(f"\n{name}")
    print(f"Accuracy:    {metrics['Accuracy']:.2%}")
    print(f"Precision:   {metrics['Precision']:.2%}")
    print(f"Recall:      {metrics['Recall']:.2%}")
    print(f"F1:          {metrics['F1']:.2%}")
    print(f"Specificity: {metrics['Specificity']:.2%}")

