import pandas as pd

# =========================================================
# LOAD DATA
# =========================================================

s1 = pd.read_parquet("data/processed/stage1_flags.parquet")
s2 = pd.read_parquet("data/processed/stage2_flags.parquet")
known_suspects = pd.read_csv("data/reference/known_suspects.csv")


# =========================================================
# FILTER TO KNOWN SUSPECTS
# =========================================================

s1_matches = s1[
    s1["remote_host"].isin(known_suspects["remote_host"])
]

s2_matches = s2[
    s2["remote_host"].isin(known_suspects["remote_host"])
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
#
# An IP is considered detected by Stage 1 if at least one
# row for that IP has threat_tier != "none".
#
# Important:
# We evaluate at IP level, not row level.
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
#
# An IP is considered detected by Stage 2 if at least one
# row triggers ANY of the four Stage 2 anomaly flags.
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
# BUILD FINAL EVALUATION TABLE
# =========================================================
#
# Use known_suspects as the master list so every one of the
# 15 reference IPs appears, even if a stage detects none.
# =========================================================

evaluation = pd.DataFrame({
    "remote_host": known_suspects["remote_host"]
})

evaluation["detected_in_stage1"] = (
    evaluation["remote_host"]
    .map(stage1_detected)
    .fillna(False)
)

evaluation["detected_in_stage2"] = (
    evaluation["remote_host"]
    .map(stage2_detected)
    .fillna(False)
)

evaluation["detected_in_either_stage"] = (
    evaluation["detected_in_stage1"]
    | evaluation["detected_in_stage2"]
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

combined_count = (
    evaluation["detected_in_either_stage"]
    .sum()
)


# =========================================================
# UNIQUE CONTRIBUTIONS OF EACH STAGE
# =========================================================

stage1_only = (
    evaluation["detected_in_stage1"]
    & ~evaluation["detected_in_stage2"]
).sum()

stage2_only = (
    ~evaluation["detected_in_stage1"]
    & evaluation["detected_in_stage2"]
).sum()

both_stages = (
    evaluation["detected_in_stage1"]
    & evaluation["detected_in_stage2"]
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
    f"Combined coverage: "
    f"{combined_count}/{total_suspects} "
    f"({combined_count / total_suspects:.2%})"
)

print(f"\nStage 1 only: {stage1_only}")
print(f"Stage 2 only: {stage2_only}")
print(f"Both stages: {both_stages}")


# =========================================================
# LIST IPs UNIQUELY DETECTED BY EACH STAGE
# =========================================================

print("\n=== STAGE 1 ONLY ===")

print(
    evaluation.loc[
        evaluation["detected_in_stage1"]
        & ~evaluation["detected_in_stage2"],
        "remote_host"
    ].to_list()
)


print("\n=== STAGE 2 ONLY ===")

print(
    evaluation.loc[
        ~evaluation["detected_in_stage1"]
        & evaluation["detected_in_stage2"],
        "remote_host"
    ].to_list()
)


print("\n=== DETECTED BY BOTH ===")

print(
    evaluation.loc[
        evaluation["detected_in_stage1"]
        & evaluation["detected_in_stage2"],
        "remote_host"
    ].to_list()
)

