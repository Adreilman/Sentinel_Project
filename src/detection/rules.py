import pandas as pd

HIGH_VOLUME_THRESHOLD = 220
MEDIUM_VOLUME_THRESHOLD = 100
UA_ROTATION_THRESHOLD = 3
ERROR_RATE_THRESHOLD = 0.05
MALFORMED_RATE_THRESHOLD = 0.01
BOT_EXCLUSION_THRESHOLD = 0.9
HIGH_SCORE_THRESHOLD = 7
MEDIUM_SCORE_THRESHOLD = 2

df = pd.read_parquet("data/processed/features.parquet")

not_confirmed_bot = df["bot_rate"] < BOT_EXCLUSION_THRESHOLD

df["flag_high_volume"] = (df["requests_per_minute"] > HIGH_VOLUME_THRESHOLD) & not_confirmed_bot
df["flag_medium_volume"] = (df["requests_per_minute"] > MEDIUM_VOLUME_THRESHOLD) & not_confirmed_bot
df["flag_ua_rotation_suspicious"] = (df["unique_uas_per_ip"] >= UA_ROTATION_THRESHOLD) & not_confirmed_bot
df["flag_error_anomaly"] = (df["error_rate"] >= ERROR_RATE_THRESHOLD) & not_confirmed_bot
df["flag_malformed_anomaly"] = (df["malformed_rate"] >= MALFORMED_RATE_THRESHOLD) & not_confirmed_bot

df["threat_score"] = (
    df["flag_high_volume"].astype(int) * 3
    + df["flag_medium_volume"].astype(int) * 1
    + df["flag_ua_rotation_suspicious"].astype(int) * 3
    + df["flag_error_anomaly"].astype(int) * 2
    + df["flag_malformed_anomaly"].astype(int) * 2
)

df["threat_tier"] = "none"
df.loc[df["threat_score"].between(MEDIUM_SCORE_THRESHOLD, HIGH_SCORE_THRESHOLD - 1), "threat_tier"] = "medium"
df.loc[df["threat_score"] >= HIGH_SCORE_THRESHOLD, "threat_tier"] = "high"

print(df["threat_tier"].value_counts())

known_bots = df[df["remote_host"].isin(["66.249.66.91", "66.249.66.93", "207.46.13.177"])]
leaked = known_bots[known_bots["threat_tier"] != "none"]
print(f"\nKnown-bot rows still flagged medium/high: {len(leaked)} of {len(known_bots)}")
if len(leaked) > 0:
    print(leaked[["remote_host", "bot_rate", "threat_score"]].to_string())

high_confidence = df[df["threat_tier"] == "high"].copy()
print(f"\nHigh-priority: {high_confidence['remote_host'].nunique()} distinct IPs, {len(high_confidence)} flagged minutes")
print(high_confidence["requests_per_minute"].describe())

display_columns = [
    "remote_host", "minute_bucket", "requests_per_minute",
    "unique_uas_per_ip", "bot_rate", "error_rate", "malformed_rate",
    "threat_score", "threat_tier"
]
print(high_confidence[display_columns].sort_values("threat_score", ascending=False).to_string(index=False))

df.to_parquet("data/processed/stage1_flags.parquet")
print("\nSaved: data/processed/stage1_flags.parquet")