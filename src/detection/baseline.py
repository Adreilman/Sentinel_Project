import pandas as pd

df = pd.read_parquet("data/processed/features.parquet")

ip_mean_rpm = df.groupby("remote_host")["requests_per_minute"].mean()
ip_std_rpm = df.groupby("remote_host")["requests_per_minute"].std()

df = df.join(ip_mean_rpm.rename("ip_mean_rpm"), on="remote_host")
df = df.join(ip_std_rpm.rename("ip_std_rpm"), on="remote_host")

df["rpm_zscore"] = (df["requests_per_minute"] - df["ip_mean_rpm"]) / df["ip_std_rpm"]

diff = df["requests_per_minute"] - df["ip_mean_rpm"]
zero_var_mask = (diff == 0) & (df["ip_std_rpm"] == 0)
df.loc[zero_var_mask, "rpm_zscore"] = 0

# NOTE: bot_rate is not a perfect bot signal. user_agents library plus a
# substring check (google/applebot) catches most crawler traffic, but some
# legitimate crawlers (confirmed via manual inspection of 66.249.83.x, part
# of Google's crawler range) send fully unmarked, browser-mimicking UA
# strings with zero identifying text. No UA-content check can catch these -
# closing this gap fully would require IP-range-based bot detection instead.
df["flag_rpm_anomaly"] = (
    (df["rpm_zscore"] > 3) & (df["requests_per_minute"] > 10) & (df["bot_rate"] < 0.9)
)

print(f"rpm_zscore NaN count: {df['rpm_zscore'].isna().sum()}")
print(f"flag_rpm_anomaly count: {df['flag_rpm_anomaly'].sum()}")

flagged_zscore = df[df["flag_rpm_anomaly"]]
print(flagged_zscore[[
    "remote_host", "requests_per_minute", "ip_mean_rpm", "ip_std_rpm", "rpm_zscore"
]].sort_values("rpm_zscore", ascending=False).head(10).to_string())

df.to_parquet("data/processed/stage2_flags.parquet")
print("\nSaved: data/processed/stage2_flags.parquet")