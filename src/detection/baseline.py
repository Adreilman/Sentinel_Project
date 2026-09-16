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

# print(f"rpm_zscore NaN count: {df['rpm_zscore'].isna().sum()}")
# print(f"flag_rpm_anomaly count: {df['flag_rpm_anomaly'].sum()}")

flagged_zscore = df[df["flag_rpm_anomaly"]]
# print(flagged_zscore[[
#     "remote_host", "requests_per_minute", "ip_mean_rpm", "ip_std_rpm", "rpm_zscore"
# ]].sort_values("rpm_zscore", ascending=False).head(10).to_string())


unique_uas_mean = df.groupby("remote_host")["unique_uas_per_ip"].mean()
unique_uas_std = df.groupby("remote_host")["unique_uas_per_ip"].std()
df = df.join(unique_uas_mean.rename("unique_uas_mean"), on="remote_host")
df = df.join(unique_uas_std.rename("unique_uas_std"), on="remote_host")
df["unique_uas_zscore"] = (df["unique_uas_per_ip"] - df["unique_uas_mean"]) / df["unique_uas_std"]

diff = df["unique_uas_per_ip"] - df["unique_uas_mean"]
zero_var_mask = (diff == 0) & (df["unique_uas_std"] == 0)
df.loc[zero_var_mask, "unique_uas_zscore"] = 0

# print(df["unique_uas_zscore"].isna().sum())
# print(unique_uas_std.isna().sum())
# print((unique_uas_std == 0).sum())
df["flag_ua_zscore_anomaly"] = (df["unique_uas_zscore"] > 3) & (df["unique_uas_per_ip"] > 2) & (df["bot_rate"] < 0.9)

# print(df["flag_ua_zscore_anomaly"].sum())
# flagged_ua = df[df["flag_ua_zscore_anomaly"]]
# print(flagged_ua[["remote_host", "unique_uas_per_ip", "unique_uas_mean", "unique_uas_std", "unique_uas_zscore"]].sort_values("unique_uas_zscore", ascending=False).head(10).to_string())
# print(df[df["remote_host"] == "64.233.172.230"]["bot_rate"].unique())


response_bytes_avg_mean = df.groupby("remote_host")["response_bytes_avg"].mean()

response_bytes_avg_std = df.groupby("remote_host")["response_bytes_avg"].std()
df = df.join(response_bytes_avg_mean.rename("response_bytes_avg_mean"), on="remote_host")
df = df.join(response_bytes_avg_std.rename("response_bytes_avg_std"), on="remote_host")
df["response_bytes_avg_zscore"] = (df["response_bytes_avg"] - df["response_bytes_avg_mean"]) / df["response_bytes_avg_std"]
diff = df["response_bytes_avg"] - df["response_bytes_avg_mean"]
zero_var_mask = (diff == 0) & (df["response_bytes_avg_std"] == 0)
df.loc[zero_var_mask, "response_bytes_avg_zscore"] = 0
df["flag_response_bytes_avg_zscore_anomaly"] = (df["response_bytes_avg_zscore"] > 3) & (df["response_bytes_avg"] > 5000) & (df["bot_rate"] < 0.9)

respone_bytes_total_mean = df.groupby("remote_host")["response_bytes_total"].mean()
respone_bytes_total_std = df.groupby("remote_host")["response_bytes_total"].std()
df = df.join(respone_bytes_total_mean.rename("response_bytes_total_mean"), on="remote_host")
df = df.join(respone_bytes_total_std.rename("response_bytes_total_std"), on="remote_host")
df["response_bytes_total_zscore"] = (df["response_bytes_total"] - df["response_bytes_total_mean"]) / df["response_bytes_total_std"]
diff = df["response_bytes_total"] - df["response_bytes_total_mean"]
zero_var_mask = (diff == 0) & (df["response_bytes_total_std"] == 0)
df.loc[zero_var_mask, "response_bytes_total_zscore"] = 0
df["flag_response_bytes_total_zscore_anomaly"] = (df["response_bytes_total_zscore"] > 3) & (df["response_bytes_total"] > 20000) & (df["bot_rate"] < 0.9)


# print(df["flag_response_bytes_avg_zscore_anomaly"].sum())
# print(df["flag_response_bytes_total_zscore_anomaly"].sum())

# flagged_avg = df[df["flag_response_bytes_avg_zscore_anomaly"]]
# print(flagged_avg[["remote_host", "response_bytes_avg", "response_bytes_avg_mean", "response_bytes_avg_std", "response_bytes_avg_zscore"]].sort_values("response_bytes_avg_zscore", ascending=False).head(10).to_string())

# flagged_total = df[df["flag_response_bytes_total_zscore_anomaly"]]
# print(flagged_total[["remote_host", "response_bytes_total", "response_bytes_total_mean", "response_bytes_total_std", "response_bytes_total_zscore"]].sort_values("response_bytes_total_zscore", ascending=False).head(10).to_string())


print(df[df["remote_host"] == "72.52.125.78"][["minute_bucket", "requests_per_minute", "unique_uas_per_ip", "unique_paths_per_ip", "response_bytes_avg", "response_bytes_total", "rpm_zscore", "unique_uas_zscore", "response_bytes_avg_zscore", "response_bytes_total_zscore"]].sort_values("minute_bucket").to_string())


df.to_parquet("data/processed/stage2_flags.parquet")
print("\nSaved: data/processed/stage2_flags.parquet")