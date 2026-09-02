import pandas as pd
from user_agents import parse


df = pd.read_parquet('data/processed/parsed_logs.parquet')
df["time_received_isoformat"] = pd.to_datetime(df["time_received_isoformat"],format='%Y-%m-%dT%H:%M:%S')

df["minute_bucket"] = df["time_received_isoformat"].dt.floor('min')

requests_per_minute = df.groupby(["remote_host","minute_bucket"]).size()


unique_uas_per_ip = df.groupby(["remote_host", "minute_bucket"])["request_header_user_agent"].nunique()

unique_pr_per_ip = df.groupby(["remote_host", "minute_bucket"])["request_url_path"].nunique()

df["is_error"] = (df["status"]>=400)

error_rate_by_ip = df.groupby(["remote_host"])["is_error"].mean()

malformed_request_rate = df.groupby(["remote_host"])["malformed_request"].mean()

request_count_by_ip = df.groupby("remote_host").size()

malformed_summary = pd.DataFrame({
    "malformed_rate": malformed_request_rate,
    "request_count": request_count_by_ip
})


unique_uas = df[df["request_header_user_agent"].notna()]["request_header_user_agent"].unique()
bot_lookup = {ua: parse(ua).is_bot for ua in unique_uas}
df["is_bot"] = df["request_header_user_agent"].map(bot_lookup)

features = pd.DataFrame({
    "requests_per_minute": requests_per_minute,
    "unique_uas_per_ip": unique_uas_per_ip,
    "unique_paths_per_ip": unique_pr_per_ip,
})

features = features.join(error_rate_by_ip.rename("error_rate"))
features = features.join(malformed_request_rate.rename("malformed_rate"))

bot_rate_by_ip = df.groupby(["remote_host","minute_bucket"])["is_bot"].mean()
features = features.join(bot_rate_by_ip.rename("bot_rate"))


response_bytes_avg = df.groupby(["remote_host","minute_bucket"])["response_bytes_clf"].mean()
response_bytes_total = df.groupby(["remote_host","minute_bucket"])["response_bytes_clf"].sum()
features = features.join(response_bytes_avg.rename("response_bytes_avg"))
features = features.join(response_bytes_total.rename("response_bytes_total"))


# print(features["response_bytes_avg"].describe())
# print(features["response_bytes_total"].describe())
# print(features.sort_values("response_bytes_total", ascending=False).head(5)[["remote_host", "minute_bucket", "requests_per_minute", "response_bytes_total"]])
# print(features.sort_values("response_bytes_total", ascending=False).tail(10)[["remote_host", "minute_bucket", "requests_per_minute", "response_bytes_total"]])

method_diversity_per_ip = df.groupby(["remote_host","minute_bucket"])["request_method"].nunique()
features = features.join(method_diversity_per_ip.rename("method_diversity"))

print(features["method_diversity"].describe())

features = features.reset_index()
features.to_parquet("data/processed/features.parquet")
check = pd.read_parquet("data/processed/features.parquet")
print(check.shape)
print(check.columns.tolist())
