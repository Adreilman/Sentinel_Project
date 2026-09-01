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


features = features.reset_index()
features.to_parquet("data/processed/features.parquet")
check = pd.read_parquet("data/processed/features.parquet")
print(check.shape)