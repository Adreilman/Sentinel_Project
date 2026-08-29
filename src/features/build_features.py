import pandas as pd

df = pd.read_parquet('data/processed/parsed_logs.parquet')
df["time_received_isoformat"] = pd.to_datetime(df["time_received_isoformat"],format='%Y-%m-%dT%H:%M:%S')

df["minute_bucket"] = df["time_received_isoformat"].dt.floor('min')

requests_per_minute = df.groupby(["remote_host","minute_bucket"]).size()


unique_uas_per_ip = df.groupby(["remote_host", "minute_bucket"])["request_header_user_agent"].nunique()

unique_pr_per_ip = df.groupby(["remote_host", "minute_bucket"])["request_url_path"].nunique()

df["is_error"] = (df["status"]>=400)

error_rate_by_ip = df.groupby(["remote_host"])["is_error"].mean()