import pandas as pd

df = pd.read_parquet("data/processed/parsed_logs.parquet")


print(df[(df["malformed_request"]==True) & (df["remote_host"] == "74.82.60.66")][["remote_host","time_received_isoformat","request_method","request_url_path","status","response_bytes_clf","request_header_user_agent","malformed_request"]].head(10).to_string())
