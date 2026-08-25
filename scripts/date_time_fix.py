import pandas as pd
import re
from datetime import datetime

datetime_format = '%d/%b/%Y:%H:%M:%S'

def fix_timestamp(raw):
    time = raw.strip('[]')
    time = re.sub(r'\s*\+\d{4}','',time)
    format_date = datetime.strptime(time,datetime_format).isoformat()
    return format_date


df = pd.read_parquet('data/processed/parsed_logs.parquet')

df.loc[df["malformed_request"]==True,"time_received_isoformat"] = df.loc[df["malformed_request"]==True,"time_received_isoformat"].apply(fix_timestamp)
print(df[df["malformed_request"] == True]["time_received_isoformat"].head())
still_broken = df[(df["malformed_request"]==True) & (df["time_received_isoformat"].str.contains('[', regex=False))]
print(still_broken)
print(len(still_broken))
df.to_parquet('data/processed/parsed_logs.parquet')
