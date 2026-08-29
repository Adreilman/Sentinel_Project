import apache_log_parser
import datetime
import os
import re
import pandas as pd
from tqdm import tqdm
from datetime import datetime


format = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i" "%{End-Line}i"'
log_parsing = apache_log_parser.make_parser(format)


def reader(filename):
    with open(filename) as f:
        
        result = []
        errors = 0
        for line in tqdm(f):
            try:
                match = log_parsing(line)
                filtered = {
                    "remote_host":match["remote_host"],
                    "time_received_isoformat":match["time_received_isoformat"],
                    "request_method":match["request_method"],
                    "request_url_path":match["request_url_path"],
                    "status":int(match["status"]),
                    "response_bytes_clf":int(match["response_bytes_clf"]),
                    "request_header_referer":match["request_header_referer"],
                    "request_header_user_agent":match["request_header_user_agent"],
                    "malformed_request": False
                }
                result.append(filtered)
            except Exception:
                errors+=1
                regip = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                regtime = r'\[\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]'
                regcode_bytes = r'"\s+(\d{3})\s+(\d+)\s'
                restime = re.findall(regtime,line)
                rescode = re.findall(regcode_bytes,line)
                resip = re.findall(regip,line)
                filtered = {
                "remote_host": resip[0] if resip else None,
                "time_received_isoformat": restime[0] if restime else None,
                "request_method": None,
                "request_url_path": None,
                "status": int(rescode[0][0]) if rescode else None,
                "response_bytes_clf": int(rescode[0][1]) if rescode else None,
                "request_header_referer": None,
                "request_header_user_agent": None,
                "malformed_request": True,
                }
                result.append(filtered)
                
        df = pd.DataFrame(result)
        os.makedirs("data/processed", exist_ok=True)
        df.to_parquet("data/processed/parsed_logs.parquet")
        print(len(df))
        print(df.dtypes)
        print(df[df["malformed_request"]==True])
        print(f"Errors: {errors}")
        
if __name__ == '__main__':
    reader("data/raw/access.log")

