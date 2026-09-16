import pandas as pd
import os

known_suspects = [
    {"remote_host": "151.239.241.163", "reason": "14 rotating UAs across multiple days, sustained 200-300 req/min, 0% bot-confirmed", "found_via": "stage1"},
    {"remote_host": "2.188.27.28", "reason": "559 req/min burst, 4 rotating UAs, normal-looking paths but spoofed browser identity", "found_via": "stage1"},
    {"remote_host": "5.78.190.233", "reason": "Repeat offender, 220+ req/min across multiple minutes, combined rule hit", "found_via": "stage1"},
    {"remote_host": "91.99.30.32", "reason": "Flagged 9 separate times, sustained high volume plus UA rotation", "found_via": "stage1"},
    {"remote_host": "91.99.47.57", "reason": "Flagged 9 separate times, sustained pattern across a single day", "found_via": "stage1"},
    {"remote_host": "172.20.2.174", "reason": "Extreme z-scores (70+) across volume and response bytes simultaneously, near-zero baseline", "found_via": "stage2"},
    {"remote_host": "91.99.72.15", "reason": "Consistently high z-scores across volume, UA rotation, and response bytes", "found_via": "stage2"},
    {"remote_host": "104.222.32.84", "reason": "High z-scores on response bytes avg and total", "found_via": "stage2"},
    {"remote_host": "104.222.32.94", "reason": "High z-scores on response bytes avg and total", "found_via": "stage2"},
    {"remote_host": "195.181.168.181", "reason": "High z-scores on UA rotation and response bytes", "found_via": "stage2"},
    {"remote_host": "195.181.169.141", "reason": "High z-scores on UA rotation and response bytes", "found_via": "stage2"},
    {"remote_host": "217.219.76.102", "reason": "Appeared independently in both Stage 1 and Stage 2, cross-validated", "found_via": "stage1_and_stage2"},
    {"remote_host": "74.82.60.74", "reason": "Low malformed-rate but high volume; one buried protocol-mismatch request hidden in otherwise normal traffic", "found_via": "phase1_malformed_rate"},
    {"remote_host": "74.82.60.66", "reason": "Same 74.82.x.x cluster pattern as 74.82.60.74", "found_via": "phase1_malformed_rate"},
    {"remote_host": "74.82.17.87", "reason": "Same 74.82.x.x cluster pattern as 74.82.60.74", "found_via": "phase1_malformed_rate"},
]

df = pd.DataFrame(known_suspects)

os.makedirs("data/reference", exist_ok=True)
df.to_csv("data/reference/known_suspects.csv", index=False)
print(f"Saved {len(df)} known suspects to data/reference/known_suspects.csv")
print(df)