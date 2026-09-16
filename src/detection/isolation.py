import pandas as pd

df = pd.read_parquet("data/processed/features.parquet")
known_suspects = pd.read_csv("data/reference/known_suspects.csv")

print(df["unique_paths_per_ip"].describe())

print("\nValue counts:")
print(df["unique_paths_per_ip"].value_counts().sort_index().head(20))

print("\nNumber of unique values:")
print(df["unique_paths_per_ip"].nunique())

ip_stats = (
    df.groupby("remote_host")["unique_paths_per_ip"]
    .agg(["mean", "std", "min", "max"])
    .sort_values("max", ascending=False)
)

print(ip_stats.head(20).to_string())

suspect_paths = (
    df[df["remote_host"].isin(known_suspects["remote_host"])]
    .groupby("remote_host")["unique_paths_per_ip"]
    .agg(["mean", "std", "min", "max"])
    .sort_values("max", ascending=False)
)

print(suspect_paths.to_string())

ip_mean_paths = df.groupby("remote_host")["unique_paths_per_ip"].mean()
ip_std_paths = df.groupby("remote_host")["unique_paths_per_ip"].std()

df["paths_mean"] = df["remote_host"].map(ip_mean_paths)
df["paths_std"] = df["remote_host"].map(ip_std_paths)

df["paths_zscore"] = (
    (df["unique_paths_per_ip"] - df["paths_mean"])
    / df["paths_std"]
)
print(
    df[
        [
            "remote_host",
            "minute_bucket",
            "unique_paths_per_ip",
            "paths_mean",
            "paths_std",
            "paths_zscore"
        ]
    ]
    .sort_values("paths_zscore", ascending=False)
    .head(20)
    .to_string(index=False)
)
print(
    df[
        df["remote_host"].isin(known_suspects["remote_host"])
    ][
        [
            "remote_host",
            "unique_paths_per_ip",
            "paths_mean",
            "paths_std",
            "paths_zscore"
        ]
    ]
    .sort_values("paths_zscore", ascending=False)
    .head(30)
    .to_string(index=False)
)

high_path_z = df[df["paths_zscore"] > 3]

print(
    high_path_z["unique_paths_per_ip"].describe()
)

print("\nHigh z-score rows by path count:")

print(
    high_path_z["unique_paths_per_ip"]
    .value_counts()
    .sort_index()
    .head(30)
)
non_suspects = df[
    ~df["remote_host"].isin(known_suspects["remote_host"])
]

high_path_z_non_suspect = non_suspects[
    non_suspects["paths_zscore"] > 3
]

print(
    high_path_z_non_suspect[
        [
            "remote_host",
            "minute_bucket",
            "unique_paths_per_ip",
            "paths_mean",
            "paths_std",
            "paths_zscore"
        ]
    ]
    .sort_values("paths_zscore", ascending=False)
    .head(30)
    .to_string(index=False)
)
flag_paths_zscore_anomaly = (
    (df["paths_zscore"] > 3)
    & (df["unique_paths_per_ip"] > 10)
    & (df["bot_rate"] < 0.9)
)

df["flag_paths_zscore_anomaly"] = flag_paths_zscore_anomaly

print(df["flag_paths_zscore_anomaly"].sum())

flagged_paths = df[df["flag_paths_zscore_anomaly"]]
print(
    flagged_paths[
        ["remote_host", "unique_paths_per_ip", "paths_mean", "paths_std", "paths_zscore"]
    ]
    .sort_values("paths_zscore", ascending=False)
    .head(15)
    .to_string(index=False)
)

suspect_coverage = (
    df[df["remote_host"].isin(known_suspects["remote_host"])]
    .groupby("remote_host")["flag_paths_zscore_anomaly"]
    .sum()
)
print("\nKnown suspect coverage:")
print(suspect_coverage)