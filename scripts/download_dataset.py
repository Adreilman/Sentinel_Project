import kagglehub
import os
import shutil

# Step 1: download to kagglehub's cache (this is NOT your project folder)
cache_path = kagglehub.dataset_download("eliasdabbas/web-server-access-logs")
print("Downloaded to kagglehub cache:", cache_path)

# Step 2: define where you actually want it — inside your project
# NOTE: adjust this if your project root isn't where you're running the script from
project_raw_dir = os.path.join("data", "raw")
os.makedirs(project_raw_dir, exist_ok=True)

# Step 3: copy every file from the cache into your project's data/raw folder
copied_files = []
for f in os.listdir(cache_path):
    src = os.path.join(cache_path, f)
    if os.path.isfile(src):
        dst = os.path.join(project_raw_dir, f)
        shutil.copy2(src, dst)
        copied_files.append(dst)

print("\nCopied into your project folder:")
for f in copied_files:
    size_mb = os.path.getsize(f) / (1024 * 1024)
    print(f" - {f}  ({size_mb:.1f} MB)")

# Step 4: pick the largest file as the likely log file
if not copied_files:
    raise FileNotFoundError("No files were copied — check the cache path above.")

log_file_path = max(copied_files, key=os.path.getsize)
print("\nLikely log file:", log_file_path)

# Step 5: sanity check — print first 3 lines to confirm format
print("\nFirst 3 lines:")
with open(log_file_path, encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f):
        if i >= 3:
            break
        print(line.strip())