import sys, os, glob

base = "/home/user/CryproScan"
for s in glob.glob(f"{base}/services/*"):
    if os.path.isdir(s):
        sys.path.insert(0, s)
for sh in glob.glob(f"{base}/shared/*"):
    if os.path.isdir(sh):
        sys.path.insert(0, sh)

import uvicorn
from api.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8010, log_level="info")
