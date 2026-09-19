import os
import sys
import glob

# Ensure user site packages (/home/user/.local/lib/python3.11/site-packages) is on sys.path
user_site = os.path.expanduser("~/.local/lib/python3.11/site-packages")
if os.path.exists(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)


# Ensure all microservices and shared modules are discoverable on PYTHONPATH
root_dir = os.path.dirname(os.path.abspath(__file__))
for p in glob.glob(os.path.join(root_dir, 'services', '*')):
    if os.path.isdir(p):
        sys.path.insert(0, p)
for p in glob.glob(os.path.join(root_dir, 'shared', '*')):
    if os.path.isdir(p):
        sys.path.insert(0, p)

import uvicorn

if __name__ == "__main__":
    os.environ.setdefault("PORT", "8010")
    os.environ.setdefault("HOST", "0.0.0.0")
    uvicorn.run("api.main:app", host="0.0.0.0", port=8010, reload=False, log_level="info")
