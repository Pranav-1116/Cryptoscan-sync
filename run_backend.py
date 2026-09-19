import os
import sys
import glob

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
