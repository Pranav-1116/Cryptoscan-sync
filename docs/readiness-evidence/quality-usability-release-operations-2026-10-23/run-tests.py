from pathlib import Path
import os,sys
root=Path(__file__).resolve().parents[3];sys.path.insert(0,str(root/'scripts'))
from _bootstrap import bootstrap
bootstrap()
for folder in ('services','shared'):
 for child in (root/folder).iterdir():
  if child.is_dir():sys.path.insert(0,str(child))
sys.path.insert(0,str(root/'services/api/tests/unit'))
os.environ['PYTHONPATH']=os.pathsep.join(p for p in sys.path if p.startswith(str(root)))
import pytest
raise SystemExit(pytest.main(sys.argv[1:]))
