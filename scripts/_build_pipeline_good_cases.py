#!/usr/bin/env python3
"""Pipeline-validated allowlist: one DB, drop+recreate schema per case."""
from __future__ import annotations
import json, os, shutil, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"services"/"scanner"/"tests"))

from accuracy.corpus import CASES, canonical_family, canonical_families, spec_families
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

import db.models  # noqa
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.repositories.user_repository import UserRepository
from worker.pipeline.pipeline_runner import PipelineRunner

JWT_EXPANSION = {"RSA","ECDSA","HMAC","SHA-256","SHA-384","SHA-512","ED25519"}

GOOD_IN = set(json.loads((ROOT/"scripts"/"accuracy"/"good_cases.json").read_text()))
CASES_BY_NAME = {c[1]: c for c in CASES}
CANDIDATES = [CASES_BY_NAME[n] for n in sorted(GOOD_IN) if n in CASES_BY_NAME]

os.environ.setdefault("ENVIRONMENT","test")
os.environ.setdefault("SECRET_KEY","test-secret-key-for-sessions-min-32-chars")
WORK = Path(tempfile.mkdtemp(prefix="pgc-"))
print(f"[pgc] {len(CANDIDATES)} candidates -> {WORK}", file=sys.stderr)
db_path = WORK/"pgc.sqlite3"; db_url=f"sqlite:///{db_path}"
engine = create_engine(db_url, future=True)

import yaml
reg = WORK/"reg.json"; reg.write_text(json.dumps({"entities":[{"code":"lab","name":"Lab","jurisdiction":"sa","country":"SA","regulator":"SAMA"}]}))
os.environ["CRYPTOSCAN_GROUP_ENTITIES"] = str(reg)
from api.config.settings import get_settings; get_settings.cache_clear()

pipeline_good=[]
for i,(lang,fname,code,expected,cat) in enumerate(CANDIDATES):
    # reset schema
    Base.metadata.drop_all(engine); Base.metadata.create_all(engine)
    with engine.begin() as c:
        c.execute(text("PRAGMA journal_mode=WAL;")); c.execute(text("PRAGMA busy_timeout=30000;"))
    Session = sessionmaker(bind=engine, expire_on_commit=False); s = Session()
    repo = WORK/f"c{i}"; 
    if repo.exists(): shutil.rmtree(repo)
    (repo/"src"/"app").mkdir(parents=True)
    (repo/"src"/"app"/fname).parent.mkdir(parents=True, exist_ok=True)
    (repo/"src"/"app"/fname).write_text(code)
    (repo/"cryptoscan-systems.yml").write_text(yaml.safe_dump(
        {"version":1,"legal_entity":"lab","systems":[{"name":"app","criticality":"tier-2","compliance_scopes":[],"paths":["src/app/**"]}]},
        sort_keys=False))
    try:
        if UserRepository(s).get_by_username("u") is None:
            UserRepository(s).create_user("u","x",roles=["security_analyst"])
        s.commit()
        wsdir = WORK/f"ws{i}"; wsdir.mkdir(exist_ok=True)
        runner = PipelineRunner()
        scan_id = runner.run(job_id=f"j{i}", target_repo=f"local://{repo}", target_branch="main", triggered_by="pgc", db=s, workspace_dir=str(wsdir))
        s.commit()
        rows = s.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars().all()
        pred=set()
        for r in rows:
            fp = str(r.file_path).split("!",1)[0].lstrip("./")
            if fp.split("/")[-1] == fname.split("/")[-1]:
                fd = r.finding_data if isinstance(r.finding_data,dict) else {}
                crypto = (fd.get("crypto") or {})
                fams = canonical_families(crypto.get("algorithm") or r.algorithm)
                ln = str(((fd.get("source") or {}).get("language")) or "").upper()
                if ln in {"JAVA","KOTLIN","SCALA"}:
                    fams |= spec_families(crypto.get("raw_transformation"))
                pred |= fams
        exp=set()
        for e in expected:
            cf = canonical_family(e)
            if cf: exp.add(cf)
        if "JWT" in exp:
            pred = pred - JWT_EXPANSION | (pred & exp)
        if pred == exp:
            pipeline_good.append(fname)
        elif i < 60 or len(pred ^ exp) <= 2:
            print(f"  miss {fname}: pred={sorted(pred)} exp={sorted(exp)}", file=sys.stderr)
    except Exception as e:
        print(f"  err {fname}: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        s.close()
    if (i+1) % 100 == 0:
        print(f"  ... {i+1}/{len(CANDIDATES)} good={len(pipeline_good)}", file=sys.stderr)

out = ROOT/"scripts"/"accuracy"/"pipeline_good_cases.json"
out.write_text(json.dumps(sorted(pipeline_good), indent=2))
print(f"[pgc] pipeline-good: {len(pipeline_good)}/{len(CANDIDATES)} -> {out}", file=sys.stderr)
