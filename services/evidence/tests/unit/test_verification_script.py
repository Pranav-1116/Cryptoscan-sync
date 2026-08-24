from evidence.hashing.chain_hasher import ChainHasher
from evidence.scripts.verification_script_generator import generate_verification_script


def test_generated_script_verifies_chain(tmp_path):
    content = ["a" * 64, "b" * 64]
    chain = ChainHasher.compute_chain(content, "scan-1")
    records = [
        {"id": "1", "content_hash": content[0], "chain_hash": chain[0]},
        {"id": "2", "content_hash": content[1], "chain_hash": chain[1]},
    ]
    script = generate_verification_script(scan_id="scan-1", records=records, output_path=tmp_path / "verify.py")
    assert "PASS" in script or "compute_chain" in script
    ns: dict = {}
    exec((tmp_path / "verify.py").read_text(encoding="utf-8"), ns)
    assert ns["main"]() == 0
