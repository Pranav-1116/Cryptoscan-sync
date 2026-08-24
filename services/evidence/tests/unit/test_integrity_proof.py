from evidence.models.integrity_proof import IntegrityProof


def test_integrity_proof_round_trip():
    finding = {"algorithm": "AES", "file_path": "a.py", "line_number": 1}
    proof = IntegrityProof.from_finding(finding, chain_position=0)
    assert len(proof.content_hash) == 64
    assert proof.verify(finding)
    assert not proof.verify({"algorithm": "DES"})
