from evidence.core.pipeline import EvidencePipeline


def test_full_pipeline_creates_manifest(sample_findings):
    pipeline = EvidencePipeline()
    records, manifest = pipeline.process(sample_findings, scan_id="s1")
    assert manifest.verify_manifest_hash()
    assert records[0].chain_position == 0
    assert records[1].previous_hash == records[0].chain_hash
