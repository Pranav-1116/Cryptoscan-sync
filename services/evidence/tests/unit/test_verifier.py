from evidence.core.pipeline import EvidencePipeline


def test_pipeline_verify_integrity(sample_findings):
    pipeline = EvidencePipeline(scan_session_id="scan-test")
    records, manifest = pipeline.process(sample_findings, scan_id="scan-test")
    assert len(records) == 2
    assert manifest.total_findings == 2
    ok, err = pipeline.verify_integrity()
    assert ok is True
    assert err is None
