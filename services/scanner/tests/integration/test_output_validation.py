import json

from scanner.core.scanner import Scanner
from scanner.output.json_schema import is_valid_scan_result, validate_scan_result
from scanner.output.json_writer import JSONWriter


def test_scan_json_matches_schema(sample_java_files, temp_workspace):
    result = Scanner().scan(sample_java_files)
    payload = result.model_dump(mode="json")
    assert is_valid_scan_result(payload)
    assert not validate_scan_result(payload)
    out = temp_workspace / "scan.json"
    JSONWriter(out).write(result)
    written = json.loads(out.read_text())
    assert written["findings"]
    assert {"source", "crypto", "metadata"} <= written["findings"][0].keys()
