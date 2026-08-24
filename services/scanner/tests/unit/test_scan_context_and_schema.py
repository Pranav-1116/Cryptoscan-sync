from scanner.core.scan_context import ScanContext
from scanner.extractors.context_extractor import extract_context
from scanner.output.json_schema import is_valid_scan_result, validate_scan_result
from scanner.parsers.parse_error_handler import safe_parse


def test_scan_context_defaults(temp_workspace):
    ctx = ScanContext(root_path=temp_workspace, scan_id="s1")
    assert ctx.target_type == "LOCAL_DIRECTORY"
    assert ctx.languages == []


def test_validate_scan_result():
    assert is_valid_scan_result({"scan_id": "1", "scanner_id": "x", "findings": []})
    errors = validate_scan_result({"scan_id": "1"})
    assert errors


def test_safe_parse_swallows_errors(temp_workspace):
    def boom(_path, _root=None):
        raise RuntimeError("bad parse")

    findings, error = safe_parse(boom, temp_workspace / "a.java", temp_workspace)
    assert findings == []
    assert error["type"] == "RuntimeError"


def test_context_extractor_reads_class(temp_workspace):
    path = temp_workspace / "Pay.java"
    path.write_text("class Pay {\n  void encrypt() {\n    Cipher.getInstance(\"AES\");\n  }\n}\n")
    ctx = extract_context(path, 3)
    assert ctx["class_name"] == "Pay"
