from scanner.extractors.context_extractor import containing_method, extract_context


def test_extract_context_finds_class_and_method(temp_workspace):
    path = temp_workspace / "Pay.java"
    path.write_text(
        "package com.example;\n"
        "public class Pay {\n"
        "  void encrypt() {\n"
        "    Cipher.getInstance(\"AES\");\n"
        "  }\n"
        "}\n"
    )
    ctx = extract_context(path, 4)
    assert ctx["class_name"] == "Pay"
    assert ctx["method_name"] == "encrypt"
    assert "Cipher.getInstance" in (ctx.get("code_snippet") or "")


def test_containing_method_reads_prefix():
    source = "class A {\n  void hash() {\n    MessageDigest.getInstance(\"MD5\");\n  }\n}\n"
    assert containing_method(source, 3) == "hash"
