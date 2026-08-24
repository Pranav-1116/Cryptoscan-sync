from scanner.core.language_detector import detect_languages_in_repo


def test_detects_polyglot_extensions(temp_workspace):
    (temp_workspace / "a.py").write_text("print(1)\n")
    (temp_workspace / "b.js").write_text("console.log(1)\n")
    (temp_workspace / "c.cs").write_text("class C {}\n")
    (temp_workspace / "d.java").write_text("class D {}\n")
    found = detect_languages_in_repo(temp_workspace)
    assert set(found) >= {"PYTHON", "JAVASCRIPT", "CSHARP", "JAVA"}
