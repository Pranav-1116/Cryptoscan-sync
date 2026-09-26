from shared_models.field_accuracy import aggregate, language_of, score_workbook


def _wb():
    return {
        "repo": "bank-a/payments-switch", "files_scanned": 120, "scanner_version": "1.4.0",
        "findings": [
            {"file": "src/Pin.java", "algorithm": "3DES", "verdict": "TP"},
            {"file": "src/Pin.java", "algorithm": "3DES", "verdict": "TP"},          # duplicate hit, counted once
            {"file": "src/Pin.java", "algorithm": "MD5", "verdict": "FP", "note": "checksum of a log file"},
            {"file": "src/Mac.java", "algorithm": "HMAC", "verdict": "TP"},
            {"file": "src/Mac.java", "algorithm": "HMAC", "verdict": "FP"},          # TP elsewhere in file cancels this FP
            {"file": "cfg/tls.conf", "algorithm": "TLS1.0", "verdict": ""},          # unreviewed
            {"file": "iso/Pack.cbl", "algorithm": "AES", "verdict": "FP"},
        ],
        "candidate_misses": [
            {"file": "iso/CSNBENC.cbl", "verdict": "FN", "expected": ["DES"]},
            {"file": "docs/README.md", "verdict": "OK"},
            {"file": "src/Util.kt", "verdict": ""},
        ],
    }


def test_score_is_per_file_family_like_the_corpus_benchmark():
    t = score_workbook(_wb(), reviewer="bank-a crypto CoE")
    assert (t.tp, t.fp, t.fn) == (2, 2, 1)
    assert t.precision == 0.5 and t.recall == round(2 / 3, 4)
    assert t.unreviewed == 2 and t.findings_reviewed == 6 and t.candidate_misses_reviewed == 2
    langs = {l.language: l for l in t.by_language}
    assert langs["java"].tp == 2 and langs["java"].fp == 1 and langs["cobol"].fp == 1 and langs["cobol"].fn == 1
    assert t.fp_examples[0]["note"].startswith("checksum") and t.fn_examples[0]["expected"] == ["DES"]


def test_aggregate_pools_and_flags_weak_languages():
    a = score_workbook(_wb(), reviewer="r1")
    b = score_workbook({"repo": "bank-b/core", "findings": [{"file": f"x{i}.cbl", "algorithm": "AES", "verdict": "FP"} for i in range(12)]}, reviewer="r2")
    agg = aggregate([a, b], corpus_f1=1.0)
    assert agg.status == "MEASURED" and agg.triages == 2 and agg.repos == 2 and agg.reviewers == 2
    assert agg.tp == 2 and agg.fp == 14 and agg.fn == 1
    assert "cobol" in agg.worst_languages and "java" not in agg.worst_languages
    assert agg.gap is not None and agg.gap > 0.5


def test_no_field_data_is_explicit():
    agg = aggregate([], corpus_f1=1.0)
    assert agg.status == "NO_FIELD_DATA" and agg.f1 is None and agg.corpus_f1 == 1.0


def test_language_of():
    assert language_of("a/b/X.sqlrpgle") == "rpg" and language_of("k.reg") == "config" and language_of("z.bin") == "other"
