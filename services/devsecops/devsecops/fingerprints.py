"""Exact and fuzzy fingerprints: identity for a fleet, not a similarity trick.

Two questions a fleet asks over and over, and both are answered offline with no
model and no network:

* *is this the same build as that one?* — answered by **exact** fingerprints:
  SHA-256 over the code sections with their names and lengths framed in (so a
  section rename or a split section is visible, while a changed debug path is
  not), over the sorted import and export surfaces, plus whatever build identity
  the format carries itself (ELF ``.note.gnu.build-id``, PE CodeView ``GUID`` +
  age, Mach-O ``LC_UUID``). The file's own digest is kept beside them because it
  answers a different question: a file hash changes when a comment string
  changes, and a build fingerprint does not.
* *is this nearly the same build as that one?* — answered by **fuzzy**
  fingerprints: ssdeep (CTPH, context-triggered piecewise hashing), implemented
  here from the ssdeep specification. A rolling hash over a seven-byte window
  triggers piece boundaries, each piece is hashed with FNV-1a, and the result is
  two base64 sequences emitted at the block size that produced them. Comparison
  is the reference edit-distance score, 0-100, with the same block-size and
  common-substring rules as ``ssdeep``/``ppdeep`` (the module's test vectors were
  produced by that reference implementation and are checked in).

Nothing here claims more than it measured: every fingerprint row says which
sections were hashed and how many bytes they were, a file too large to hash
completely says it was truncated, and a similarity score is only ever claimed
between two fingerprints this module produced. An exact fingerprint is an
identity claim; a fuzzy score is a *resemblance*, reported as such.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# ssdeep (CTPH)
# --------------------------------------------------------------------------- #

#: ssdeep's base64 alphabet — the index is the low six bits of the piece hash
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_ROLLING_WINDOW = 7
_ROLLING_INIT = 0x28021967          # HASH_INIT (== 39 mod 64)
_HASH_PRIME = 0x01000193            # FNV-1a prime
_MIN_BLOCK = 3
_SPAMSUM_LENGTH = 64                # 64 pieces at the base size, 32 at double
_MAX_BLOCK = _MIN_BLOCK << 20
_MASK = 0xFFFFFFFF

#: how much code the exact fingerprint hashes. The bound exists so a pathological
#: 512 MiB binary cannot make one file scan take minutes; at 64 MiB no real
#: ``.text`` is truncated, and a truncated one says so.
MAX_CODE_BYTES = 64 * 1024 * 1024

#: how much of that code the fuzzy pass reads. ssdeep is ~2 MiB/s in pure Python,
#: so the fuzzy fingerprint is a *sample* of the build — and a sample that stops
#: early is labelled as one (`fuzzy_bytes`, `fuzzy_truncated`). The default keeps a
#: scan inside the 10k-binaries/hour budget; a targeted lookup can raise it (up to
#: ``MAX_FUZZY_LIMIT``) because it only has a handful of files to read. The exact
#: hashes above cover the whole file and are not affected by this bound.
MAX_FUZZY_BYTES = 512 * 1024
MAX_FUZZY_LIMIT = 8 * 1024 * 1024

#: sections that *are* the build rather than the packaging around it. The list is
#: deliberately format-neutral: it is matched against ELF/PE/Mach-O section names
#: and anything else a parser can name.
CODE_SECTIONS = frozenset({
    ".text", ".init", ".fini", ".plt", ".plt.got", ".plt.sec",
    ".rodata", ".rodata.1", ".data.rel.ro", ".data.rel.ro.local",
    ".rdata", ".CRT",
    "__TEXT,__text", "__TEXT,__const", "__TEXT,__cstring", "__TEXT,__literal4",
    "__TEXT,__literal8", "__TEXT,__ustring", "__DATA,__const",
})

#: the head of a fingerprint window is framed with the section name and size, so
#: two builds that only differ in how the linker laid sections out do not collide
_FRAME = b"\x00\x1f"


def _piecewise(data: bytes, block_size: int) -> tuple[str, str]:
    """One ssdeep pass at one block size: rolling triggers, FNV piece hashes.

    Both sequences are produced in the same walk — the base block size (up to 63
    pieces) and the doubled block size (up to 31) — exactly as ssdeep does, so
    two files whose block sizes differ by a factor of two remain comparable.
    """
    hash1 = hash2 = _ROLLING_INIT
    window = [0] * _ROLLING_WINDOW
    roll1 = roll2 = roll3 = 0
    index = 0
    pieces1: list[str] = []
    pieces2: list[str] = []
    last1 = last2 = ""
    rolling = 0
    for byte in data:
        hash1 = ((hash1 * _HASH_PRIME) & _MASK) ^ byte
        hash2 = ((hash2 * _HASH_PRIME) & _MASK) ^ byte
        roll2 = roll2 - roll1 + _ROLLING_WINDOW * byte
        roll1 = roll1 + byte - window[index]
        roll3 = ((roll3 << 5) & _MASK) ^ byte
        window[index] = byte
        index = (index + 1) % _ROLLING_WINDOW
        rolling = (roll1 + roll2 + roll3) & _MASK
        if rolling % block_size == block_size - 1:
            last1 = _B64[hash1 & 0x3F]
            if len(pieces1) < _SPAMSUM_LENGTH - 1:
                pieces1.append(_B64[hash1 & 0x3F])
                hash1 = _ROLLING_INIT
                last1 = ""
            if rolling % (block_size * 2) == block_size * 2 - 1:
                last2 = _B64[hash2 & 0x3F]
                if len(pieces2) < _SPAMSUM_LENGTH // 2 - 1:
                    pieces2.append(_B64[hash2 & 0x3F])
                    hash2 = _ROLLING_INIT
                    last2 = ""
    if rolling != 0:
        pieces1.append(_B64[hash1 & 0x3F])
        pieces2.append(_B64[hash2 & 0x3F])
    else:
        pieces1.append(last1)
        pieces2.append(last2)
    return "".join(pieces1), "".join(pieces2)


def fuzzy_hash(data: bytes, *, limit: int = MAX_FUZZY_BYTES) -> str:
    """ssdeep fingerprint of ``data``: ``blocksize:base:doubled``.

    The block size starts at 3, doubles until the file fits in 64 pieces, and is
    halved again whenever the pass produced fewer than 32 pieces (a sparse pass
    says nothing). Data past ``limit`` is not read; callers that truncate record
    that fact next to the fingerprint.
    """
    sample = data[:limit] if limit and len(data) > limit else data
    size = len(sample)
    block_size = _MIN_BLOCK
    while block_size * _SPAMSUM_LENGTH < size:
        block_size *= 2
    while True:
        first, second = _piecewise(sample, block_size)
        if block_size > _MIN_BLOCK and len(first) < _SPAMSUM_LENGTH // 2:
            block_size //= 2
            if block_size < _MIN_BLOCK:
                block_size = _MIN_BLOCK
                first, second = _piecewise(sample, block_size)
                break
            continue
        break
    return f"{block_size}:{first}:{second}"


def parse_fuzzy(fingerprint: str) -> tuple[int, str, str] | None:
    """Split ``blocksize:base:doubled``; ``None`` for anything malformed.

    Empty piece lists are valid ssdeep — that is what a sample that produced no
    pieces looks like — and are returned as empty strings rather than rejected.
    """
    parts = str(fingerprint or "").split(":")
    if len(parts) != 3:
        return None
    try:
        block_size = int(parts[0])
    except ValueError:
        return None
    if block_size < _MIN_BLOCK:
        return None
    return block_size, parts[1], parts[2]


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left):
        current = [i + 1]
        for j, rc in enumerate(right):
            current.append(min(current[j] + 1, previous[j + 1] + 1,
                               previous[j] + (0 if lc == rc else 1)))
        previous = current
    return previous[-1]


def _share_a_substring(left: str, right: str, window: int = _ROLLING_WINDOW) -> bool:
    """ssdeep refuses to score two sequences that share nothing of substance.

    A shared run of at least seven characters is the bar. Shorter sequences cannot
    clear it, which is why two very short fingerprints score 0 rather than a
    meaningless 4: the score is only meaningful where there is something to match.
    """
    if len(left) < window or len(right) < window:
        return False
    seen = {left[index:index + window] for index in range(len(left) - window + 1)}
    return any(right[index:index + window] in seen
               for index in range(len(right) - window + 1))


def _score_sequences(left: str, right: str, block_size: int) -> int:
    if not _share_a_substring(left, right):
        return 0
    score = _levenshtein(left, right)
    score = (score * _SPAMSUM_LENGTH) // (len(left) + len(right))
    score = 100 - (100 * score) // _SPAMSUM_LENGTH
    cap = (block_size // _MIN_BLOCK) * min(len(left), len(right))
    return max(0, min(score, cap))


def _strip_sequences(text: str) -> str:
    """Drop runs of four or more identical characters, as ssdeep's compare does."""
    pieces = [text[:3]]
    for index in range(3, len(text)):
        if (text[index] != text[index - 1] or text[index] != text[index - 2]
                or text[index] != text[index - 3]):
            pieces.append(text[index])
    return "".join(pieces)


def fuzzy_similarity(left: str, right: str) -> int:
    """ssdeep's comparison score, 0-100 (100 = identical fingerprints).

    Block sizes that are not equal or a factor of two apart cannot be compared:
    the score is 0, not a guess.
    """
    one = parse_fuzzy(left)
    two = parse_fuzzy(right)
    if one is None or two is None:
        return 0
    block1, base1, double1 = one
    block2, base2, double2 = two
    if block1 != block2 and block1 != block2 * 2 and block2 != block1 * 2:
        return 0
    if not base1 or not base2:
        # a deliberate departure from ssdeep, which scores two empty fingerprints as
        # 100: an empty piece list means the sample produced no pieces at all, and
        # two samples that produced nothing are not the same file
        return 0
    base1, double1 = _strip_sequences(base1), _strip_sequences(double1)
    base2, double2 = _strip_sequences(base2), _strip_sequences(double2)
    if block1 == block2 and base1 == base2:
        return 100
    if block1 == block2:
        return max(_score_sequences(base1, base2, block1),
                   _score_sequences(double1, double2, block2 * 2))
    if block1 == block2 * 2:
        return _score_sequences(base1, double2, block1)
    return _score_sequences(double1, base2, block2)


# --------------------------------------------------------------------------- #
# exact fingerprints
# --------------------------------------------------------------------------- #

def _framed(digest: Any, name: str, size: int) -> None:
    digest.update(_FRAME)
    digest.update(f"{name}\x00{size}\x00".encode("utf-8", "replace"))


def code_bytes(data: bytes, windows: Iterable[tuple[str, int, int]],
               *, limit: int = MAX_CODE_BYTES) -> tuple[bytes, list[str], bool]:
    """The code of a binary: the selected sections, in file order, framed.

    Returns the bytes, the section names that went in, and whether the read was
    cut short — because a fingerprint of half a file is a fingerprint of half a
    file and the report has to be able to say which half.
    """
    chunks: list[bytes] = []
    names: list[str] = []
    used = 0
    truncated = False
    for name, offset, size in windows:
        if name not in CODE_SECTIONS or size <= 0 or offset < 0:
            continue
        if offset >= len(data):
            continue
        chunk = data[offset:offset + size]
        if not chunk:
            continue
        if used + len(chunk) > limit:
            chunk = chunk[:max(0, limit - used)]
            truncated = True
        if not chunk:
            break
        chunks.append(chunk)
        names.append(name)
        used += len(chunk)
        if used >= limit:
            truncated = True
            break
    return b"".join(chunks), names, truncated


def exact_fingerprints(data: bytes, *, code: bytes, code_sections: list[str],
                       imports: Iterable[str] = (), exports: Iterable[str] = (),
                       build_id: str | None = None, fmt: str = "",
                       truncated: bool = False) -> dict[str, Any]:
    """The exact side: file, code, ABI surface, build identity and the composite.

    ``build_fingerprint`` is the fleet identity — the same source built twice with
    the same toolchain lands on the same value, and the linker layout, the debug
    path and the file name do not enter it.
    """
    imports_sorted = sorted({str(name) for name in imports if str(name).strip()})
    exports_sorted = sorted({str(name) for name in exports if str(name).strip()})
    imports_digest = hashlib.sha256("\x00".join(imports_sorted).encode("utf-8", "replace"))
    exports_digest = hashlib.sha256("\x00".join(exports_sorted).encode("utf-8", "replace"))
    code_digest = hashlib.sha256()
    code_digest.update(f"{fmt}\x00{len(code)}\x00".encode("utf-8", "replace"))
    code_digest.update(code)
    file_digest = hashlib.sha256(data).hexdigest()
    code_sha256 = code_digest.hexdigest() if code else None
    identity = hashlib.sha256()
    identity.update(f"{fmt}\x00{code_sha256 or file_digest}\x00"
                    f"{imports_digest.hexdigest()}\x00".encode("utf-8", "replace"))
    row: dict[str, Any] = {
        "file_sha256": file_digest,
        "code_sha256": code_sha256,
        "code_bytes": len(code),
        "code_sections": code_sections[:8],
        "imports_sha256": imports_digest.hexdigest(),
        "imports_count": len(imports_sorted),
        "exports_sha256": exports_digest.hexdigest(),
        "exports_count": len(exports_sorted),
        "build_id": build_id or None,
        "build_fingerprint": identity.hexdigest(),
        "truncated": truncated,
    }
    if not code:
        row["note"] = ("no code section was identifiable (the file carries none this scanner "
                       "names), so the build fingerprint falls back to the file digest")
    elif truncated:
        row["note"] = (f"code sections were read up to {MAX_CODE_BYTES} bytes; the code "
                       f"fingerprint covers the first {len(code)} byte(s)")
    else:
        row["note"] = f"code fingerprint covers {', '.join(code_sections[:3])} and {len(code)} byte(s)"
    return row


def build_id_of(record: dict[str, Any]) -> str | None:
    """The build identity the file declares about itself, in a normal form.

    Formats that carry one put it where a linker put it: ELF ``.note.gnu.build-id``,
    PE's CodeView ``GUID`` + age (the same pair a symbol server keys on), Mach-O's
    ``LC_UUID``. A file with none says ``None`` rather than borrowing the file hash.
    """
    if record.get("build_id"):
        return f"elf-build-id:{record['build_id']}"
    # the PE parser keeps the debug directory under `debug` (it is parsed from the
    # debug directory entry); the identity may be in either place
    debug = record.get("debug") or {}
    guid = record.get("pdb_guid") or debug.get("pdb_guid")
    if guid:
        age = record.get("pdb_age") or debug.get("pdb_age")
        return f"pe-codeview:{guid}{f'+{age}' if age else ''}"
    if record.get("uuid"):
        return f"macho-uuid:{record['uuid']}"
    return None


def fingerprint_record(data: bytes, record: dict[str, Any], *,
                       fuzzy_limit: int = MAX_FUZZY_BYTES) -> dict[str, Any]:
    """Fingerprint a parsed record: exact digests plus the ssdeep resemblance.

    The fuzzy pass runs over the code sections when there are any — the packaging
    around a build changes far more often than the build does — and over the whole
    file when there are not (a raw blob, a filesystem image, an archive).
    """
    windows = record.get("_code_windows") or []
    code, names, truncated = code_bytes(data, windows)
    row = exact_fingerprints(
        data, code=code, code_sections=names,
        imports=record.get("imports") or [], exports=record.get("exports") or [],
        build_id=build_id_of(record), fmt=str(record.get("format") or ""),
        truncated=truncated)
    source = code or data
    basis = "code sections" if code else "whole file"
    sample = source[:max(1, fuzzy_limit)]
    row["ssdeep"] = fuzzy_hash(sample)
    row["fuzzy_basis"] = basis
    row["fuzzy_bytes"] = len(sample)
    row["fuzzy_truncated"] = len(source) > len(sample)
    if row["fuzzy_truncated"]:
        row["note"] = (row.get("note", "") + f"; the fuzzy fingerprint reads the first "
                       f"{len(sample)} byte(s) of {basis}").lstrip("; ")
    return row


# --------------------------------------------------------------------------- #
# fleet clustering
# --------------------------------------------------------------------------- #

#: a pair scoring this or better is the same software with a difference, not two
#: unrelated binaries that happen to share bytes
FUZZY_SIMILARITY = 85
#: pairwise comparison is quadratic; the budget is stated rather than exceeded
MAX_FUZZY_PAIRS = 400
#: how many members of a duplicate group are listed before the list is summarised
MAX_GROUP_MEMBERS = 12


def cluster(records: list[dict[str, Any]], *, similarity: int = FUZZY_SIMILARITY,
            max_pairs: int = MAX_FUZZY_PAIRS) -> dict[str, Any]:
    """Group artefacts by exact build identity, then by fuzzy resemblance.

    Exact groups are the answer to "which of these are the same build". Near
    groups are pairs that are close but *not* identical — a variant, a hotfix, or
    a binary that has been altered — and are reported as resemblance with the
    score, never as identity.
    """
    fingerprinted = [(record.get("path") or record.get("name") or "?",
                      record.get("format") or "?",
                      record.get("fingerprints") or {})
                     for record in records]
    fingerprinted = [(path, fmt, row) for path, fmt, row in fingerprinted if row]
    builds: dict[str, list[tuple[str, str]]] = {}
    code_only: dict[str, list[str]] = {}
    for path, _fmt, row in fingerprinted:
        builds.setdefault(str(row.get("build_fingerprint")), []).append(
            (path, str(row.get("file_sha256") or "")))
        code = row.get("code_sha256")
        if code:
            code_only.setdefault(str(code), []).append(path)

    # a build group is not automatically a set of identical files: the same code
    # and the same imports can be packaged with different strings, names or debug
    # data, and saying "identical" there would be a claim the bytes do not support
    exact: list[dict[str, Any]] = []
    for key, members in sorted(builds.items()):
        if len(members) <= 1:
            continue
        paths = [path for path, _digest in members]
        digests = {digest for _path, digest in members if digest}
        exact.append({
            "build_fingerprint": key, "count": len(members),
            "members": sorted(paths)[:MAX_GROUP_MEMBERS],
            "members_truncated": len(members) > MAX_GROUP_MEMBERS,
            "byte_identical": len(digests) == 1 and len(members) > 1,
            "distinct_file_digests": max(1, len(digests)),
            "note": ("the same code and import surface"
                     + ("" if len(digests) == 1 else
                        "; the files are not byte-identical, so packaging differs")),
        })
    shared_code = [{"code_sha256": key, "count": len(paths),
                    "members": sorted(paths)[:MAX_GROUP_MEMBERS],
                    "members_truncated": len(paths) > MAX_GROUP_MEMBERS}
                   for key, paths in sorted(code_only.items())
                   if len(paths) > 1 and
                   len({str(row.get("build_fingerprint"))
                        for path, _fmt, row in fingerprinted
                        if (row.get("code_sha256") or "") == key}) > 1]

    pairs: list[dict[str, Any]] = []
    compared = 0
    skipped = 0
    by_format: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for path, fmt, row in fingerprinted:
        by_format.setdefault(fmt, []).append((path, row))
    for fmt, rows in sorted(by_format.items()):
        for index, (path, row) in enumerate(rows):
            for other_path, other in rows[index + 1:]:
                if row.get("build_fingerprint") == other.get("build_fingerprint"):
                    continue        # identical builds are an exact group, not a resemblance
                if row.get("code_sha256") and row.get("code_sha256") == other.get("code_sha256"):
                    # the same code with different imports is already reported as
                    # shared code; saying it again as a resemblance would be noise
                    continue
                if compared >= max_pairs:
                    skipped += 1
                    continue
                compared += 1
                score = fuzzy_similarity(str(row.get("ssdeep") or ""),
                                         str(other.get("ssdeep") or ""))
                if score >= similarity:
                    pairs.append({"left": path, "right": other_path, "format": fmt,
                                  "score": score, "threshold": similarity,
                                  "left_ssdeep": row.get("ssdeep"),
                                  "right_ssdeep": other.get("ssdeep")})
    pairs.sort(key=lambda row: (-int(row["score"]), str(row["left"]), str(row["right"])))
    # one relationship per pair of builds, not per pair of files: a variant that
    # resembles twelve identical copies resembles one build, and saying it twelve
    # times buries the finding it belongs to
    group_of = {path: str(row.get("build_fingerprint")) for path, _fmt, row in fingerprinted}
    collapsed: list[dict[str, Any]] = []
    seen: dict[tuple[str, str, int], dict[str, Any]] = {}
    for pair in pairs:
        left_key = group_of.get(str(pair["left"])) or str(pair["left"])
        right_key = group_of.get(str(pair["right"])) or str(pair["right"])
        key = (*sorted((left_key, right_key)), int(pair["score"]))
        if key in seen:
            seen[key]["also_matched"] = int(seen[key].get("also_matched") or 1) + 1
            continue
        pair["also_matched"] = 1
        seen[key] = pair
        collapsed.append(pair)
    pairs = collapsed
    return {
        "artefacts_fingerprinted": len(fingerprinted),
        "distinct_builds": len(builds),
        "exact_duplicates": exact,
        "shared_code": shared_code,
        "near_duplicates": pairs,
        "similarity_threshold": similarity,
        "comparisons": compared,
        "comparisons_skipped": skipped,
        "note": ("exact groups are the same build fingerprint; near pairs are resemblance "
                 f"at or above {similarity} of 100 and are never reported as identity"),
    }


#: how many groups/pairs a manifest carries; the counts above them are complete
MAX_GROUPS_IN_SUMMARY = 20


def summarise(clusters: dict[str, Any], *, limit: int = MAX_GROUPS_IN_SUMMARY) -> dict[str, Any]:
    """A manifest-sized view of the comparison: complete counts, bounded lists."""
    exact = list(clusters.get("exact_duplicates") or [])
    near = list(clusters.get("near_duplicates") or [])
    return {
        "artefacts_fingerprinted": clusters.get("artefacts_fingerprinted", 0),
        "distinct_builds": clusters.get("distinct_builds", 0),
        "exact_duplicate_groups": len(exact),
        "exact_duplicate_artefacts": sum(int(group.get("count") or 0) for group in exact),
        "near_duplicate_pairs": len(near),
        "similarity_threshold": clusters.get("similarity_threshold", FUZZY_SIMILARITY),
        "comparisons": clusters.get("comparisons", 0),
        "comparisons_skipped": clusters.get("comparisons_skipped", 0),
        "duplicate_groups": exact[:limit],
        "near_duplicates": near[:limit],
        "groups_shown": min(len(exact), limit),
        "near_shown": min(len(near), limit),
        "note": clusters.get("note"),
    }


def fingerprint_findings(clusters: dict[str, Any], *, paths: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Findings for what the fleet comparison found, one per group or pair."""
    wanted = set(paths) if paths else None
    findings: list[dict[str, Any]] = []
    for group in clusters.get("exact_duplicates") or []:
        members = [str(name) for name in group.get("members") or []]
        if wanted is not None and not wanted.intersection(members):
            continue
        byte_note = ("the files are byte-identical"
                     if group.get("byte_identical") else
                     f"the files are not byte-identical "
                     f"({group.get('distinct_file_digests')} distinct file digests)")
        findings.append({
            "code": "BIN-FINGERPRINT-DUPLICATE", "severity": "INFO",
            "title": f"{group['count']} artefacts are the same build",
            "detail": (f"{group['count']} artefacts share build fingerprint "
                       f"{str(group['build_fingerprint'])[:32]}… — the same code and the same "
                       f"import surface; {byte_note}. A fix applied to one of them applies to "
                       f"all. Members: "
                       + ", ".join(members)
                       + (" (list truncated)" if group.get("members_truncated") else "")),
            "path": members[0] if members else None,
            "build_fingerprint": group["build_fingerprint"],
            "byte_identical": bool(group.get("byte_identical")),
            "members": members, "member_count": group["count"],
        })
    for group in clusters.get("shared_code") or []:
        members = [str(name) for name in group.get("members") or []]
        if wanted is not None and not wanted.intersection(members):
            continue
        findings.append({
            "code": "BIN-FINGERPRINT-SHARED-CODE", "severity": "INFO",
            "title": f"{group['count']} artefacts share code but not a build",
            "detail": (f"{group['count']} artefacts have identical code sections "
                       f"({str(group['code_sha256'])[:32]}…) but different import surfaces — "
                       f"the same implementation linked against different libraries. Members: "
                       + ", ".join(members)),
            "path": members[0] if members else None,
            "code_sha256": group["code_sha256"],
            "members": members, "member_count": group["count"],
        })
    for pair in clusters.get("near_duplicates") or []:
        members = [str(pair.get("left")), str(pair.get("right"))]
        if wanted is not None and not wanted.intersection(members):
            continue
        extra = int(pair.get("also_matched") or 1) - 1
        if pair["score"] >= 100:
            # ssdeep has a resolution: a change smaller than a piece boundary can
            # leave the sampled fingerprint identical while the digests differ
            reason = ("their fuzzy samples are identical while the exact digests differ — the "
                      "difference is smaller than the fuzzy sample resolves, which is what a "
                      "hand-patched copy looks like")
        else:
            reason = (f"their code resembles each other at {pair['score']} of 100 (ssdeep, "
                      f"threshold {pair['threshold']}) — a variant or a patched copy")
        findings.append({
            "code": "BIN-FINGERPRINT-NEAR-DUPLICATE", "severity": "INFO",
            "title": (f"two artefacts are {pair['score']}% similar"
                      if pair["score"] < 100 else "two artefacts are the same build as far as the sample can see"),
            "detail": (f"{pair['left']} and {pair['right']} are not the same build but {reason}. "
                       + (f"{extra} further copy/copies of the same build show the same "
                          f"resemblance. " if extra else "")
                       + "Resemblance, not identity."),
            "path": pair["left"], "other_path": pair["right"], "score": pair["score"],
            "also_matched": extra + 1, "samples_identical": pair["score"] >= 100,
        })
    return findings


def match(query: dict[str, Any], record: dict[str, Any], *,
          similarity: int = FUZZY_SIMILARITY) -> dict[str, Any]:
    """Answer "is this artefact the queried build, or close to it?" for one pair.

    The verdict is one of ``identical`` (same build fingerprint), ``same-code``
    (identical code, different imports), ``similar`` (fuzzy score at or above the
    threshold) or ``different`` — each with the numbers that produced it. The
    threshold only ever applies to the fuzzy half: an exact match is exact.
    """
    subject = record.get("fingerprints") or {}
    query_fingerprint = str(query.get("build_fingerprint") or "")
    code = str(query.get("code_sha256") or "")
    verdict = "different"
    score = 0
    if query_fingerprint and subject.get("build_fingerprint") == query_fingerprint:
        verdict = "identical"
    elif code and subject.get("code_sha256") == code:
        verdict = "same-code"
    else:
        score = fuzzy_similarity(str(query.get("ssdeep") or ""), str(subject.get("ssdeep") or ""))
        if score >= similarity:
            verdict = "similar"
    row = {"verdict": verdict, "score": score,
           "build_fingerprint": subject.get("build_fingerprint"),
           "code_sha256": subject.get("code_sha256"),
           "ssdeep": subject.get("ssdeep"),
           "threshold": similarity}
    if verdict == "similar" and score >= 100:
        # ssdeep has a resolution: a change smaller than a piece boundary leaves the
        # sampled fingerprint identical while the exact digests differ
        row["samples_identical"] = True
        row["note"] = ("the fuzzy samples are identical while the exact digests differ — the "
                       "change is smaller than the sample resolves, which is what a patched "
                       "copy looks like")
    return row


def compare(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare two fingerprint rows directly (both must be this module's rows)."""
    one = left.get("fingerprints") or left
    two = right.get("fingerprints") or right
    identical = bool(one.get("build_fingerprint")) and \
        one.get("build_fingerprint") == two.get("build_fingerprint")
    code = bool(one.get("code_sha256")) and one.get("code_sha256") == two.get("code_sha256")
    score = fuzzy_similarity(str(one.get("ssdeep") or ""), str(two.get("ssdeep") or ""))
    return {"identical_build": identical, "identical_code": code, "score": score,
            "threshold": FUZZY_SIMILARITY,
            "left": {"file_sha256": one.get("file_sha256"),
                     "code_sha256": one.get("code_sha256"),
                     "build_fingerprint": one.get("build_fingerprint"),
                     "ssdeep": one.get("ssdeep")},
            "right": {"file_sha256": two.get("file_sha256"),
                      "code_sha256": two.get("code_sha256"),
                      "build_fingerprint": two.get("build_fingerprint"),
                      "ssdeep": two.get("ssdeep")}}
