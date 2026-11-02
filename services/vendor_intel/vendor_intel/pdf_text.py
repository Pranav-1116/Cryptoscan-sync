"""Text out of a vendor PDF, or a refusal — never an empty string.

Procurement evidence arrives as PDFs. A VBOM that says "crypto capabilities:
none" because the extractor silently returned nothing is worse than one that
says "this document could not be read", so every failure here is an exception
with a reason, and an empty result is a failure.

This is a *text-layer* extractor, not a PDF renderer:

* it reads content streams, inflating ``FlateDecode`` ones with :mod:`zlib`;
* it decodes the text-showing operators ``Tj``, ``TJ``, ``'`` and ``\"``,
  including the ``\\(``, ``\\)``, ``\\\\`` and octal escapes a PDF producer uses;
* it treats ``Td``/``TD``/``T*``/``TL`` as line breaks so a questionnaire's
  ``Label: value`` lines survive as lines;
* it refuses an encrypted file, a file with no ``%PDF`` header, and a document
  with no extractable text (a scanned page) with a message saying which.

Object streams, cross-reference streams and embedded fonts are irrelevant to
text extraction, and a scanned page has no text layer at all — that is a
document to send back to the vendor, not a parsing problem to solve here.
"""

from __future__ import annotations

import re
import zlib
from typing import Iterator

SCHEMA = "cryptoscan.pdf-text/1"

#: Upper bound on a decompressed stream. A vendor questionnaire is kilobytes;
#: a stream that inflates to more than this is refused rather than held in
#: memory, because a decompression bomb is the classic way to kill a scanner.
MAX_STREAM_BYTES = 32 * 1024 * 1024


class PdfTextError(ValueError):
    """The document's text could not be extracted, for the stated reason."""


_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_FLATE = re.compile(rb"/Filter\s*(?:\[\s*)?/FlateDecode")
_ESCAPES = {
    b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f",
    b"(": b"(", b")": b")", b"\\": b"\\",
}


def _inflate(payload: bytes) -> bytes:
    try:
        data = zlib.decompress(payload)
    except zlib.error:
        try:
            data = zlib.decompressobj().decompress(payload)
        except zlib.error as exc:  # pragma: no cover - corrupt stream
            raise PdfTextError(f"a content stream did not inflate: {exc}") from exc
    if len(data) > MAX_STREAM_BYTES:
        raise PdfTextError(
            f"a content stream expanded past {MAX_STREAM_BYTES} bytes; refusing to parse it")
    return data


def _decode_literal(raw: bytes) -> str:
    out = bytearray()
    index = 0
    while index < len(raw):
        byte = raw[index]
        if byte != 0x5C:  # backslash
            out.append(byte)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            break
        nxt = raw[index:index + 1]
        if nxt in _ESCAPES:
            out.extend(_ESCAPES[nxt])
            index += 1
            continue
        octal = re.match(rb"[0-7]{1,3}", raw[index:])
        if octal:
            out.append(int(octal.group(0), 8) & 0xFF)
            index += len(octal.group(0))
            continue
        index += 1  # unknown escape: the backslash is dropped, as PDF says
    return out.decode("latin-1")


def _strings(stream: bytes) -> list[str]:
    """Every text-showing operator in one content stream, in document order."""
    lines: list[str] = []
    current: list[str] = []
    index = 0
    length = len(stream)
    while index < length:
        char = stream[index:index + 1]
        if char == b"(":
            depth = 1
            end = index + 1
            while end < length and depth:
                byte = stream[end:end + 1]
                if byte == b"\\":
                    end += 2
                    continue
                if byte == b"(":
                    depth += 1
                elif byte == b")":
                    depth -= 1
                end += 1
            literal = stream[index + 1:end - 1]
            tail = stream[end:end + 12]
            index = end
            if re.match(rb"\s*Tj", tail) or re.match(rb"\s*'", tail) or re.match(rb"\s*\"", tail):
                current.append(_decode_literal(literal))
            elif re.match(rb"[\s\d]*\]\s*TJ", stream[end:end + 40]):
                current.append(_decode_literal(literal))
            continue
        if char == b"[":
            # An array of string fragments followed by TJ: no inter-word space.
            end = stream.find(b"]", index)
            if end == -1:
                break
            tail = stream[end:end + 6]
            if re.match(rb"\s*TJ", tail):
                for match in re.finditer(rb"\((?:\\.|[^\\)])*\)", stream[index:end]):
                    current.append(_decode_literal(match.group(0)[1:-1]))
            index = end + 1
            continue
        for operator in (b"Td", b"TD", b"T*", b"TL"):
            if stream.startswith(operator, index):
                if current:
                    lines.append("".join(current))
                    current = []
                index += len(operator)
                break
        else:
            index += 1
    if current:
        lines.append("".join(current))
    return lines


def _streams(data: bytes) -> Iterator[bytes]:
    for match in _STREAM.finditer(data):
        payload = match.group(1)
        header = data[max(0, match.start() - 512):match.start()]
        if _FLATE.search(header):
            yield _inflate(payload)
        else:
            yield payload


def extract_text(data: bytes) -> str:
    """The document's text, or :class:`PdfTextError` saying why there is none."""
    if not isinstance(data, (bytes, bytearray)):
        raise PdfTextError("extract_text takes bytes, not text")
    if not bytes(data[:5]) == b"%PDF-":
        raise PdfTextError("the file does not start with %PDF-, so it is not a PDF")
    if re.search(rb"/Encrypt\b", bytes(data)):
        raise PdfTextError(
            "the PDF is encrypted, so it has no readable text layer; ask the vendor for an "
            "unencrypted copy or the questionnaire in text form")
    chunks: list[str] = []
    stream_count = 0
    for stream in _streams(bytes(data)):
        stream_count += 1
        lines = _strings(stream)
        if lines:
            chunks.append("\n".join(lines))
    text = "\n".join(chunks)
    if not text.strip():
        raise PdfTextError(
            f"{stream_count} content stream(s) were read and none contained text; a scanned "
            "page has no text layer and needs OCR or a text copy from the vendor")
    return text


def extract_summary(data: bytes) -> dict[str, object]:
    """Text plus the facts a reviewer needs to judge the extraction."""
    text = extract_text(data)
    return {
        "schema": SCHEMA,
        "characters": len(text),
        "lines": len(text.splitlines()),
        "has_text_layer": True,
        "statement": f"{len(text.splitlines())} line(s) of text recovered from the document",
        "text": text,
    }
