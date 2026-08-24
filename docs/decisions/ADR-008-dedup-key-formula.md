# ADR-008 dedup key formula

## Status

Accepted.

## Decision

```
SHA-256(algorithm|purpose|file_path|line_number)
```

Two scanners that land on the same tuple merge into one asset. Two or more
distinct `scanner_id`s raise confidence to `VERIFIED`.

## Consequences

The same algorithm used on two lines is two assets. Container library
findings (line 0, manifest path) stay separate from source-line assets.
