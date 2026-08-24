# Deduplication design

Findings from every scanner are collapsed into `crypto_assets`.

Identity tuple:

```
algorithm | purpose | file_path | line_number
```

`dedup_key` is the SHA-256 of that tuple. When two or more distinct
`scanner_id` values agree, confidence is raised to `VERIFIED`.

The worker runs dedup after policy so each evidence row already has a
compliance status; assets keep a list of evidence ids and scanner ids.
