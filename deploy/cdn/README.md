# CDN cache policy

`cache-policy.json` is the single machine-readable statement of what an edge
cache (CloudFront, Fastly, Akamai, or the bank's own Varnish) may hold about
this platform. Any vendor config is a *translation* of this file; the
invariant tests (`scripts/tests/test_cdn_config.py`) keep the translation
honest by pinning the origin (`.docker/frontend/nginx.conf`) and the policy
to the same numbers.

The three principles are not performance taste — they are correctness:

1. **Hashed bundles are immutable.** Vite content-hashes every name under
   `/assets/`; a changed byte is a new URL. Long TTLs are safe by
   construction, and the edge must never *lengthen* the origin's max-age
   (2592000 = 30d) either — the two must agree exactly.
2. **The shell is never cached.** `index.html` is the only unhashed file and
   it names the hashed ones. A cached shell points at bundles that no longer
   exist after the next deploy.
3. **Authenticated traffic bypasses the edge entirely.** `/api/`, `/ws`,
   `/events` are tenant-scoped; a shared cache holding one bank's bytes is
   the breach this platform never ships. The API's own conditional-get
   layer (`conditional_get.py` — strong ETag, `304`, `private, no-cache`)
   is the only cache those responses may ever meet.

Caching responses at the edge is safe *because* the application already
answers honestly about freshness: `X-RateLimit-*` at the gateway,
ETag revalidation at the API, and the read cache's named staleness ceiling
on the server. The CDN is the last link of that chain, not a first one.
