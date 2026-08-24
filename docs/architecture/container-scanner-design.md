# Container scanner design

Part 2 scans an *image root* or a repository filesystem. It does not pull
registry images and it does not disassemble binaries.

1. Walk package manifests (`requirements.txt`, `package.json`, `pom.xml`,
   `.csproj`, `go.mod`) and OS inventory files (`dpkg` status, `apk`
   installed, `rpm -qa` text).
2. Fingerprint known crypto libraries from a local JSON catalog.
3. Match local CVE rows (no live NVD call).
4. Treat `*.jar` / `libcrypto.so*` as binaries.
5. Merge Docker layers with `layer_merger` when a saved image tar has been
   unpacked (whiteouts supported).

Webhook handlers record a job; they do not `docker pull`.
