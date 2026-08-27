"""Per-language parsers turning source into RawFindings.

Modules:
- ast_visitor: Shared Python AST helpers used by language detectors
- c_like: Comment-aware helpers for C-like languages (JS/TS/C#). Preserves newlines
- config_crypto_parser: Detect cryptographic settings in deploy/config files (nginx, TLS, JWT, Terraform)
- csharp_parser: C# cryptographic API parser (regex, no Roslyn required)
- finding_factory: Shared RawFinding constructor for language parsers
- go_parser: Go crypto detector (stdlib crypto/*, x/crypto, TLS). Regex fallback, no extra parser deps
- java_ast: Brace-aware Java AST walker for cryptographic API calls
- java_parser: Java source code parser using regex-based AST analysis
- javascript_parser: JavaScript / TypeScript cryptographic API parser (regex, no tree-sitter required)
- js_ts_parser: Spec-named JavaScript/TypeScript parser entry (tree-sitter-free regex)
- kotlin_parser: Kotlin / Scala crypto detector — same JVM APIs as the Java parser
- parse_error_handler: Graceful parse-error handling used by the multi-language runner
- php_parser: PHP crypto detector (openssl, hash, mcrypt, password_hash, libsodium)
- python_parser: Python cryptographic API parser (stdlib ast)
- ruby_parser: Ruby OpenSSL / Digest / ActiveSupport crypto detector
- rust_parser: Rust crypto detector (ring, rustls, openssl, aes, rsa, md-5, sha2)
"""
