"""Authentication and authorization (token auth, RBAC guards).

Modules:
- auth: Username/password authentication against the users table (with env-admin bootstrap)
- exceptions
- hmac_verifier: GitHub webhook HMAC verification
- passwords: Password hashing (PBKDF2-SHA256) with a plaintext fallback for local development
- session_manager: HMAC-signed session tokens
"""
