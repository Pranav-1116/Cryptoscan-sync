"""API settings — one schema used everywhere."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from shared_config.base_settings import KNOWN_WEAK_SECRETS, BaseSettings

# Canonical weak-secret registry lives in shared_config; re-exported here for
# the production gate below.
WEAK_SECRET_KEYS = set(KNOWN_WEAK_SECRETS)
WEAK_PASSWORDS = {
    "", "cryptoscan", "admin", "password", "changeme", "secret",
    "dev-stream-secret-0123456789abcdef",
    "dev-cbom-secret-0123456789abcdef",
    "dev-cbom-signing-secret-change-me-32ch",
}
WEAK_WEBHOOK_SECRETS = {
    "dev-webhook-secret-change-me-32chars!!",
    "change-me-to-a-random-webhook-secret-32ch",
}


class APISettings(BaseSettings):
    """API settings — inherits env/log-level validation and secret redaction
    from shared_config.BaseSettings (enterprise base)."""

    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    HOST: str = "0.0.0.0"
    API_HOST: str = "0.0.0.0"
    PORT: int = 8010
    API_PORT: int = 8010
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    API_VERSION: str = "1.0.0"
    DOCS_ENABLED: bool | None = None

    SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"

    # Offline licensing (advanced/73 P0#1, round 31): HMAC-signed license
    # document — inline JSON or a file path. LICENSE_REQUIRED=off keeps
    # community/self-hosted installs fully open (the default).
    LICENSE_REQUIRED: bool = False
    LICENSE_SIGNING_KEY: str = ""
    LICENSE_DOCUMENT: str = ""
    LICENSE_SITE_ID: str = ""

    # External secrets (advanced/75 P0#1, round 31): providers may be
    # referenced from any credential setting as vault://... / file:... /
    # env:... and are resolved at startup (see api.security.vault).
    VAULT_ADDR: str = ""
    VAULT_TOKEN: str = ""
    VAULT_KV_MOUNT: str = "secret"
    VAULT_TIMEOUT_SECONDS: float = 5.0
    VAULT_PROVIDERS_DISABLED: bool = False  # kill-switch: inline values only

    # Trusted reverse-proxy boundary (§4.8, round 70): forwarded headers
    # are honored only when the declared topology says a proxy you own
    # added them. COUNT=0 (default) trusts only the socket address — a
    # client cannot satisfy an IP allowlist or dodge per-IP limits by
    # writing X-Forwarded-For. N>=1 takes entry -N (the address the
    # outermost trusted proxy observed; everything left of it is
    # client-supplied). CIDRS, when set, additionally requires the socket
    # peer itself to be inside a trusted network (closes the direct-
    # connection spoof when the API is reachable without the proxy).
    TRUSTED_PROXY_COUNT: int = 0
    TRUSTED_PROXY_CIDRS: str = ""

    # Zero-trust policy decision point (advanced/82, round 31): external
    # policy-as-code that can only RESTRICT (deny-wins over RBAC allow).
    ZERO_TRUST_ENFORCED: bool = False
    ZERO_TRUST_POLICY_FILE: str = ""
    OPA_URL: str = ""
    # threat-intel feeds (deep/30, round 35): "name=url" pairs, comma
    # separated; empty = no feeds (community default, manual import only)
    THREAT_INTEL_FEEDS: str = ""
    THREAT_INTEL_FEED_SECRET: str = ""
    THREAT_INTEL_FEED_TIMEOUT: int = 15
    # Serving side (round 38): THIS deployment exposes GET /threat-intel/feed
    # so a central instance can feed branch instances (the same signed-bundle
    # format sync_feeds consumes). Empty token = open-but-signed feed
    # (advisories are distribution-intended; the signature is the integrity
    # boundary); a token requires ?token= on every pull.
    THREAT_INTEL_FEED_TOKEN: str = ""
    # runtime egress guard (audit 81, round 35): "off" (community default)
    # or "enforce" — under enforce, outbound TCP must match the allowlist
    EGRESS_GUARD: str = "off"
    EGRESS_ALLOWLIST: str = ""
    OPA_POLICY_PATH: str = "cryptoscan/allow"
    OPA_TIMEOUT_SECONDS: float = 3.0

    # PKI report signing (W55-56): optional path to an RSA private key (PEM).
    # When set, /scans/{id}/report carries a real RS256 signature; when unset
    # the signature stays null — we never downgrade to HMAC-and-call-it-signed.
    REPORT_SIGNING_KEY: str = ""
    REPORT_SIGNING_KEY_ID: str = ""
    # OIDC SSO (verification side, bring-your-own-IdP): off until OIDC_ISSUER is set.
    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_JWKS_URL: str = ""
    OIDC_JWKS_FILE: str = ""
    OIDC_AUTO_PROVISION: bool = False
    OIDC_CLOCK_LEEWAY: int = 60
    # Authorization-code flow (server-side redirect). Redirect URI defaults to
    # /api/v1/auth/oidc/callback on the request base when unset. Endpoint URLs
    # default to discovery; overrides exist for air-gapped deployments.
    OIDC_CLIENT_SECRET: str = ""
    OIDC_REDIRECT_URI: str = ""
    OIDC_SCOPES: str = "openid profile email"
    OIDC_AUTHORIZATION_URL: str = ""
    OIDC_TOKEN_URL: str = ""
    OIDC_POST_LOGIN_REDIRECT: str = "/"

    # Outbound automation connectors (ITSM/SIEM delivery of automation runs).
    # Values never leave the process — status endpoints report names only.
    SERVICENOW_INSTANCE_URL: str = ""
    SERVICENOW_USER: str = ""
    SERVICENOW_PASSWORD: str = ""
    SPLUNK_HEC_URL: str = ""
    SPLUNK_HEC_TOKEN: str = ""
    JIRA_BASE_URL: str = ""
    JIRA_USER_EMAIL: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_PROJECT_KEY: str = ""
    SENTINEL_WORKSPACE_ID: str = ""
    SENTINEL_SHARED_KEY: str = ""

    # SAML 2.0 SSO (SP side, bring-your-own-IdP): off until SAML_IDP_ENTITY_ID
    # and the IdP signing certificate are set. Certificate is PEM, either inline
    # or a path in SAML_IDP_CERT_PATH.
    SAML_ENABLED: bool = False
    SAML_SP_ENTITY_ID: str = ""
    SAML_ACS_URL: str = ""
    SAML_IDP_ENTITY_ID: str = ""
    SAML_IDP_SSO_URL: str = ""
    SAML_IDP_CERT: str = ""          # inline PEM (or single-line base64)
    SAML_IDP_CERT_PATH: str = ""
    SAML_ROLE_ATTRIBUTE: str = "groups"
    SAML_AUTO_PROVISION: bool = False
    SAML_CLOCK_SKEW_SECONDS: int = 120

    # LDAP / Active Directory bind auth: off until LDAP_SERVER_URI is set.
    LDAP_ENABLED: bool = False
    LDAP_SERVER_URI: str = ""        # e.g. ldaps://dc01.corp:636
    LDAP_BIND_DN: str = ""           # service/bind account DN
    LDAP_BIND_PASSWORD: str = ""
    LDAP_USER_SEARCH_BASE: str = ""
    LDAP_USER_SEARCH_FILTER: str = "(sAMAccountName={username})"
    LDAP_GROUP_SEARCH_BASE: str = ""
    LDAP_GROUP_MEMBERSHIP_FILTER: str = "(member:1.2.840.113556.1.4.1941:={user_dn})"
    # deterministic group-DN -> CryptoScan role mapping (JSON or comma k=v).
    LDAP_GROUP_ROLE_MAP: str = ""

    SESSION_EXPIRE_HOURS: int = 24
    COOKIE_SECURE: bool | None = None
    # Real-time stream: how often the API tails monitor_events (written by the
    # separate monitor process) and republishes them on the SSE stream.
    # 0 disables the tailer. In-process events (pipeline stages, auth, API
    # keys) are always pushed the instant they happen.
    EVENT_TAILER_SECONDS: float = 2.0
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "cryptoscan"
    ADMIN_PASSWORD_HASH: str = ""
    LOGIN_MAX_FAILURES: int = 8
    LOGIN_LOCKOUT_SECONDS: int = 900

    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    REDIS_URL: str = ""
    SCAN_JOB_QUEUE_KEY: str = "cryptoscan:jobs:queue"
    ALLOW_SQLITE: bool = False

    CORS_ORIGINS: str = "*"
    ALLOW_INSECURE_CORS: bool = False
    # Prometheus scrapes estate-shape and request-volume metrics. Keep the
    # endpoint open in development/test for local tooling, but require an
    # explicit bearer token in production; metrics are not public health data.
    METRICS_TOKEN: str = ""
    TRUSTED_HOSTS: list[str] = Field(default_factory=lambda: ["*"])
    # serving TLS at the app boundary (round 36, deployment set): when
    # set, both must be valid at boot (reverse-proxy termination stays a
    # legitimate unconfigured shape — the TLS posture surface says so)
    TLS_CERT_FILE: str = ""
    TLS_KEY_FILE: str = ""
    TLS_CA_BUNDLE: str = ""
    TLS_MIN_VERSION: str = "1.2"

    GITHUB_WEBHOOK_SECRET: str = "dev-webhook-secret-change-me-32chars!!"
    # Secrets consumed by separate routers/processes stay in the typed model so
    # missing production env vars fail startup instead of selecting a module
    # level development fallback.
    REGISTRY_WEBHOOK_SECRET: str = ""
    CBOM_SIGNING_SECRET: str = ""
    STREAM_SECRET: str = ""
    AUDITOR_API_KEY: str = ""
    GITHUB_TOKEN: str = ""

    NEO4J_URI: str = ""
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cryptoscan"
    NEO4J_DATABASE: str = "neo4j"
    ISTIO_PROMETHEUS_URL: str = ""

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "alerts@cryptoscan.local"
    ALERT_EMAIL_TO: str = "security@example.com"

    # Live-monitor alert sinks (SIEM/webhook/ChatOps) — unset sinks are skipped honestly
    ALERT_CEF_HOST: str = ""
    ALERT_CEF_PORT: int = 514
    ALERT_WEBHOOK_URL: str = ""
    ALERT_WEBHOOK_SECRET: str = ""
    # ChatOps incoming webhook (Slack/Mattermost-compatible; round 37).
    # The workspace/webhook itself is an external system — this is the
    # client half, signed like the generic webhook sink.
    ALERT_CHATOPS_URL: str = ""
    ALERT_CHATOPS_SECRET: str = ""
    ALERT_CHATOPS_CHANNEL: str = ""
    # severity -> channel routing rules, first match wins:
    # "CRITICAL=#soc-critical,HIGH=#soc-high,ANY=#soc-crypto"
    ALERT_CHATOPS_ROUTES: str = ""
    # inbound ChatOps slash commands (round 38): a POST endpoint the
    # workspace calls; HMAC-verified with the same chatops secret
    ALERT_CHATOPS_COMMAND_TOKEN: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        if not self.CORS_ORIGINS or self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # is_production / redacted() / validate_for_production() come from the
    # shared enterprise base.


    @property
    def docs_enabled(self) -> bool:
        if self.DOCS_ENABLED is not None:
            return bool(self.DOCS_ENABLED)
        return not self.is_production

    @property
    def cookie_secure(self) -> bool:
        if self.COOKIE_SECURE is not None:
            return bool(self.COOKIE_SECURE)
        return self.is_production

    @property
    def trusted_host_list(self) -> list[str]:
        return [str(item).strip() for item in (self.TRUSTED_HOSTS or []) if str(item).strip()]


def validate_runtime_settings(settings: APISettings | None = None) -> None:
    """Fail closed when ENVIRONMENT=production still has demo defaults."""
    settings = settings or get_settings()
    if not settings.is_production:
        return
    errors: list[str] = []
    secret = (settings.SECRET_KEY or "").strip()
    if len(secret) < 32 or secret in WEAK_SECRET_KEYS:
        errors.append("SECRET_KEY must be a unique value of at least 32 characters")
    if not settings.ADMIN_PASSWORD_HASH:
        # A plaintext ADMIN_PASSWORD cannot authenticate in production at all
        # (verify_password refuses the non-PBKDF2 fallback there), so reject it
        # at boot instead of letting the deployment come up unable to log in.
        errors.append(
            "ADMIN_PASSWORD_HASH must be set in production "
            "(generate one with scripts/hash_admin_password.py); "
            "a plaintext ADMIN_PASSWORD is not accepted"
        )
    webhook = (settings.GITHUB_WEBHOOK_SECRET or "").strip()
    if webhook in WEAK_WEBHOOK_SECRETS or len(webhook) < 24:
        errors.append("GITHUB_WEBHOOK_SECRET must be a unique value of at least 24 characters")
    if settings.DATABASE_URL.startswith("sqlite") and not settings.ALLOW_SQLITE:
        errors.append("DATABASE_URL must be PostgreSQL in production (or set ALLOW_SQLITE=true)")
    if not (settings.REDIS_URL or "").strip():
        errors.append("REDIS_URL must be configured in production for durable realtime events and shared scan state")
    if float(settings.EVENT_TAILER_SECONDS or 0) <= 0:
        errors.append("EVENT_TAILER_SECONDS must be greater than zero in production")
    if settings.cors_origin_list == ["*"] and not settings.ALLOW_INSECURE_CORS:
        errors.append("CORS_ORIGINS must be an explicit origin list (or set ALLOW_INSECURE_CORS=true)")
    hosts = settings.trusted_host_list
    if not hosts or "*" in hosts:
        errors.append("TRUSTED_HOSTS must be an explicit host allow-list in production")
    metrics_token = (settings.METRICS_TOKEN or "").strip()
    if len(metrics_token) < 32:
        errors.append("METRICS_TOKEN must be a unique value of at least 32 characters")

    # These are independent HMAC/API-key boundaries. Do not let production
    # silently use a development secret when one integration is unused.
    required_secrets = {
        "REGISTRY_WEBHOOK_SECRET": settings.REGISTRY_WEBHOOK_SECRET,
        "CBOM_SIGNING_SECRET": settings.CBOM_SIGNING_SECRET,
        "STREAM_SECRET": settings.STREAM_SECRET,
        "AUDITOR_API_KEY": settings.AUDITOR_API_KEY,
    }
    for name, value in required_secrets.items():
        candidate = (value or "").strip()
        if len(candidate) < 32 or candidate.lower() in WEAK_PASSWORDS:
            errors.append(f"{name} must be a unique value of at least 32 characters")

    # Production must not silently use the in-memory graph backend or the
    # bundled Neo4j password.
    if not (settings.NEO4J_URI or "").strip():
        errors.append("NEO4J_URI must be configured in production")
    neo4j_password = (settings.NEO4J_PASSWORD or "").strip()
    if len(neo4j_password) < 24 or neo4j_password.lower() in WEAK_PASSWORDS:
        errors.append("NEO4J_PASSWORD must be a unique value of at least 24 characters")
    # Serving TLS (round 36): when configured at the app boundary it must
    # be valid — parse, key pairing, not expired. Unconfigured stays legal
    # (reverse-proxy termination is a deployment shape we cannot see).
    from api.security.tls_posture import production_tls_gate

    tls_error = production_tls_gate()
    if tls_error:
        errors.append(tls_error)
    if errors:
        raise RuntimeError("production configuration rejected: " + "; ".join(errors))


@lru_cache
def get_settings() -> APISettings:
    return APISettings()


# Back-compat alias
Settings = APISettings
