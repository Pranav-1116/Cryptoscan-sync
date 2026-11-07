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
    "",
    "cryptoscan",
    "admin",
    "password",
    "changeme",
    "secret",
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
    CRYPTOSCAN_DEPLOYMENT_PROFILE: str = ""
    LOG_LEVEL: str = "INFO"
    API_VERSION: str = "1.0.0"
    DOCS_ENABLED: bool | None = None

    SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"
    # Key rotation overlap (§ operational): sessions are HMAC-signed with
    # SECRET_KEY. Rotating it without an overlap logs every user out mid-shift,
    # so the previous key(s) stay ACCEPTED (never used to sign) until
    # SECRET_KEY_PREVIOUS is cleared. Comma-separated, oldest last; the
    # rotation script rewrites both values and the audit refuses a stale entry
    # that equals the current key.
    SECRET_KEY_PREVIOUS: str = ""

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

    # On-premises single-organisation installs: a bank runs ONE organisation,
    # and an account the admin creates must not meet "no tenant membership" on
    # first login. When enabled, a user with no membership is attached to the
    # install's organisation at the configured role (default: viewer — read
    # everything, change nothing until an admin grants more). Off by default,
    # because on a multi-organisation or SaaS deployment the same behaviour
    # would be a privilege grant nobody asked for, and self-serve signup would
    # fill the bank's organisation with strangers.
    ONPREM_SINGLE_ORG: bool = False
    ONPREM_DEFAULT_ORG_SLUG: str = "default"
    ONPREM_DEFAULT_ORG_NAME: str = "Default organisation"
    ONPREM_AUTO_MEMBERSHIP_ROLE: str = "viewer"
    # Granting admin/owner automatically is a bigger decision than attaching a
    # reader, so it needs a second, explicit acknowledgement.
    ONPREM_AUTO_MEMBERSHIP_ADMIN_ACK: bool = False

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

    # PKI report signing (W55-56): an RSA private key — a PEM path, inline PEM,
    # or a key reference to an HSM/KMS (aws-kms://…, vault://transit/…,
    # pkcs11://…; see api.security.signing_backend). When set, the report
    # carries a real RS256 signature; when unset the signature stays null — we
    # never downgrade to HMAC-and-call-it-signed.
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
    SAML_IDP_CERT: str = ""  # inline PEM (or single-line base64)
    SAML_IDP_CERT_PATH: str = ""
    SAML_ROLE_ATTRIBUTE: str = "groups"
    SAML_AUTO_PROVISION: bool = False
    SAML_CLOCK_SKEW_SECONDS: int = 120

    # LDAP / Active Directory bind auth: off until LDAP_SERVER_URI is set.
    LDAP_ENABLED: bool = False
    LDAP_SERVER_URI: str = ""  # e.g. ldaps://dc01.corp:636
    LDAP_BIND_DN: str = ""  # service/bind account DN
    LDAP_BIND_PASSWORD: str = ""
    LDAP_USER_SEARCH_BASE: str = ""
    LDAP_USER_SEARCH_FILTER: str = "(sAMAccountName={username})"
    LDAP_GROUP_SEARCH_BASE: str = ""
    LDAP_GROUP_MEMBERSHIP_FILTER: str = "(member:1.2.840.113556.1.4.1941:={user_dn})"
    # deterministic group-DN -> CryptoScan role mapping (JSON or comma k=v).
    LDAP_GROUP_ROLE_MAP: str = ""

    SESSION_EXPIRE_HOURS: int = 24
    #: The idle window is a *second* limit, not a replacement for the absolute
    #: expiry above: a token carried off a machine and never used dies at expiry;
    #: one used continuously keeps working until the absolute limit.
    COOKIE_SECURE: bool | None = None
    # Real-time stream: how often the API tails monitor_events (written by the
    # separate monitor process) and republishes them on the SSE stream.
    # 0 disables the tailer. In-process events (pipeline stages, auth, API
    # keys) are always pushed the instant they happen.
    EVENT_TAILER_SECONDS: float = 2.0
    # The 24/7 estate loop. Off by default: a single-box install may prefer the
    # `cryptoscan serve` process (or a cron tick). When on, the API process runs
    # the estate scheduler in a background thread — safe on every replica,
    # because each run is claimed with a lease in the database.
    ESTATE_REALTIME: bool = False
    ESTATE_REALTIME_POLL_SECONDS: float = 30.0
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "cryptoscan"
    ADMIN_PASSWORD_HASH: str = ""
    LOGIN_MAX_FAILURES: int = 8
    LOGIN_LOCKOUT_SECONDS: int = 900
    #: Failures from one source (IP) inside LOGIN_SOURCE_WINDOW_SECONDS before
    #: that source is refused outright. Per-account lockout stops an attacker
    #: grinding one user; this stops password spraying, where every account sees
    #: exactly one failure and no per-account counter ever trips.
    LOGIN_SOURCE_MAX_FAILURES: int = 20
    LOGIN_SOURCE_WINDOW_SECONDS: int = 900
    #: Idle window. A session unused for this long is refused even though its
    #: absolute expiry has not passed. 0 disables the idle check.
    SESSION_IDLE_MINUTES: int = 30

    #: ── twin history retention ───────────────────────────────────────────────
    #: How long a *superseded* fact value and *stale, unreferenced* evidence are
    #: kept. Nothing current is ever pruned. Seven years is the usual bank
    #: horizon, and the default that prunes nothing in practice while leaving the
    #: mechanism switched on.
    ESTATE_HISTORY_RETENTION_DAYS: int = 2555
    ESTATE_EVIDENCE_RETENTION_DAYS: int = 2555
    #: The content-addressed evidence store the security-control plane resolves snapshot
    #: bodies (and the evidence ids inside them) against. An empty root means "no store is
    #: configured": a snapshot that *claims* evidence is then refused, because an
    #: unresolvable evidence id is an assertion, not a reading. Tenant bodies live under
    #: ``<root>/<tenant_id>/`` and a location may never escape its tenant directory.
    SECURITY_CONTROLS_EVIDENCE_ROOT: str = ""
    #: Litigation/regulatory hold: refuses every sweep, archiving nothing and
    #: deleting nothing, until an operator clears it.
    ESTATE_RETENTION_LEGAL_HOLD: bool = False

    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    REDIS_URL: str = ""
    REDIS_CA_CERTS: str = ""
    REDIS_SENTINELS: str = ""  # JSON [[host, port], ...], TLS only
    REDIS_SENTINEL_MASTER: str = ""
    REDIS_SENTINEL_USERNAME: str = ""
    REDIS_SENTINEL_PASSWORD: str = ""
    SCAN_JOB_QUEUE_KEY: str = "cryptoscan:jobs:queue"
    ALLOW_SQLITE: bool = False

    CORS_ORIGINS: str = "*"
    ALLOW_INSECURE_CORS: bool = False
    # Prometheus scrapes estate-shape and request-volume metrics. Keep the
    # endpoint open in development/test for local tooling, but require an
    # explicit bearer token in production; metrics are not public health data.
    METRICS_TOKEN: str = ""
    #: Shared secret Alertmanager presents when it posts a notification. Like
    #: METRICS_TOKEN it is an infrastructure principal, not a human session: a
    #: pager has no cookie jar, and requiring one is how "nothing is paging"
    #: happens. Blank in development/test; production requires 32+ characters.
    ALERTMANAGER_WEBHOOK_TOKEN: str = ""
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
    previous = [part.strip() for part in (settings.SECRET_KEY_PREVIOUS or "").split(",") if part.strip()]
    if previous:
        if secret in previous:
            # An "overlap" that contains the current key is a no-op that hides
            # a rotation nobody performed.
            errors.append("SECRET_KEY_PREVIOUS must not contain the current SECRET_KEY")
        weak_previous = [key for key in previous if len(key) < 32 or key in WEAK_SECRET_KEYS]
        if weak_previous:
            errors.append("SECRET_KEY_PREVIOUS entries must each be at least 32 characters")
        if len(previous) > 3:
            errors.append(
                "SECRET_KEY_PREVIOUS carries more than 3 rotations; retire the oldest "
                "(every retained key is a key an attacker can still forge sessions with)"
            )
        if len(set(previous)) != len(previous):
            errors.append("SECRET_KEY_PREVIOUS contains a duplicate entry")
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
    if settings.REDIS_URL:
        from api.events.redis_backend import validate_realtime_redis, RedisConfigurationError

        try:
            validate_realtime_redis(settings)
        except (RedisConfigurationError, ValueError) as exc:
            # The validator knows exactly which rule failed (TLS, the default
            # ACL user, Sentinel endpoints). Collapsing that into one sentence
            # sent operators hunting the wrong setting, so the specific reason
            # is carried into the boot refusal.
            detail = str(exc).strip()
            errors.append(
                "Realtime Redis requires verified TLS, dedicated ACL credentials and a valid "
                "Sentinel configuration"
                + (f" — {detail}" if detail else "")
            )
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
    alertmanager_token = (settings.ALERTMANAGER_WEBHOOK_TOKEN or "").strip()
    if len(alertmanager_token) < 32:
        errors.append(
            "ALERTMANAGER_WEBHOOK_TOKEN must be a unique value of at least 32 "
            "characters: alerts that evaluate and reach nothing are a silent outage"
        )

    # On-prem single-organisation auto-membership: safe for one bank's own
    # installation, unsafe the moment the deployment serves several tenants or
    # lets users sign themselves up.
    if settings.ONPREM_SINGLE_ORG:
        role = (settings.ONPREM_AUTO_MEMBERSHIP_ROLE or "").strip().lower()
        if role not in {"viewer", "member", "admin", "owner"}:
            errors.append(
                "ONPREM_AUTO_MEMBERSHIP_ROLE must be viewer, member, admin or owner"
            )
        if role in {"admin", "owner"} and not settings.ONPREM_AUTO_MEMBERSHIP_ADMIN_ACK:
            errors.append(
                "ONPREM_AUTO_MEMBERSHIP_ROLE of admin/owner requires "
                "ONPREM_AUTO_MEMBERSHIP_ADMIN_ACK=true"
            )
        import os

        signup = os.environ.get("CRYPTOSCAN_SAAS_SIGNUP", "").strip().lower() in {"1", "true", "yes", "on"}
        if signup:
            errors.append(
                "ONPREM_SINGLE_ORG cannot be combined with CRYPTOSCAN_SAAS_SIGNUP: "
                "self-serve signup would join strangers to the bank's organisation"
            )
        if not (settings.ONPREM_DEFAULT_ORG_SLUG or "").strip():
            errors.append("ONPREM_DEFAULT_ORG_SLUG must name the install's organisation")

    # The forwarded-header boundary is only as good as the pair of values that
    # describe it. A CIDR list with COUNT=0 is a configuration nobody honors; a
    # COUNT with no CIDR list trusts X-Forwarded-For from ANY peer, which is the
    # direct-connection spoof; and 0.0.0.0/0 is the same hole spelled out.
    proxy_count = int(settings.TRUSTED_PROXY_COUNT or 0)
    proxy_cidrs = [part.strip() for part in (settings.TRUSTED_PROXY_CIDRS or "").split(",") if part.strip()]
    if proxy_cidrs and proxy_count < 1:
        errors.append(
            "TRUSTED_PROXY_COUNT must be at least 1 when TRUSTED_PROXY_CIDRS is set "
            "(a proxy allow-list that is never consulted is worse than none)"
        )
    if proxy_count >= 1 and not proxy_cidrs:
        errors.append(
            "TRUSTED_PROXY_CIDRS must name the proxy network when TRUSTED_PROXY_COUNT >= 1 "
            "(otherwise any client that can reach the API may write its own X-Forwarded-For)"
        )
    if proxy_count < 0:
        errors.append("TRUSTED_PROXY_COUNT cannot be negative")
    import ipaddress

    for cidr in proxy_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"TRUSTED_PROXY_CIDRS entry {cidr!r} is not a valid network")
            continue
        if network.prefixlen == 0:
            errors.append(f"TRUSTED_PROXY_CIDRS must not trust every address ({cidr})")

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

    # The explicit operator profile refuses graph routes/projections; requiring
    # fake graph credentials would make a supposedly graph-disabled install lie.
    profile = settings.CRYPTOSCAN_DEPLOYMENT_PROFILE
    operator_profile = profile == "kubernetes-external-services/local-source-v1"
    if profile and not operator_profile:
        errors.append("Unknown CRYPTOSCAN_DEPLOYMENT_PROFILE")
    if operator_profile:
        if (settings.NEO4J_URI or "").strip():
            errors.append("Operator profile must leave NEO4J_URI empty; graph is not enabled")
    else:
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
