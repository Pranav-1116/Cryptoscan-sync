"""Inert configuration representations with genuinely distinct indirection states."""


def snippets(config, certificate):
    state = config["resolution"]["state"]
    policy = config["configured_policy"]
    protocols = " ".join(x.replace("TLS1.", "TLSv1.") for x in policy["versions"])
    directives = f"ssl_protocols {protocols};\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;\nssl_ecdh_curve X25519:prime256v1;\n"
    if state == "inherited":
        directives = "include ../policies/modern.conf;\n"
    elif state == "environment-driven":
        directives = "ssl_protocols ${LAB_TLS_VERSIONS};\nssl_ciphers ${LAB_TLS_CIPHERS};\n"
    elif state == "indirect":
        directives = "include ../policies/modern.conf;\n# resolve by explicit policy reference in loadbalancer.json\n"
    elif state == "missing":
        directives = "# TLS protocol and cipher configuration intentionally missing\n"
    elif state == "conflicting":
        directives += "ssl_protocols TLSv1.2;\n"
    elif state == "stale":
        directives = "ssl_protocols TLSv1.2;\nssl_ciphers AES128-SHA;\n"
    elif state == "vendor-declared":
        directives = "# VENDOR_DECLARED TLS1.3/AES-256-GCM; no local TLS directives\n"
    auth = "on" if config["client_certificate_required"] else "off"
    return {
        "nginx.conf": f"# SYNTHETIC INERT TEMPLATE; state={state}; never deploy\n"
        + directives
        + f"ssl_certificate CERT-REF:{certificate['certificate_id']};\n# private-key-reference {config['private_key_reference']}\n"
        + f"ssl_verify_client {auth};\n# trusted-ca {config['trusted_ca']}\n# alpn h2,http/1.1; sni {certificate['san'][0]}\n"
        + f"# upstream_tls={config['upstream_tls']}; upstream_client_auth={config['upstream_client_certificate_required']}\n",
        "haproxy.cfg": f"# SYNTHETIC INERT TEMPLATE; state={state}; never deploy\n"
        + (
            "global\n  ssl-default-bind-options ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3\n"
            if state == "explicit"
            else f"# policy-ref {state}\n"
        )
        + f"# crt-ref {certificate['certificate_id']}; key-ref {config['private_key_reference']}\n# upstream TLS={config['upstream_tls']}\n",
    }
