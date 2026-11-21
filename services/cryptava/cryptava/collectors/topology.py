"""TechBOM: how the things the other planes found fit together, and — only where the
bank has said so in the agent's configuration — which business system they belong to.

The technical topology (service runs on host, host on hardware, service exposes
endpoint, service loads library, package provided by vendor …) is already in the
observation as evidenced edges; the platform projects the TechBOM from them. What a
host cannot know is the *business* meaning: that this box is part of "SWIFT
Gateway". That comes from the agent config, is sent as ``CONFIGURED`` evidence with an
``APPROVED_MAPPING`` basis, and is labelled as such:

.. code-block:: json

    {"system": {"name": "SWIFT Gateway", "owner": "Payments Ops", "criticality": "tier-0",
                "applications": [{"name": "Alliance Access", "services": ["java", "nginx"]}],
                "depends_on": [{"name": "Core Banking", "via": "ISO 20022 over MQ"}, "Payment HSM"]}}
"""

from __future__ import annotations


from cryptava.collectors import Context
from cryptava.observation import source
from cryptava.util import slug

TECH_TYPES = {"SYSTEM", "APPLICATION", "SERVICE", "CONTAINER", "HOST", "DATABASE", "HSM", "VENDOR", "HARDWARE"}


def collect(ctx: Context) -> None:
    obs = ctx.obs
    system = ctx.config.get("system") or {}
    mapped = 0
    if isinstance(system, dict) and system.get("name"):
        name = str(system["name"])
        ref = obs.asset(f"system:{slug(name)}", "SYSTEM", name, identity={"name": name},
                        attributes={"owner": system.get("owner"), "criticality": system.get("criticality"),
                                    "business_service": system.get("business_service")},
                        source="cryptava-config", environment=ctx.environment)
        ev = obs.observe(ref, "CONFIGURED", {
            "mapping": "host is part of this business system", "host": ctx.fqdn,
            "declared_by": "cryptava agent configuration (bank-approved mapping)",
            "owner": system.get("owner"), "criticality": system.get("criticality"),
        }, layer="APPLICATION", source="cryptava-config")
        obs.relate(ctx.host_ref, "part_of", ref, basis="APPROVED_MAPPING", evidence=[ev])
        mapped += 1
        for app in system.get("applications") or []:
            if not isinstance(app, dict) or not app.get("name"):
                continue
            app_name = str(app["name"])
            app_ref = obs.asset(f"app:{slug(app_name)}", "APPLICATION", app_name,
                                identity={"name": app_name, "system": name},
                                attributes={"owner": app.get("owner") or system.get("owner")},
                                source="cryptava-config", environment=ctx.environment)
            app_ev = obs.observe(app_ref, "CONFIGURED", {
                "mapping": f"application of {name}", "services": app.get("services"), "host": ctx.fqdn,
                "declared_by": "cryptava agent configuration (bank-approved mapping)",
            }, layer="APPLICATION", source="cryptava-config")
            obs.relate(app_ref, "part_of", ref, basis="APPROVED_MAPPING", evidence=[app_ev])
            obs.relate(app_ref, "runs_on", ctx.host_ref, basis="APPROVED_MAPPING", evidence=[app_ev])
            for service_name in app.get("services") or []:
                svc = ctx.services.get(str(service_name))
                if svc:
                    obs.relate(svc, "part_of", app_ref, basis="APPROVED_MAPPING", evidence=[app_ev])
                    mapped += 1
        # the bank's architecture: which other business systems this one calls. A host cannot
        # see that SWIFT Gateway needs Core Banking; the CMDB can. Sent as CONFIGURED evidence on
        # an APPROVED_MAPPING edge, so the migration simulation can warn about a peer that is
        # not part of a change — and never mistaken for an observed connection.
        for peer in system.get("depends_on") or []:
            entry = peer if isinstance(peer, dict) else {"name": peer}
            peer_name = str(entry.get("name") or "").strip()
            if not peer_name or peer_name == name:
                continue
            peer_ref = obs.asset(f"system:{slug(peer_name)}", "SYSTEM", peer_name, identity={"name": peer_name},
                                 source="cryptava-config", environment=ctx.environment)
            dep_ev = obs.observe(ref, "CONFIGURED", {
                "mapping": f"{name} depends on {peer_name}", "depends_on": peer_name,
                "via": entry.get("via"), "protocol": entry.get("protocol"),
                "declared_by": "cryptava agent configuration (bank-approved mapping)", "host": ctx.fqdn,
            }, layer="APPLICATION", source="cryptava-config")
            obs.relate(ref, "depends_on", peer_ref, basis="APPROVED_MAPPING", evidence=[dep_ev])

    tech_assets = sum(1 for a in obs.assets.values() if a["type"] in TECH_TYPES)
    tech_edges = sum(1 for r in obs.relationships.values()
                     if obs.assets[r["subject"]]["type"] in TECH_TYPES and obs.assets[r["object"]]["type"] in TECH_TYPES)
    provenance = [
        source("evidenced edges from the other five planes", "runs on, hosted on, exposes, loads library, "
               "provided by, uses certificate …", "READ" if tech_edges else "EMPTY", tech_edges),
        source("agent config 'system'", "approved business-system mapping (name, owner, criticality, applications)",
               "READ" if mapped else "NOT_CONFIGURED", mapped or None,
               system.get("name") if mapped else "set 'system' in the agent config"),
    ]
    if mapped:
        obs.plane("TechBOM · topology", "COMPLETE",
                  f"{tech_assets} technology assets, {tech_edges} evidenced links; business system "
                  f"'{system['name']}' from the approved mapping", expected=1, collected=1, sources=provenance)
    else:
        obs.plane("TechBOM · topology", "PARTIAL",
                  f"{tech_assets} technology assets, {tech_edges} evidenced links; no business system mapped "
                  "(set 'system' in the agent config)", expected=2, collected=1, sources=provenance)
