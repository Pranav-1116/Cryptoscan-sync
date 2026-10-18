"""Bounded exact-estate projection for immutable twin replay (no disk dependency)."""
from sqlalchemy import func

from db.models.software_supply_chain import ReleaseSbomBinding, SoftwareArtifact, SoftwareDeployment
from db.tenancy import current_tenant
from shared_models.software_identity import SCHEMA, scope_key

ARTIFACT_CAP = 2000
DEPLOYMENT_CAP = 5000
BINDING_CAP = 200
COMPONENT_CAP = 20000


def software_snapshot(db):
    tenant = current_tenant()

    def rows(model):
        return db.query(model).filter(model.tenant_id == tenant, model.scope_key == scope_key(tenant))

    artifacts = rows(SoftwareArtifact).order_by(SoftwareArtifact.id).limit(ARTIFACT_CAP).all()
    deployments = rows(SoftwareDeployment).order_by(SoftwareDeployment.id).limit(DEPLOYMENT_CAP).all()
    bindings, components = [], 0
    # Stream rather than materializing every JSON document in the estate.
    for row in rows(ReleaseSbomBinding).order_by(ReleaseSbomBinding.id).limit(BINDING_CAP).yield_per(1):
        if components >= COMPONENT_CAP:
            break
        selected = (row.components or [])[:COMPONENT_CAP - components]
        bindings.append({**row.to_dict(), "components": selected})
        components += len(selected)
    totals = {"artifacts": rows(SoftwareArtifact).count(), "deployments": rows(SoftwareDeployment).count(),
              "sbom_bindings": rows(ReleaseSbomBinding).count(),
              "components": int(db.query(func.sum(ReleaseSbomBinding.component_count)).filter(
                  ReleaseSbomBinding.tenant_id == tenant,
                  ReleaseSbomBinding.scope_key == scope_key(tenant)).scalar() or 0)}
    returned = {"artifacts": len(artifacts), "deployments": len(deployments),
                "sbom_bindings": len(bindings), "components": components}
    limits = {"artifacts": ARTIFACT_CAP, "deployments": DEPLOYMENT_CAP, "sbom_bindings": BINDING_CAP, "components": COMPONENT_CAP}
    coverage = {key: {"total": total, "known_total": total, "limit": limits[key], "unit": "components" if key == "components" else "rows", "returned": returned[key], "truncated": returned[key] < total}
                for key, total in totals.items()}
    return {"software_artifacts": [row.to_dict() for row in artifacts],
            "software_sbom_bindings": bindings,
            "software_deployments": [row.to_dict() for row in deployments],
            "software_supply_chain_coverage": {"schema": SCHEMA, "collections": coverage,
                                                "truncated": any(c["truncated"] for c in coverage.values())}}
