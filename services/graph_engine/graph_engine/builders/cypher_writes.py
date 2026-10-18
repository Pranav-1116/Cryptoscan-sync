"""Parameterized MERGE statements used to populate Neo4j.

Per-tenant node identity (round 35): every node MERGE keys on
``tenant_id`` alongside its business id, so two tenants that both have a
system named "payments" are two nodes, never one merged cross-tenant
node. Edge MERGEs match tenanted endpoints. Pruning deletes only within
the syncing tenant — plus un-stamped legacy nodes, and only during a
platform-scope sync, so the first post-upgrade platform sync migrates
pre-tenant graphs instead of duplicating them.
"""

from __future__ import annotations

MERGE_SYSTEMS = """
// cryptoscan.query=merge_systems
UNWIND $rows AS row
MERGE (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
SET s.tenant_id = row.tenant_id,
SET s.name = row.name,
    s.environment = row.environment,
    s.criticality = row.criticality,
    s.owner = row.owner
"""

MERGE_ASSETS = """
// cryptoscan.query=merge_assets
UNWIND $rows AS row
MERGE (a:CryptoAsset {asset_id: row.asset_id, tenant_id: row.tenant_id})
SET a.tenant_id = row.tenant_id,
SET a.algorithm = row.algorithm,
    a.key_size = row.key_size,
    a.purpose = row.purpose,
    a.confidence = row.confidence,
    a.file_path = row.file_path
"""

MERGE_PROCESSES = """
// cryptoscan.query=merge_processes
UNWIND $rows AS row
MERGE (p:BusinessProcess {process_id: row.process_id, tenant_id: row.tenant_id})
SET p.tenant_id = row.tenant_id,
SET p.name = row.name,
    p.revenue_daily = row.revenue_daily,
    p.customer_count = row.customer_count
"""

MERGE_OWNERS = """
// cryptoscan.query=merge_owners
UNWIND $rows AS row
MERGE (o:BusinessOwner {owner_id: row.owner_id, tenant_id: row.tenant_id})
SET o.tenant_id = row.tenant_id,
SET o.name = row.name,
    o.email = row.email,
    o.role = row.role
"""

MERGE_SCOPES = """
// cryptoscan.query=merge_scopes
UNWIND $rows AS row
MERGE (c:ComplianceScope {standard_name: row.standard_name, tenant_id: row.tenant_id})
SET c.tenant_id = row.tenant_id,
SET c.version = row.version
"""

MERGE_VENDORS = """
// cryptoscan.query=merge_vendors
UNWIND $rows AS row
MERGE (v:Vendor {vendor_id: row.vendor_id, tenant_id: row.tenant_id})
SET v.tenant_id = row.tenant_id,
SET v.name = row.name,
    v.criticality = row.criticality
"""

MERGE_CERTS = """
// cryptoscan.query=merge_certs
UNWIND $rows AS row
MERGE (c:Certificate {cert_id: row.cert_id, tenant_id: row.tenant_id})
SET c.tenant_id = row.tenant_id,
SET c.subject = row.subject,
    c.issuer = row.issuer,
    c.not_after = row.not_after,
    c.expiry_status = row.expiry_status
"""

MERGE_CLOUD = """
// cryptoscan.query=merge_cloud
UNWIND $rows AS row
MERGE (c:CloudResource {resource_id: row.resource_id, tenant_id: row.tenant_id})
SET c.tenant_id = row.tenant_id,
SET c.cloud_provider = row.cloud_provider,
    c.resource_type = row.resource_type,
    c.name = row.name
"""

MERGE_USES = """
// cryptoscan.query=merge_uses
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (a:CryptoAsset {asset_id: row.asset_id, tenant_id: row.tenant_id})
MERGE (s)-[r:USES]->(a)
SET r.usage_type = row.usage_type,
    r.provenance = row.provenance,
    r.source = row.source
"""

MERGE_CALLS = """
// cryptoscan.query=merge_calls
UNWIND $rows AS row
MATCH (a:System {system_id: row.parent_id, tenant_id: row.tenant_id})
MATCH (b:System {system_id: row.child_id, tenant_id: row.tenant_id})
MERGE (a)-[rel:CALLS {relation: row.relation}]->(b)
WITH rel, row
WHERE coalesce(rel.lifecycle_revision, 0) <= coalesce(row.lifecycle_revision, 0)
  AND (rel.lifecycle_revision IS NULL OR row.lifecycle_revision IS NOT NULL)
SET rel.protocol = row.protocol,
    rel.relation = row.relation,
    rel.frequency = row.frequency,
    rel.provenance = row.provenance,
    rel.source = row.source,
    rel.observed_at = row.observed_at,
    rel.lifecycle_state = row.lifecycle_state,
    rel.lifecycle_source = row.lifecycle_source,
    rel.lifecycle_revision = row.lifecycle_revision,
    rel.valid_until = row.valid_until,
    rel.valid_until_epoch = row.valid_until_epoch,
    rel.last_confirmed_at = row.last_confirmed_at,
    rel.lifecycle_reason = row.lifecycle_reason,
    rel.lifecycle_evidence_ref = row.lifecycle_evidence_ref,
    rel.last_reconciliation_id = row.last_reconciliation_id,
    rel.projection_state = row.projection_state,
    rel.record_id = row.record_id
"""

MERGE_SUPPORTS = """
// cryptoscan.query=merge_supports
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (p:BusinessProcess {process_id: row.process_id, tenant_id: row.tenant_id})
MERGE (s)-[r:SUPPORTS]->(p)
SET r.provenance = 'DECLARED',
    r.source = 'system_business_process mapping'
"""

MERGE_OWNED_BY = """
// cryptoscan.query=merge_owned_by
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (o:BusinessOwner {owner_id: row.owner_id, tenant_id: row.tenant_id})
MERGE (s)-[r:OWNED_BY]->(o)
SET r.provenance = 'DECLARED',
    r.source = 'system owner mapping'
"""

MERGE_COMPLY = """
// cryptoscan.query=merge_comply
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (c:ComplianceScope {standard_name: row.standard_name, tenant_id: row.tenant_id})
MERGE (s)-[r:MUST_COMPLY_WITH]->(c)
SET r.provenance = 'DECLARED',
    r.source = 'system compliance_scopes'
"""

MERGE_VENDOR_EDGE = """
// cryptoscan.query=merge_vendor_edge
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (v:Vendor {vendor_id: row.vendor_id, tenant_id: row.tenant_id})
MERGE (s)-[r:DEPENDS_ON_VENDOR]->(v)
SET r.dependency_type = row.dependency_type,
    r.provenance = 'DECLARED',
    r.source = 'vendor dependency mapping'
"""

MERGE_SECURED_BY = """
// cryptoscan.query=merge_secured_by
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (c:Certificate {cert_id: row.cert_id, tenant_id: row.tenant_id})
MERGE (s)-[r:SECURED_BY]->(c)
SET r.endpoint = row.endpoint,
    r.provenance = 'SCANNER_DERIVED',
    r.source = 'certificate inventory'
"""

MERGE_DEPLOYED_ON = """
// cryptoscan.query=merge_deployed_on
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (c:CloudResource {resource_id: row.resource_id, tenant_id: row.tenant_id})
MERGE (s)-[r:DEPLOYED_ON]->(c)
SET r.provenance = 'DECLARED',
    r.source = 'cloud resource mapping'
"""

# Ghost-node pruning (report 03/09 — MERGE-only sync never removed deleted
# entities). One template per node kind; ids are chunked by the store.
PRUNE_KIND = """
// cryptoscan.query=prune_kind
MATCH (n:{label})
WHERE n.{prop} IS NOT NULL AND (
  (n.tenant_id IS NULL AND $tenant = 'platform')
  OR (n.tenant_id = $tenant AND NOT n.{prop} IN $ids)
)
DETACH DELETE n
RETURN count(n) AS pruned
"""

MERGE_NETWORK = """
// cryptoscan.query=merge_network
UNWIND $rows AS row
MERGE (n:NetworkResource {network_id: row.network_id, tenant_id: row.tenant_id})
SET n.tenant_id = row.tenant_id,
SET n.name = row.name,
    n.endpoint = row.endpoint,
    n.resource_type = row.resource_type
"""

MERGE_CONNECTS_TO = """
// cryptoscan.query=merge_connects_to
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (n:NetworkResource {network_id: row.network_id, tenant_id: row.tenant_id})
MERGE (s)-[r:CONNECTS_TO]->(n)
SET r.provenance = 'SCANNER_DERIVED',
    r.source = 'network probes'
"""


MERGE_CONTAINERS = """
// cryptoscan.query=merge_containers
UNWIND $rows AS row
MERGE (c:ContainerImage {container_id: row.container_id, tenant_id: row.tenant_id})
SET c.tenant_id = row.tenant_id,
SET c.name = row.name,
    c.image = row.image,
    c.package_count = row.package_count,
    c.library_count = row.library_count,
    c.vuln_count = row.vuln_count
"""

MERGE_RUNS = """
// cryptoscan.query=merge_runs
UNWIND $rows AS row
MATCH (s:System {system_id: row.system_id, tenant_id: row.tenant_id})
MATCH (c:ContainerImage {container_id: row.container_id, tenant_id: row.tenant_id})
MERGE (s)-[r:RUNS]->(c)
SET r.provenance = 'SCANNER_DERIVED',
    r.source = 'container image inventory'
"""


QUARANTINE_LEGACY_CALLS = """
// cryptoscan.query=quarantine_legacy_calls
MATCH (a:System)-[r:CALLS]->(b:System)
WHERE coalesce(a.tenant_id, 'platform') = $tenant AND coalesce(b.tenant_id, 'platform') = $tenant
  AND r.relation IS NULL
  AND EXISTS { MATCH (a)-[known:CALLS]->(b)
               WHERE known.relation IS NOT NULL AND known.lifecycle_revision IS NOT NULL }
SET r.projection_state = 'STALE', r.lifecycle_reason = 'ambiguous_legacy_projection'
RETURN count(r) AS quarantined
"""
