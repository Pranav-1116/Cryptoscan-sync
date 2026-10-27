# Architecture and dataflow diagrams

[Recovery pack index](../README.md)

These are rendered **SVG diagrams**, not screenshots or AI-generated architecture
illustrations. Each has editable Graphviz **DOT source**, an accessible SVG title
and description, and a caption in the corresponding Markdown guide. Open the SVG
for full resolution; the Markdown image may be scaled down on a small screen.

## Diagram inventory

| # | Diagram | Main explanation | Source |
|---|---|---|---|
| 01 | [System architecture](01-system-architecture.svg) | [Architecture and boundaries](../01-architecture-and-recovery-boundaries.md) | [DOT](01-system-architecture.dot) |
| 02 | [Consistency groups](02-consistency-groups.svg) | [Inventory and cohorts](../02-data-inventory-and-consistency-groups.md) | [DOT](02-consistency-groups.dot) |
| 03 | [Backup dataflow](03-backup-dataflow.svg) | [Capture through independent-copy and restore acceptance](../03-backup-policy-and-end-to-end-dataflow.md) | [DOT](03-backup-dataflow.dot) |
| 04 | [Recovery dataflow](04-recovery-dataflow.svg) | [Incident through isolated restore and cutover](../04-disaster-recovery-runbook.md) | [DOT](04-recovery-dataflow.dot) |
| 05 | [Execution reconciliation](05-execution-reconciliation.svg) | [SQL authority, UNKNOWN and new-job admission](../05-queue-execution-and-evidence-reconciliation.md) | [DOT](05-execution-reconciliation.dot) |
| 06 | [Key and ransomware boundaries](06-key-and-ransomware-boundaries.svg) | [Separate custody and clean recovery](../06-security-keys-ransomware-and-retention.md) | [DOT](06-key-and-ransomware-boundaries.dot) |
| 07 | [Failback dataflow](07-failback-dataflow.svg) | [Preserve all new recovery-side writes](../08-scenario-playbooks-and-operating-templates.md) | [DOT](07-failback-dataflow.dot) |
| 08 | [Drill and acceptance](08-drill-and-acceptance.svg) | [Measured evidence and separate review](../07-drills-validation-and-acceptance.md) | [DOT](08-drill-and-acceptance.dot) |

The [catalog](catalog.json) records titles, descriptions and expected structural
counts: **8 diagrams / 92 nodes / 118 edges**. These counts describe drawings,
not deployed services, completed controls or passed recovery tests.

## Legend and scope

- **Blue:** durable data or an authority store.
- **Green:** operational step or control.
- **Amber:** decision, trust or bank-provisioned dependency.
- **Gray:** conditional/derived/transient component.
- **Red:** stop, unsafe, refused or blocked state.
- A dashed edge is conditional scope; it does not enable the feature.

Color does not certify a site control as implemented. Vault, isolated recovery,
key custody, replication, immutable storage and offsite arrows are required site
architecture unless separately demonstrated. The controlled profile excludes
unqualified graph/live collectors. Each chapter states the applicable boundary.

## Reproduce the SVGs without changing product dependencies

The documentation renderer is [render.mjs](render.mjs). It uses
`@viz-js/viz` **3.31.0** and Graphviz's `dot` layout through WASM. Initial visual
previews were rasterized outside Git with `@resvg/resvg-js` **2.6.2**; only SVGs
are deliverables. No application package/lockfile or deployed image is changed.

Use an approved isolated documentation-build environment, not a bank runtime.
Review the package/version under the organization's dependency policy. Offline
sites must supply their approved cached tooling; a public registry is not a
required recovery dependency.

```bash
set -eu
# Approved paths must name a NEW tool directory and a NEW output directory.
: "${APPROVED_DIAGRAM_TOOL_DIR:?new isolated tool directory required}"
: "${APPROVED_DIAGRAM_OUTPUT:?new output directory required}"
DIAGRAM_SOURCE="$PWD/docs/disaster-recovery/diagrams"
test ! -e "$APPROVED_DIAGRAM_TOOL_DIR"
test ! -e "$APPROVED_DIAGRAM_OUTPUT"
mkdir -p "$APPROVED_DIAGRAM_TOOL_DIR"
cp "$DIAGRAM_SOURCE/render.mjs" "$APPROVED_DIAGRAM_TOOL_DIR/render.mjs"
npm install --prefix "$APPROVED_DIAGRAM_TOOL_DIR" \
  --ignore-scripts --no-audit --no-fund @viz-js/viz@3.31.0
node "$APPROVED_DIAGRAM_TOOL_DIR/render.mjs" \
  --input "$DIAGRAM_SOURCE" --output "$APPROVED_DIAGRAM_OUTPUT"
```

The output must be new and outside the diagram source directory; existing output
is refused rather than overwritten. Review the render and compare before
replacing checked-in SVGs. Keep DOT labels, catalog descriptions/counts and
Markdown captions synchronized; source correctness needs human review as well as
successful layout. SVGs contain no external image/font loads, scripts or external
DTD. XML namespace identifiers are not external network dependencies.
