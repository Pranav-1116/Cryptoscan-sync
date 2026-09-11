import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiCloudAccounts, apiCloudKeys, apiCloudCollect, CloudAccount, CloudCollectResult } from "../lib/api.js";

/* Cloud — connected read-only cloud accounts rendered as a provider tree
   (AWS / Azure / GCP → account → regions). Source of truth is
   GET /api/v1/cloud/accounts. Scans are strictly read-only and credentials
   stay in the vault (only a role reference is shown). The tree is empty until
   an account is registered via onboarding — nothing is fabricated.

   Below the estate tree: the cloud KMS key inventory (AWS KMS / Azure Key
   Vault). Collection normalizes key METADATA into the same crypto-asset
   inventory as file discovery — no key material is ever fetched or stored,
   unknown key types are skipped with their reason, never guessed. */

const PROVIDERS = ["AWS", "AZURE", "GCP"] as const;
type Prov = (typeof PROVIDERS)[number] | "OTHER";

const PROV_META: Record<Prov, { glyph: string; name: string; color: string }> = {
  AWS: { glyph: "☁", name: "Amazon Web Services", color: "#f59e0b" },
  AZURE: { glyph: "◇", name: "Microsoft Azure", color: "#3b82f6" },
  GCP: { glyph: "◈", name: "Google Cloud Platform", color: "#22c55e" },
  OTHER: { glyph: "▤", name: "Other / unknown", color: "#64748b" },
};

function providerOf(a: CloudAccount): Prov {
  const p = String(a.cloud_provider || a.provider || "").toUpperCase();
  return (PROVIDERS as readonly string[]).includes(p) ? (p as Prov) : "OTHER";
}
function regionsOf(a: CloudAccount): string[] {
  if (Array.isArray(a.regions)) return a.regions.filter(Boolean);
  if (typeof a.regions === "string") return a.regions.split(",").map((s) => s.trim()).filter(Boolean);
  return [];
}

export default function Cloud() {
  const res = useApi(() => apiCloudAccounts(), []);
  const live = res.source === "live";
  const accounts: CloudAccount[] = useMemo(() => res.data?.accounts ?? [], [res.data]);
  const [open, setOpen] = useState<Record<string, boolean>>({ AWS: true, AZURE: true, GCP: true, OTHER: true });
  const [showTable, setShowTable] = useState(false);

  const byProvider = useMemo(() => {
    const map: Record<Prov, CloudAccount[]> = { AWS: [], AZURE: [], GCP: [], OTHER: [] };
    for (const a of accounts) map[providerOf(a)].push(a);
    return map;
  }, [accounts]);

  const totalRegions = useMemo(
    () => new Set(accounts.flatMap(regionsOf)).size, [accounts]);
  const connected = accounts.filter((a) => a.enabled !== false).length;

  const toggle = (p: string) => setOpen((s) => ({ ...s, [p]: !s[p] }));

  /* ── cloud KMS key inventory ─────────────────────────────────────────── */
  const keysRes = useApi(() => apiCloudKeys(), []);
  const [kmsRef, setKmsRef] = useState("");
  const [collecting, setCollecting] = useState<string | null>(null);
  const [collectResult, setCollectResult] = useState<CloudCollectResult | null>(null);
  const [collectErr, setCollectErr] = useState<string | null>(null);

  const collect = async (provider: "aws-kms" | "azure-keyvault" | "gcp-kms" | "aws-acm", dryRun: boolean) => {
    setCollecting(provider);
    setCollectErr(null);
    const opts = provider === "aws-kms" || provider === "aws-acm"
      ? { region: kmsRef.trim(), dry_run: dryRun }
      : provider === "gcp-kms"
        ? { project: kmsRef.trim(), dry_run: dryRun }
        : { vault_url: kmsRef.trim(), dry_run: dryRun };
    const res = await apiCloudCollect(provider, opts);
    setCollecting(null);
    if (res.source === "live" && res.data) {
      setCollectResult(res.data);
      void keysRes.run();
    } else {
      setCollectErr(res.error || "collection failed");
    }
  };

  return (
    <>
      <PageHead
        crumb="discovery / cloud"
        title="Cloud estate"
        sub="Read-only AWS · Azure · GCP accounts — role references and regions (credentials stay vaulted)"
        right={
          <>
            <LiveBadge source={res.source} />
            <Badge tone={live && accounts.length ? "green" : ""}>
              <span className="dot" /> {accounts.length} accounts · {totalRegions} regions
            </Badge>
            <button className="btn sm" onClick={() => setShowTable((v) => !v)}>
              {showTable ? "tree view" : "table view"}
            </button>
          </>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div className="kpi"><span className="k">connected accounts</span><span className="v" style={{ color: "var(--cyan)" }}>{connected}</span></div>
        <div className="kpi"><span className="k">disabled</span><span className="v">{accounts.length - connected}</span></div>
        <div className="kpi"><span className="k">regions in scope</span><span className="v">{totalRegions}</span></div>
        <div className="kpi"><span className="k">providers</span><span className="v">{PROVIDERS.filter((p) => byProvider[p].length).length}</span></div>
      </div>

      {!accounts.length ? (
        <Panel title="Connected cloud accounts" sub="read-only scanning; no secrets stored in scan records">
          <div className="dim" style={{ fontSize: 13, padding: "18px 4px" }}>
            {live
              ? "No cloud accounts connected yet — register one in Onboarding (read-only; credentials are vault references)."
              : "Backend offline — cloud accounts unavailable."}
            <br /><a href="#/onboarding" className="mono" style={{ fontSize: 12 }}>go to onboarding →</a>
          </div>
        </Panel>
      ) : showTable ? (
        <Panel title="Connected cloud accounts" sub="read-only scanning; no secrets stored in scan records">
          <Table
            head={["provider", "account identifier", "role / access reference", "regions", "status"]}
            rows={accounts.map((c) => [
              <Badge tone="violet">{providerOf(c)}</Badge>,
              <span className="mono">{c.account_identifier ?? c.account_id ?? "—"}</span>,
              <span className="mono dim" style={{ fontSize: 12 }}>{c.role_arn ? "vault-ref / role configured" : "—"}</span>,
              <span className="dim">{regionsOf(c).join(", ") || "—"}</span>,
              c.enabled === false ? <Badge tone="amber">disabled</Badge> : <Badge tone="green">{c.status || "connected"}</Badge>,
            ])}
          />
        </Panel>
      ) : (
        <Panel
          title="Provider tree"
          sub="provider → account → regions · click a provider to collapse · read-only"
        >
          <div className="cloud-tree">
            {(Object.keys(PROV_META) as Prov[]).map((p) => {
              const list = byProvider[p];
              const meta = PROV_META[p];
              if (list.length === 0) return null;
              const isOpen = open[p] !== false;
              const acctRegions = new Set(list.flatMap(regionsOf)).size;
              return (
                <div key={p} className={`cloud-prov ${isOpen ? "open" : ""}`} data-prov={p}>
                  <button className="prov-head" onClick={() => toggle(p)}>
                    <span className="prov-caret">▶</span>
                    <span className="prov-glyph" style={{ color: meta.color }}>{meta.glyph}</span>
                    <span className="prov-name">{meta.name}</span>
                    <span className="prov-count">{list.length} account{list.length === 1 ? "" : "s"} · {acctRegions} region{acctRegions === 1 ? "" : "s"}</span>
                    <span className="prov-spacer" />
                    <Badge tone={list.some((a) => a.enabled === false) ? "amber" : "green"}>
                      {list.filter((a) => a.enabled !== false).length}/{list.length} active
                    </Badge>
                  </button>
                  {isOpen && (
                    <div className="cloud-accounts">
                      {list.map((a, i) => {
                        const id = a.account_identifier ?? a.account_id ?? `account-${i}`;
                        const regs = regionsOf(a);
                        const disabled = a.enabled === false;
                        return (
                          <div key={`${p}-${id}-${i}`} className="cloud-acct">
                            <div className="acct-line">
                              <span className="acct-id">{id}</span>
                              {a.role_arn
                                ? <Badge tone="cyan">vault-ref role</Badge>
                                : <span className="acct-ref">no role ref</span>}
                              <span style={{ marginInlineStart: "auto" }}>
                                {disabled
                                  ? <Badge tone="amber">disabled</Badge>
                                  : <Badge tone="green">{a.status || "connected"}</Badge>}
                              </span>
                            </div>
                            {regs.length > 0 && (
                              <div className="acct-regions">
                                {regs.map((r) => <span key={r} className="region-chip">{r}</span>)}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      <Panel title="Cloud KMS key inventory" sub="AWS KMS · Azure Key Vault · GCP KMS keys + AWS ACM certificates — metadata folded into the same inventory (read-only; no key material fetched or stored)" className="mt">
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input
            className="inp"
            placeholder="AWS region · Azure vault URL · GCP project (optional)"
            value={kmsRef}
            onChange={(e) => setKmsRef(e.target.value)}
            style={{ flex: "1 1 260px" }}
          />
          <button className="btn sm" disabled={collecting !== null} onClick={() => void collect("aws-kms", true)}>
            preview AWS KMS
          </button>
          <button className="btn sm primary" disabled={collecting !== null} onClick={() => void collect("aws-kms", false)}>
            {collecting === "aws-kms" ? "Collecting…" : "Collect AWS KMS"}
          </button>
          <button className="btn sm primary" disabled={collecting !== null} onClick={() => void collect("azure-keyvault", false)}>
            {collecting === "azure-keyvault" ? "Collecting…" : "Collect Azure Key Vault"}
          </button>
          <button className="btn sm primary" disabled={collecting !== null} onClick={() => void collect("gcp-kms", false)}>
            {collecting === "gcp-kms" ? "Collecting…" : "Collect GCP KMS"}
          </button>
          <button className="btn sm primary" disabled={collecting !== null} onClick={() => void collect("aws-acm", false)}>
            {collecting === "aws-acm" ? "Collecting…" : "Collect AWS ACM certs"}
          </button>
        </div>
        {collectErr && (
          <div style={{ color: "var(--red)", fontSize: 12.5, marginTop: 8 }}>✕ {collectErr}</div>
        )}
        {collectResult && (
          <div style={{ marginTop: 10, fontSize: 12.5, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <Badge tone={collectResult.created ? "green" : "cyan"}>
              {collectResult.created} new · {collectResult.upserted} upserted · {collectResult.seen} seen
            </Badge>
            {collectResult.truncated && <Badge tone="amber">more keys exist — bounded pass of 100</Badge>}
            {collectResult.skipped.length > 0 && (
              <Badge tone="amber">{collectResult.skipped.length} skipped — reasons below, never guessed</Badge>
            )}
            {collectResult.skipped.length > 0 && (
              <div className="mono dim" style={{ fontSize: 11.5, width: "100%" }}>
                {collectResult.skipped.slice(0, 4).map((s) => (
                  <div key={s.ref}>skip {s.ref}: {s.reason}</div>
                ))}
              </div>
            )}
          </div>
        )}
        <div style={{ marginTop: 12 }}>
          {(keysRes.data?.assets ?? []).length === 0 ? (
            <div className="dim" style={{ fontSize: 13 }}>
              {keysRes.source === "live"
                ? "No cloud KMS keys collected yet — run a collection above (requires cloud credentials on the platform side)."
                : "Backend offline — cloud key inventory unavailable."}
            </div>
          ) : (
            <Table
              head={["family", "bits", "purpose", "provider", "reference", "quantum-relevant", "first seen"]}
              rows={(keysRes.data?.assets ?? []).map((k) => {
                const extra = (k.extra ?? {}) as Record<string, string>;
                const qrelevant = /^(RSA|ECDSA|DH|ECDH)/.test(k.algorithm || "");
                return [
                  <span className="mono">{k.algorithm}</span>,
                  <span>{k.key_size ?? "—"}</span>,
                  <span className="dim">{k.purpose ?? "—"}</span>,
                  <Badge tone="violet">{String(extra.collector ?? "cloud")}</Badge>,
                  <span className="mono dim" style={{ fontSize: 11.5 }}>{k.file_path}</span>,
                  qrelevant ? <Badge tone="red">Shor-exposed</Badge> : <Badge tone="green">no</Badge>,
                  <span className="dim">{extra.first_seen_at ? String(extra.first_seen_at).slice(0, 10) : "—"}</span>,
                ];
              })}
            />
          )}
        </div>
      </Panel>

      <Panel title="Scan policy" sub="cloud safety guarantees" className="mt">
        <div className="mono" style={{ fontSize: 12.5, display: "flex", flexDirection: "column", gap: 8 }}>
          <div><span className="faint">access mode:</span> READ-ONLY · no resource mutation</div>
          <div><span className="faint">credentials:</span> vault references only · never in scan state or logs</div>
          <div><span className="faint">enumeration:</span> metadata + configuration · no exploit probing</div>
        </div>
      </Panel>
    </>
  );
}
