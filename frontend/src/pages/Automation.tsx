import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiAutomationRules, apiAutomationCapabilities,
  apiAutomationSaveRule, apiAutomationDeleteRule,
} from "../lib/api.js";

/* Automation rule builder — deterministic event→action rules. A rule is
   WHEN <event> · IF <conditions> · THEN <actions>. The action catalog carries
   a safety tier: OBSERVE/ANALYZE/RECOMMEND actions run automatically, while
   APPROVE/EXECUTE-tier changes are NEVER auto-applied — they open a human
   approval gate (fail-closed). Triggers/actions come live from
   /automation/capabilities; rules persist via POST /automation/rules. */

// action safety tier (mirrors services/automation/.../safety.py ACTION_POLICY)
const ACTION_TIER: Record<string, "auto" | "gate"> = {
  targeted_rescan: "auto", update_cbom: "auto",
  create_alert: "auto", notify_webhook: "auto", notify_crypto_team: "auto",
  add_pqc_queue: "auto", add_to_pqc_queue: "auto",
  create_migration_task: "auto", create_ticket: "auto",
  request_approval: "gate", apply_remediation: "gate",
  config_change: "gate", firmware_update: "gate", disable_asset: "gate",
};
const tierOf = (a: string): "auto" | "gate" => ACTION_TIER[a] ?? "gate"; // unknown fails closed

const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function slug(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "rule";
}

export default function Automation() {
  const capsRes = usePollingApi(apiAutomationCapabilities, 60000);
  const rulesRes = usePollingApi(apiAutomationRules, 15000);
  const caps = (capsRes.data ?? {}) as any;
  const rules = (rulesRes.data ?? []) as any[];

  const eventKinds: string[] = caps.event_kinds ?? [];
  const actions: string[] = caps.actions ?? [];

  const [when, setWhen] = useState("quantum_vulnerable_detected");
  const [pickedActions, setPickedActions] = useState<string[]>(["create_alert"]);
  const [severity, setSeverity] = useState("MEDIUM");
  const [condField, setCondField] = useState("");
  const [condOp, setCondOp] = useState("equals");
  const [condVal, setCondVal] = useState("");
  const [conditions, setConditions] = useState<Array<{ field: string; operator: string; value: string }>>([]);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (eventKinds.length && !eventKinds.includes(when)) setWhen(eventKinds[0]);
  }, [eventKinds]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleAction = (a: string) =>
    setPickedActions((prev) => prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]);

  const addCondition = () => {
    if (!condField.trim()) return;
    setConditions((p) => [...p, { field: condField.trim(), operator: condOp, value: condVal }]);
    setCondField(""); setCondVal("");
  };

  const autoCount = pickedActions.filter((a) => tierOf(a) === "auto").length;
  const gateCount = pickedActions.length - autoCount;

  const save = async () => {
    setSaving(true); setMsg(null);
    const ruleId = `rb-${slug(when)}-${Date.now().toString(36)}`;
    const r = await apiAutomationSaveRule({
      rule_id: ruleId,
      name: `${when} → ${pickedActions.join(", ")}`,
      when,
      if: conditions,
      then: pickedActions,
      severity,
      enabled: true,
    });
    setSaving(false);
    if (r.ok) {
      setMsg({ ok: true, text: `Rule ${ruleId} saved.` });
      void rulesRes.run();
    } else {
      setMsg({ ok: false, text: r.error || "Could not save rule." });
    }
  };

  const remove = async (id: string) => {
    const r = await apiAutomationDeleteRule(id);
    if (r.ok) void rulesRes.run();
    else setMsg({ ok: false, text: r.error || "Could not delete rule." });
  };

  const playbooks: any[] = caps.playbooks ?? [];
  const safetyTiers: string[] = caps.safety_model?.tiers ?? ["OBSERVE", "ANALYZE", "RECOMMEND", "APPROVE", "EXECUTE", "VERIFY"];

  const canSave = pickedActions.length > 0 && when && !saving;

  return (
    <>
      <PageHead
        crumb="plan / automation"
        title="Automation rule builder"
        sub="WHEN an event fires · IF conditions match · THEN deterministic actions — change actions are approval-gated, never auto-executed"
        right={<Badge tone={rules.length ? "green" : ""}><span className="dot" /> {rules.length} active rule{rules.length === 1 ? "" : "s"}</Badge>}
      />

      {/* safety ladder */}
      <Panel title="Action safety ladder" sub="read/derive/notify actions run automatically; production-change actions always require human approval (fail-closed)">
        <div className="rb-tier">
          {safetyTiers.map((t, i) => (
            <div key={t} className={`tier ${i <= 2 ? "auto" : "gate"}`}>{t}</div>
          ))}
        </div>
        <div className="row" style={{ gap: 14, marginTop: 8, fontSize: 11.5, flexWrap: "wrap" }}>
          <span className="dim"><Badge tone="green">auto</Badge> OBSERVE · ANALYZE · RECOMMEND — run without intervention</span>
          <span className="dim"><Badge tone="amber">approval</Badge> APPROVE · EXECUTE — open a governance gate, AI never decides</span>
        </div>
      </Panel>

      <div className="grid cols-2 mt" style={{ gridTemplateColumns: "minmax(0,1.35fr) minmax(0,1fr)" }}>
        {/* builder */}
        <Panel title="Build a rule" sub="pick a trigger, optional conditions, and one or more actions">
          <div className="rb-whenthen">
            <span className="rb-clause">when</span>
            <div>
              <select className="inp" value={when} onChange={(e) => setWhen(e.target.value)} style={{ width: "100%" }}>
                {eventKinds.map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>

            <span className="rb-clause">if</span>
            <div>
              {conditions.length > 0 && (
                <div className="rb-conds">
                  {conditions.map((c, i) => (
                    <div key={i}>• {c.field} {c.operator} {c.value || "∅"}
                      <button className="btn sm" style={{ marginInlineStart: 8, padding: "1px 7px" }}
                        onClick={() => setConditions((p) => p.filter((_, j) => j !== i))}>✕</button>
                    </div>
                  ))}
                </div>
              )}
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                <input className="inp" placeholder="field (e.g. severity)" value={condField} onChange={(e) => setCondField(e.target.value)} style={{ flex: "1 1 140px" }} />
                <select className="inp" value={condOp} onChange={(e) => setCondOp(e.target.value)} style={{ width: 110 }}>
                  {["equals", "not_equals", "contains", "gt", "lt"].map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
                <input className="inp" placeholder="value" value={condVal} onChange={(e) => setCondVal(e.target.value)} style={{ flex: "1 1 100px" }} />
                <button className="btn sm" onClick={addCondition}>+ condition</button>
              </div>
            </div>

            <span className="rb-clause">then</span>
            <div className="opt-grid">
              {actions.map((a) => {
                const sel = pickedActions.includes(a);
                const tier = tierOf(a);
                return (
                  <button key={a} className={`opt ${sel ? "sel" : ""}`} onClick={() => toggleAction(a)}>
                    <span>{sel ? "◉" : "○"}</span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11.5 }}>{a}</span>
                    <span className={`opt-tag ${tier}`}>{tier === "auto" ? "auto" : "approval"}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="row" style={{ gap: 10, marginTop: 16, flexWrap: "wrap" }}>
            <label style={{ fontSize: 12, color: "var(--dim)", display: "flex", alignItems: "center", gap: 8 }}>
              severity
              <select className="inp" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <button className="btn primary" disabled={!canSave} onClick={() => void save()}>
              {saving ? "Saving…" : "Save rule"}
            </button>
            <span style={{ marginInlineStart: "auto" }} className="dim" />
          </div>
          <div className="row" style={{ gap: 8, marginTop: 10, fontSize: 12 }}>
            <Badge tone="green">{autoCount} auto action{autoCount === 1 ? "" : "s"}</Badge>
            {gateCount > 0 && <Badge tone="amber">{gateCount} approval-gated</Badge>}
          </div>
          {msg && (
            <div style={{ marginTop: 10, fontSize: 12.5, color: msg.ok ? "var(--green)" : "var(--red)" }}>{msg.text}</div>
          )}
        </Panel>

        {/* active rules */}
        <Panel title="Active rules" sub="rules loaded into the deterministic engine">
          {rules.length === 0 ? (
            <div className="dim" style={{ fontSize: 13 }}>
              No custom rules yet — built-in playbooks run by default. Create one on the left.
            </div>
          ) : (
            rules.map((r, i) => {
              const thenActs: string[] = r.then ?? r.actions ?? [];
              const conds: any[] = r.if ?? r.conditions ?? [];
              return (
                <div key={r.rule_id ?? r.id ?? i} className="rb-rule-card">
                  <div className="rb-top">
                    <span className="rb-name mono">{r.name || r.rule_id || r.id}</span>
                    <Badge tone={String(r.severity || "MEDIUM").toLowerCase() === "critical" || String(r.severity).toLowerCase() === "high" ? "red" : "amber"}>{r.severity || "MEDIUM"}</Badge>
                    {r.enabled === false && <Badge tone="slate">disabled</Badge>}
                    <button className="btn sm" style={{ marginInlineStart: "auto" }}
                      onClick={() => void remove(r.rule_id ?? r.id)}>delete</button>
                  </div>
                  <div className="rb-when" style={{ marginTop: 6 }}>WHEN {r.when}</div>
                  {conds.length > 0 && (
                    <div className="rb-conds">
                      {conds.map((c, j) => <div key={j}>IF {c.field} {c.operator} {String(c.value ?? "")}</div>)}
                    </div>
                  )}
                  <div className="rb-actions">
                    {thenActs.map((a) => (
                      <Badge key={a} tone={tierOf(a) === "gate" ? "amber" : "green"}>{a}</Badge>
                    ))}
                  </div>
                </div>
              );
            })
          )}
        </Panel>
      </div>

      {/* built-in playbooks */}
      <Panel title="Built-in playbooks" sub="deterministic response packs available out of the box" className="mt">
        {playbooks.length === 0 ? (
          <div className="dim" style={{ fontSize: 13 }}>{capsRes.source === "live" ? "No playbooks reported." : "Backend offline."}</div>
        ) : (
          <div className="grid cols-3" style={{ marginTop: 4 }}>
            {playbooks.map((p) => (
              <div key={p.id} className="plug-card">
                <div className="plug-head">
                  <span className="plug-id">{p.name}</span>
                  <Badge tone="cyan">{p.trigger}</Badge>
                </div>
                <div className="dim" style={{ fontSize: 12 }}>{p.description}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}
