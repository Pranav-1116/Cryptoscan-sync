/* ── Enterprise Modals: Tenant Selector, Environment Selector, Audit Log Drawer, Evidence Provenance Drawer (Sections 54, 55, 58, 59) ── */

import React, { useState } from "react";
import { Modal, Badge, Button } from "./ui";
import { useEnterprise, ORGANIZATIONS, Environment, UserRole } from "./EnterpriseContext";

export function TenantModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { org, setOrg } = useEnterprise();

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Select Enterprise Organization & Region">
      <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "16px" }}>
        <p style={{ fontSize: "13px", color: "var(--dim)", margin: 0 }}>
          Cryptographic asset discovery and CBOM records are strictly isolated by organization and region.
        </p>

        {ORGANIZATIONS.map((o) => {
          const isSelected = org.id === o.id;
          return (
            <div
              key={o.id}
              onClick={() => { setOrg(o); onClose(); }}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "14px 16px",
                background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--bg-2)",
                border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                borderRadius: "8px",
                cursor: "pointer",
                transition: "all 0.15s ease",
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: "14px", color: isSelected ? "var(--cyan)" : "var(--text)" }}>
                  {o.name}
                </div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>
                  {o.subsidiary} · Region: {o.region}
                </div>
              </div>
              <Badge tone={isSelected ? "cyan" : "slate"}>
                {isSelected ? "ACTIVE" : "SWITCH"}
              </Badge>
            </div>
          );
        })}
      </div>
    </Modal>
  );
}

export function EnvironmentModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { env, setEnv } = useEnterprise();
  const envs: { id: Environment; label: string; desc: string; tone: string }[] = [
    { id: "Production", label: "Production", desc: "Live regulated payment gateways, core switches, and customer vaults.", tone: "red" },
    { id: "Staging", label: "Staging", desc: "Pre-production test clusters and integration environments.", tone: "amber" },
    { id: "Development", label: "Development", desc: "Local sandboxes and engineering builds.", tone: "blue" },
    { id: "DR", label: "Disaster Recovery (DR)", desc: "Warm standby replica sites and failover clusters.", tone: "violet" },
    { id: "Testing", label: "Testing", desc: "Automated regression and fuzzing clusters.", tone: "slate" },
  ];

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Select Deployment Environment">
      <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "16px" }}>
        <p style={{ fontSize: "13px", color: "var(--dim)", margin: 0 }}>
          Environment boundaries isolate policy evaluation rules, scanner profiles, and audit baselines.
        </p>

        {envs.map((e) => {
          const isSelected = env === e.id;
          return (
            <div
              key={e.id}
              onClick={() => { setEnv(e.id); onClose(); }}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "14px 16px",
                background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--bg-2)",
                border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                borderRadius: "8px",
                cursor: "pointer",
                transition: "all 0.15s ease",
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontWeight: 600, fontSize: "14px", color: "var(--text)" }}>{e.label}</span>
                  {e.id === "Production" && <Badge tone="red">● LIVE AUDITED</Badge>}
                </div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>
                  {e.desc}
                </div>
              </div>
              <Badge tone={isSelected ? "cyan" : "slate"}>
                {isSelected ? "CURRENT" : "SELECT"}
              </Badge>
            </div>
          );
        })}
      </div>
    </Modal>
  );
}

export function RoleModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { role, setRole } = useEnterprise();
  const roles: { id: UserRole; desc: string; canDo: string }[] = [
    { id: "Security Engineer", desc: "Investigates findings, initiates estate discovery, inspects WORM evidence.", canDo: "View, Scan, Evidence Inspection" },
    { id: "Security Administrator", desc: "Configures drift policies, approves baselines, manages scanners.", canDo: "Full Operational & Policy Control" },
    { id: "Auditor", desc: "Read-only access to immutable evidence packs, WORM logs, and compliance proofs.", canDo: "Read-only Evidence & Compliance Export" },
    { id: "Compliance Officer", desc: "Reviews PCI-DSS / DORA cross-standard mappings and exception workflows.", canDo: "Compliance & Risk Review" },
    { id: "Viewer", desc: "Read-only executive view of estate dashboards and high-level posture.", canDo: "Read-only Views" },
    { id: "Admin", desc: "Full administrative tenancy, user RBAC, integration keys, and maintenance controls.", canDo: "Full Enterprise Control" },
  ];

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Enterprise Role & RBAC Profile">
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "16px" }}>
        <p style={{ fontSize: "13px", color: "var(--dim)", margin: 0 }}>
          ZELNX enforces fine-grained RBAC. Actions not permitted by your active role are dynamically hidden.
        </p>

        {roles.map((r) => {
          const isSelected = role === r.id;
          return (
            <div
              key={r.id}
              onClick={() => { setRole(r.id); onClose(); }}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "12px 14px",
                background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--bg-2)",
                border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                borderRadius: "8px",
                cursor: "pointer",
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: "13.5px", color: isSelected ? "var(--cyan)" : "var(--text)" }}>
                  {r.id}
                </div>
                <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                  {r.desc}
                </div>
                <div style={{ fontSize: "10.5px", color: "var(--faint)", marginTop: "2px", fontFamily: "var(--mono)" }}>
                  Capabilities: {r.canDo}
                </div>
              </div>
              <Badge tone={isSelected ? "green" : "slate"}>
                {isSelected ? "ACTIVE" : "SWITCH"}
              </Badge>
            </div>
          );
        })}
      </div>
    </Modal>
  );
}
