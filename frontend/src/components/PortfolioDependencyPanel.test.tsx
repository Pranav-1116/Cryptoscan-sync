import { describe, expect, it } from "vitest";
import { systemRows } from "./PortfolioDependencyPanel";

const bom = {
  metadata: { component: { name: "cryptoscan-portfolio", "bom-ref": "root:cryptoscan-portfolio" } },
  components: [
    { type: "cryptographic-asset", name: "RSA", "bom-ref": "a1", cryptoProperties: {} },
    { type: "cryptographic-asset", name: "3DES", "bom-ref": "a2", cryptoProperties: {} },
    { type: "application", name: "payments-api", "bom-ref": "system:payments-api", properties: [{ name: "cryptoscan:system:criticality", value: "critical" }] },
    { type: "application", name: "hsm-gateway", "bom-ref": "system:hsm-gateway", properties: [] },
    { type: "application", name: "unassigned", "bom-ref": "system:unassigned", properties: [] },
  ],
  dependencies: [
    { ref: "root:cryptoscan-portfolio", dependsOn: ["system:payments-api", "system:hsm-gateway", "system:unassigned"] },
    { ref: "system:payments-api", dependsOn: ["a1", "system:hsm-gateway"] },
    { ref: "system:hsm-gateway", dependsOn: ["a2"] },
  ],
};

describe("estate CBOM dependency rows", () => {
  it("derives per-system assets, depends-on and dependents from dependencies[]", () => {
    const rows = systemRows(bom as any);
    const by = Object.fromEntries(rows.map((r) => [r.name, r]));
    expect(by["payments-api"]).toMatchObject({ criticality: "critical", assets: 1, dependsOn: ["hsm-gateway"], dependents: [] });
    expect(by["hsm-gateway"]).toMatchObject({ assets: 1, dependsOn: [], dependents: ["payments-api"] });
    expect(by["unassigned"].assets).toBe(0);
    expect(rows[0].name).toBe("hsm-gateway"); // most depended-on first (widest blast radius)
  });
});
