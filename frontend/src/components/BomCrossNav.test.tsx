import React from "react";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import BomCrossNav, {
  CROSS_BOM_RELATIONSHIPS,
} from "./BomCrossNav";

const renderNav = (current: string, route = "/sbom") =>
  render(
    <MemoryRouter initialEntries={[route]}>
      <BomCrossNav current={current} />
    </MemoryRouter>,
  );

describe("BomCrossNav — cross-BOM relationships are navigable (gap analysis §A)", () => {
  it("names every BOM view and marks the current one", () => {
    renderNav("CBOM", "/cbom");
    for (const label of ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TechBOM"]) {
      expect(screen.getByRole("link", { name: label })).toHaveAttribute(
        "href",
        expect.stringContaining(label === "TechBOM" ? "/live-asset-intelligence" : `/${label.toLowerCase()}`),
      );
    }
    expect(screen.getByRole("link", { name: "CBOM" })).toHaveAttribute(
      "aria-current", "page");
  });

  it("the current BOM names its cross-BOM relationship as a link", () => {
    renderNav("SBOM", "/sbom");
    const rel = CROSS_BOM_RELATIONSHIPS[0];
    const link = screen.getByRole("link", {
      name: `${rel.relationship} → ${rel.to}`,
    });
    expect(link).toHaveAttribute("href", "/cbom");
  });

  it("a carried focus term survives navigation between BOM views", () => {
    renderNav("SBOM", "/sbom?focus=OpenSSL");
    expect(screen.getByTestId("bom-focus")).toHaveTextContent("OpenSSL");
    // every sibling BOM link carries the same term
    expect(screen.getByRole("link", { name: "CBOM" })).toHaveAttribute(
      "href", "/cbom?focus=OpenSSL");
    expect(screen.getByRole("link", { name: "NBOM" })).toHaveAttribute(
      "href", "/nbom?focus=OpenSSL");
    expect(screen.getByRole("link", { name: "TechBOM" })).toHaveAttribute(
      "href", "/live-asset-intelligence?focus=OpenSSL");
  });
});
