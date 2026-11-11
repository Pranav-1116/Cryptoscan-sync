import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import DomainCrossNav, { DOMAIN_VIEWS } from "./DomainCrossNav";

const renderNav = (current: string) =>
  render(
    <MemoryRouter>
      <DomainCrossNav current={current} />
    </MemoryRouter>,
  );

describe("DomainCrossNav", () => {
  it("links the six asset-discovery domains as one workspace", () => {
    renderNav("assets");
    const nav = screen.getByRole("navigation", { name: "Asset discovery domains" });
    expect(nav).toBeInTheDocument();
    for (const domain of DOMAIN_VIEWS) {
      expect(screen.getByRole("link", { name: domain.label })).toHaveAttribute("href", domain.path);
    }
  });

  it("marks only the current domain with aria-current", () => {
    renderNav("cloud");
    expect(screen.getByRole("link", { name: "Cloud" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Assets" })).not.toHaveAttribute("aria-current");
  });

  it("never claims a domain it cannot name: every tab is a real route", () => {
    for (const domain of DOMAIN_VIEWS) {
      expect(domain.path.startsWith("/"), domain.label).toBe(true);
    }
    expect(new Set(DOMAIN_VIEWS.map((d) => d.path)).size).toBe(DOMAIN_VIEWS.length);
  });
});
