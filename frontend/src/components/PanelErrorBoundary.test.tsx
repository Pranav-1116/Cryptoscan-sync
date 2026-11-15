/* One panel's failure must not crash the dashboard (Critical: error
 * boundaries). Panel mounts the boundary, so isolation is automatic. */

import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Panel } from "./ui";
import { PanelErrorBoundary } from "./ErrorBoundary";

function Boom(): never {
  throw new Error("chart exploded");
}

describe("panel error isolation", () => {
  it("a failing panel shows a fallback while sibling panels stay live", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <div>
        <Panel title="Vulnerable chart"><Boom /></Panel>
        <Panel title="Healthy inventory"><p>assets still listed</p></Panel>
      </div>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/failed to render/);
    expect(screen.getByText("assets still listed")).toBeTruthy();
    spy.mockRestore();
  });

  it("offers a retry that re-renders the children", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    let explode = true;
    function Flaky() {
      if (explode) throw new Error("transient");
      return <p>recovered panel</p>;
    }
    render(
      <PanelErrorBoundary label="Flaky chart">
        <Flaky />
      </PanelErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/Flaky chart/);
    explode = false;
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(screen.getByText("recovered panel")).toBeTruthy();
    spy.mockRestore();
  });
});
