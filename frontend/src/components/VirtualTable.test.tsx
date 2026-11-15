/* VirtualTable: a 50,000-row inventory mounts only the visible window. */

import { beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import VirtualTable from "./VirtualTable.js";

// jsdom has no layout: make styled heights measurable so the virtualizer
// sees a real viewport, and provide the ResizeObserver it observes with.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "clientHeight", {
    configurable: true,
    get(this: HTMLElement) {
      const styled = Number((this.style?.height ?? "").replace("px", ""));
      return Number.isFinite(styled) && styled > 0 ? styled : 400;
    },
  });
  if (!("ResizeObserver" in globalThis)) {
    class RO {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = RO;
  }
});

const rows = (n: number) =>
  Array.from({ length: n }, (_, i) => [`asset-${i}`, `host-${i}`, "prod"]);

describe("VirtualTable", () => {
  it("renders only a window of rows even for huge inventories", () => {
    const { container } = render(
      <VirtualTable head={["Asset", "Host", "Env"]} rows={rows(50_000)} height={400} rowHeight={40} />,
    );
    const rendered = container.querySelectorAll(".virtual-row");
    // ~10 visible + overscan — never 50,000.
    expect(rendered.length).toBeGreaterThan(0);
    expect(rendered.length).toBeLessThan(40);
  });

  it("announces the true total to assistive technology", () => {
    render(
      <VirtualTable
        head={["Asset", "Host", "Env"]}
        rows={rows(200)}
        total={50_000}
        height={400}
        rowHeight={40}
      />,
    );
    const grid = screen.getByRole("grid");
    expect(grid.getAttribute("aria-rowcount")).toBe("50000");
  });

  it("navigates with the keyboard and reports selection", () => {
    const onSelect = vi.fn();
    render(
      <VirtualTable
        head={["Asset", "Host", "Env"]}
        rows={rows(100)}
        height={400}
        rowHeight={40}
        selected={0}
        onSelect={onSelect}
      />,
    );
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    expect(onSelect).toHaveBeenLastCalledWith(1);
    fireEvent.keyDown(grid, { key: "End" });
    expect(onSelect).toHaveBeenLastCalledWith(99);
    fireEvent.keyDown(grid, { key: "Home" });
    expect(onSelect).toHaveBeenLastCalledWith(0);
    fireEvent.keyDown(grid, { key: "PageDown" });
    const last = onSelect.mock.calls[onSelect.mock.calls.length - 1];
    expect(last[0]).toBeGreaterThan(1);
  });

  it("shows the empty state instead of an empty grid", () => {
    render(
      <VirtualTable head={["A"]} rows={[]} empty={<p>no assets</p>} />,
    );
    expect(screen.getByText("no assets")).toBeTruthy();
  });
});
