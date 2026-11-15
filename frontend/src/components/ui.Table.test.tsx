/* Windowed rendering for the generic Table: a large row array must never
 * land fully in the DOM (the 50k-asset rule), and the disclosure must say
 * what is not rendered. */

import { describe, expect, it } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";
import { Table } from "./ui";

const big = Array.from({ length: 1500 }, (_, i) => [`asset-${i}`, i]);

describe("Table windowing", () => {
  it("renders a window, not the whole array, and says so", () => {
    render(<Table head={["asset", "n"]} rows={big} />);
    // first window only (200), never all 1500
    expect(document.querySelectorAll("tbody tr").length).toBe(200);
    expect(screen.getByRole("status")).toHaveTextContent(/Showing 200 of 1,500 rows/);
  });

  it("extends the window on scroll and keeps aria-rowcount truthful", () => {
    const { container } = render(<Table head={["asset", "n"]} rows={big} />);
    const scroller = container.firstElementChild as HTMLElement;
    expect(scroller.querySelector("table")).toHaveAttribute("aria-rowcount", "1500");
    // scroll to the bottom of the rendered window
    Object.defineProperty(scroller, "scrollTop", { value: 99999, configurable: true });
    Object.defineProperty(scroller, "clientHeight", { value: 400, configurable: true });
    Object.defineProperty(scroller, "scrollHeight", { value: 100000, configurable: true });
    fireEvent.scroll(scroller);
    expect(document.querySelectorAll("tbody tr").length).toBe(400);
  });

  it("small tables render whole — no windowing chrome", () => {
    render(<Table head={["a"]} rows={[["x"], ["y"]]} />);
    expect(document.querySelectorAll("tbody tr").length).toBe(2);
    expect(screen.queryByRole("status")).toBeNull();
  });
});
