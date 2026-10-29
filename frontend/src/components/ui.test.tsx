/* UI primitives used by every page. */
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Badge, Bar, Button, Drawer, Kpi, PageHead, Panel, ProgressBar, Ring, Stat, Table, Tabs } from "./ui";

describe("ui primitives", () => {
  it("Panel renders title, subtitle and children", () => {
    render(<Panel title="Findings" sub="last scan"><span>body</span></Panel>);
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("last scan")).toBeInTheDocument();
    expect(screen.getByText("body")).toBeInTheDocument();
  });

  it("Stat / Kpi show label and value, including honest zero", () => {
    render(<><Stat label="Open" value={0} /><Kpi k="Critical" v="0" /></>);
    expect(screen.getByText("Open")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getAllByText("0").length).toBeGreaterThanOrEqual(2);
  });

  it("Badge renders its content", () => {
    render(<Badge tone="critical">CRITICAL</Badge>);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  /* `warn`/`critical`/`ok` are state words, not colour names. They used to
     reach the class attribute verbatim ("badge warn"), and global.css defines
     no `.badge.warn`, so the badge rendered with no colour at all. */
  it("Badge resolves a state word to the colour class it stands for", () => {
    const { container, rerender } = render(<Badge tone="warn">EXPORT</Badge>);
    expect(container.querySelector(".badge")?.className).toBe("badge amber");
    rerender(<Badge tone="critical">UNKNOWN KIND</Badge>);
    expect(container.querySelector(".badge")?.className).toBe("badge red");
    rerender(<Badge tone="ok">READ</Badge>);
    expect(container.querySelector(".badge")?.className).toBe("badge green");
    rerender(<Badge tone="WARNING">UPPER</Badge>);
    expect(container.querySelector(".badge")?.className).toBe("badge amber");
  });

  it("Badge still infers a tone from its own text when none is given", () => {
    const { container } = render(<Badge>CRITICAL</Badge>);
    expect(container.querySelector(".badge")?.className).toBe("badge red");
  });

  it("Bar / ProgressBar / Ring accept percentages without crashing", () => {
    const { container } = render(<><Bar value={42} /><ProgressBar value={73} label="pqc" /><Ring pct={12} label="12%" sub="ready" /></>);
    expect(container.firstChild).toBeTruthy();
    expect(screen.getByText("12%")).toBeInTheDocument();
  });

  it("Table renders headers and rows and reports row selection", () => {
    const onSelect = vi.fn();
    render(<Table head={["Algorithm", "Count"]} rows={[["RSA-2048", 3], ["AES-256", 9]]} clickable onSelect={onSelect} />);
    expect(screen.getByText("Algorithm")).toBeInTheDocument();
    expect(screen.getByText("AES-256")).toBeInTheDocument();
    fireEvent.click(screen.getByText("RSA-2048"));
    expect(onSelect).toHaveBeenCalledWith(0);
  });

  it("Table headers declare column scope and rows are keyboard-activatable (audit 06 a11y)", () => {
    const onSelect = vi.fn();
    render(<Table head={["Algorithm", "Count"]} rows={[["RSA-2048", 3]]} clickable onSelect={onSelect} />);
    expect(screen.getByRole("columnheader", { name: "Algorithm" })).toHaveAttribute("scope", "col");
    const row = screen.getByRole("button", { name: "Select row 1" });
    fireEvent.keyDown(row, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith(0);
    fireEvent.keyDown(row, { key: " " });
    expect(onSelect).toHaveBeenCalledTimes(2);
  });

  it("Tabs switches on click", () => {
    const onChange = vi.fn();
    render(<Tabs tabs={["Overview", "Export"]} active={0} onChange={onChange} />);
    fireEvent.click(screen.getByText("Export"));
    expect(onChange).toHaveBeenCalledWith(1);
  });

  it("Tabs expose the ARIA tab pattern and move with arrow keys (audit 06 a11y)", () => {
    const onChange = vi.fn();
    render(<Tabs tabs={["Overview", "Export", "Raw"]} active={0} onChange={onChange} />);
    const tablist = screen.getByRole("tablist");
    expect(tablist).toBeTruthy();
    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(3);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs[1]).toHaveAttribute("aria-selected", "false");
    expect(tabs[1]).toHaveAttribute("tabIndex", "-1");
    fireEvent.keyDown(tabs[0], { key: "ArrowRight" });
    expect(onChange).toHaveBeenCalledWith(1);
    fireEvent.keyDown(tabs[0], { key: "ArrowLeft" });
    expect(onChange).toHaveBeenCalledWith(2); // wraps around
    fireEvent.keyDown(tabs[0], { key: "End" });
    expect(onChange).toHaveBeenCalledWith(2);
    fireEvent.keyDown(tabs[0], { key: "Home" });
    expect(onChange).toHaveBeenCalledWith(0);
  });

  it("Button fires onClick and respects disabled", () => {
    const onClick = vi.fn();
    render(<><Button onClick={onClick}>Go</Button><Button disabled onClick={onClick}>Nope</Button></>);
    fireEvent.click(screen.getByText("Go"));
    fireEvent.click(screen.getByText("Nope"));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("Drawer closes via its control", () => {
    const onClose = vi.fn();
    render(<Drawer title="Detail" onClose={onClose}><p>inside</p></Drawer>);
    expect(screen.getByText("inside")).toBeInTheDocument();
    const closers = screen.getAllByRole("button");
    fireEvent.click(closers[0]);
    expect(onClose).toHaveBeenCalled();
  });

  it("PageHead renders crumb and title", () => {
    render(<PageHead crumb="Intelligence" title="CBOM" sub="shared BOM views and binary sidecars" />);
    expect(screen.getByText("Intelligence")).toBeInTheDocument();
    expect(screen.getByText("CBOM")).toBeInTheDocument();
  });
});
