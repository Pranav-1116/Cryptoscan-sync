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

  it("Tabs switches on click", () => {
    const onChange = vi.fn();
    render(<Tabs tabs={["Overview", "Export"]} active={0} onChange={onChange} />);
    fireEvent.click(screen.getByText("Export"));
    expect(onChange).toHaveBeenCalledWith(1);
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
