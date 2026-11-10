import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Donut, FlowStrip, HBars, Matrix, StackedBar, StepRail } from "./viz";

describe("composition primitives", () => {
  it("Donut draws every segment and its label — an empty set is empty, never 0%", () => {
    const { rerender } = render(
      <Donut
        segments={[
          { label: "weak", value: 3, tone: "red" },
          { label: "strong", value: 5, tone: "green" },
        ]}
        centerLabel={8}
        centerSub="findings"
      />,
    );
    expect(screen.getByText("weak")).toBeInTheDocument();
    expect(screen.getByText("strong")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "distribution" })).toBeInTheDocument();

    rerender(<Donut segments={[{ label: "none", value: 0 }]} />);
    expect(screen.getByText(/no counts to split/)).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: "distribution" })).not.toBeInTheDocument();
    // the picture survives the empty set: a labelled placeholder ring,
    // never a filled ring of zeroes and never bare text
    expect(
      screen.getByRole("img", { name: "distribution placeholder" }),
    ).toBeInTheDocument();
  });

  it("empty HBars and StackedBar still draw their shape as ghosts", () => {
    const { rerender } = render(
      <HBars rows={[]} emptyTitle="no rows" emptyNote="unknown, never zero" />,
    );
    // three ghost tracks (— / dashed bar / ?) above the honest note
    expect(screen.getAllByText("—").length).toBe(3);
    expect(screen.getByText("no rows")).toBeInTheDocument();
    expect(screen.getByText(/unknown, never zero/)).toBeInTheDocument();

    rerender(
      <StackedBar
        segments={[{ key: "a", label: "a", value: 0 }]}
        note="nothing composed"
      />,
    );
    expect(screen.getByText("Nothing to compose")).toBeInTheDocument();
    expect(screen.getByText(/nothing composed/)).toBeInTheDocument();
  });

  it("FlowStrip names every stage's state — an unknown stage is dashed, never silent", () => {
    render(
      <FlowStrip
        label="pipeline"
        stages={[
          { label: "ingest", state: "done" },
          { label: "classify", state: "unknown", note: "no classifier ran here" },
          { label: "detect", state: "failed" },
        ]}
      />,
    );
    const group = screen.getByRole("group", { name: "pipeline" });
    expect(group).toHaveTextContent("done");
    expect(group).toHaveTextContent("unknown");
    expect(group).toHaveTextContent("failed");
    // the unknown stage carries its own explanation, as its tooltip
    expect(
      screen.getByTitle("no classifier ran here"),
    ).toBeInTheDocument();
  });

  it("StepRail marks states and reports selection through onSelect", () => {
    const onSelect = vi.fn();
    render(
      <StepRail
        label="walkthrough"
        selected={2}
        onSelect={onSelect}
        steps={[
          { n: 1, title: "Overview", state: "done" },
          { n: 2, title: "Assets", state: "active" },
          { n: 3, title: "Graph", state: "pending" },
        ]}
      />,
    );
    expect(screen.getByText("Overview")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Graph"));
    expect(onSelect).toHaveBeenCalledWith(3);
  });

  it("Matrix draws an explicit empty at an intersection it was not given", () => {
    render(
      <Matrix
        label="grid"
        rowLabel="BOM"
        colLabel="state"
        rows={["SBOM", "CBOM"]}
        cols={["added", "removed"]}
        cell={(row, col) =>
          row === "SBOM" && col === "added" ? { tone: "green", text: "2" } : null
        }
      />,
    );
    expect(screen.getByText("2")).toBeInTheDocument();
    // the null intersections render the explicit dot, never a filled cell
    expect(
      screen.getAllByTitle("no data at this intersection — never assumed").length,
    ).toBe(3);
  });
});
