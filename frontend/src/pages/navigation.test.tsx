import React from "react";
import { afterEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { I18nProvider } from "../i18n/I18n";
import { RealtimeProvider } from "../lib/realtime";
import CommandCenter from "./CommandCenter";
import Cbom from "./Cbom";
import DependencyGraph from "./DependencyGraph";
import SearchResults from "./SearchResults";
import SearchOverlay from "../components/Search";

function Location() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname + location.search}</output>;
}

function mount(element: React.ReactElement, route: string) {
  return render(<I18nProvider><RealtimeProvider><MemoryRouter initialEntries={[route]}>
    {element}<Location />
  </MemoryRouter></RealtimeProvider></I18nProvider>);
}

afterEach(cleanup);

describe("primary workspace CTAs", () => {
  it("opens inventory from a dashboard KPI rather than changing only the hash", async () => {
    await act(async () => { mount(<CommandCenter />, "/command-center"); });
    const inventory = screen.getByRole("link", { name: /Crypto assets/ });
    expect(inventory).toHaveAttribute("href", "/cbom");
    fireEvent.click(inventory);
    expect(screen.getByTestId("location")).toHaveTextContent("/cbom");
  });

  it("routes the CBOM dependency CTA to an actual graph workspace", async () => {
    await act(async () => { mount(<Cbom />, "/cbom"); });
    const graph = screen.getByRole("link", { name: "View Dependency Graph" });
    expect(graph).toHaveAttribute("href", "/dependency-graph");
    fireEvent.click(graph);
    expect(screen.getByTestId("location")).toHaveTextContent("/dependency-graph");
  });

  it("routes empty dependency discovery to scanners", async () => {
    await act(async () => { mount(<DependencyGraph />, "/dependency-graph"); });
    const scan = await screen.findByRole("link", { name: "Discover Topology" });
    fireEvent.click(scan);
    expect(screen.getByTestId("location")).toHaveTextContent("/scanners");
  });

  it("opens full search results on Enter with an encoded query", async () => {
    await act(async () => { mount(<SearchOverlay onClose={() => {}} />, "/command-center"); });
    const input = screen.getByRole("textbox", { name: "Search cryptographic assets" });
    fireEvent.change(input, { target: { value: "RSA 2048" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByTestId("location")).toHaveTextContent("/search-results?q=RSA%202048");
  });

  it("reads direct search query links and updates results on repeat search", async () => {
    await act(async () => { mount(<SearchResults />, "/search-results?q=RSA%202048"); });
    await waitFor(() => expect(screen.getByRole("heading", { name: /Results for “RSA 2048”/ })).toBeInTheDocument());
    const input = screen.getByPlaceholderText("search again…");
    fireEvent.change(input, { target: { value: "ML-KEM" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByTestId("location")).toHaveTextContent("/search-results?q=ML-KEM");
    await waitFor(() => expect(screen.getByRole("heading", { name: /Results for “ML-KEM”/ })).toBeInTheDocument());
  });
});
