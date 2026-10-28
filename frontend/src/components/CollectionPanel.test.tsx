import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import CollectionPanel from "./CollectionPanel";
import { mockFetch } from "../test/setup";

/* The three claims this panel makes, each testable:

* a collector that is not production-qualified is labelled as such rather than
  shown as available;
* an empty target/job list says "nothing registered", never "nothing found";
* an unreachable API is an error, not an empty estate. */

const COLLECTORS = "/api/v1/collection/collectors";
const TARGETS = "/api/v1/collection/targets";
const JOBS = "/api/v1/collection/jobs";

function catalog(qualified = false) {
  return {
    schema_version: "cryptoscan.collector-catalog/v1",
    collectors: [
      {
        id: "offline-linux/v1",
        method: "offline_host",
        state: "DEVELOPMENT_OFFLINE_ONLY",
        production_execution_qualified: qualified,
        server_execution: false,
        capabilities: { SBOM: "PACKAGE_BINARY_MAPPED_PATH_METADATA_NOT_OPERATIONAL_USE" },
      },
    ],
  };
}

it("labels a collector that is not production-qualified instead of showing it as available", async () => {
  mockFetch({
    [COLLECTORS]: catalog(false),
    [TARGETS]: { items: [], has_more: false },
    [JOBS]: { items: [], has_more: false },
  });
  render(<CollectionPanel />);
  expect(await screen.findByText("offline-linux/v1")).toBeInTheDocument();
  expect(screen.getByText("NOT production-qualified")).toBeInTheDocument();
  expect(screen.getByText("no server execution")).toBeInTheDocument();
  expect(screen.queryByText("production-qualified")).not.toBeInTheDocument();
});

it("says nothing is registered rather than implying nothing was found", async () => {
  mockFetch({
    [COLLECTORS]: catalog(true),
    [TARGETS]: { items: [], has_more: false },
    [JOBS]: { items: [], has_more: false },
  });
  render(<CollectionPanel />);
  expect(await screen.findByText(/no collection target is registered/)).toHaveTextContent(
    "authorisation gap",
  );
  expect(screen.getByText(/no collection job exists/)).toHaveTextContent("Nothing has been asked");
  expect(screen.getByText("production-qualified")).toBeInTheDocument();
});

it("treats an unreachable API as an error, not an empty collection estate", async () => {
  globalThis.fetch = (() => Promise.reject(new Error("offline"))) as unknown as typeof fetch;
  render(<CollectionPanel />);
  await waitFor(() =>
    expect(screen.getByText(/collection API is unavailable/)).toHaveTextContent(
      "not 'no targets and no jobs'",
    ),
  );
});
