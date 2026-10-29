import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import TrafficControlReview from "./TrafficControlReview";

const ID = "11111111-1111-1111-1111-111111111111";
let fetcher: ReturnType<typeof vi.fn>;
beforeEach(() => {
  localStorage.clear(); localStorage.setItem("cryptoscan_tenant", "a"); localStorage.setItem("zelinx_token", "synthetic-test-token");
  fetcher = vi.fn(async () => new Response('{"recorded_checks_complete":true,"host_enforcement_authorized":false}'));
  vi.stubGlobal("fetch", fetcher);
});
afterEach(() => vi.unstubAllGlobals());

function select(action: string) {
  fireEvent.change(screen.getByLabelText("Operation"), { target: { value: action } });
  fireEvent.change(screen.getByLabelText("Record UUID for selected operation"), { target: { value: ID } });
}

it("does not execute/poll anything on mount and explains the native limitation", () => {
  render(<TrafficControlReview />);
  expect(fetcher).not.toHaveBeenCalled();
  expect(screen.getByText(/No real-host apply/)).toBeInTheDocument();
  expect(screen.getByText(/missing kernel qdisc is a blocked result/)).toBeInTheDocument();
});

it("retains exact uint64 JSON on import without parse and reserialization", async () => {
  render(<TrafficControlReview />); select("import");
  const raw = '{"network_namespace_inode":18446744073709551615}';
  fireEvent.change(screen.getByLabelText(/Original preflight JSON/), { target: { value: raw } });
  fireEvent.change(screen.getByLabelText(/Expected proposal/), { target: { value: "a".repeat(64) } });
  fireEvent.click(screen.getByRole("button", { name: "Run selected step" }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  expect(fetcher.mock.calls[0][1].body).toContain(raw);
  expect(fetcher.mock.calls[0][0]).toContain(`/preflight-requests/${ID}/captures`);
});

it("failed download is never offered as a usable packet", async () => {
  fetcher.mockResolvedValue(new Response('{"detail":"Separate-human approval required"}', { status: 409 }));
  render(<TrafficControlReview />); select("packet");
  fireEvent.click(screen.getByRole("button", { name: "Run selected step" }));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Refused (409):"));
  expect(screen.queryByRole("button", { name: "Save original JSON" })).not.toBeInTheDocument();
});

it("clears private data and rejects a late response after tenant switch", async () => {
  let finish!: (r: Response) => void;
  fetcher.mockImplementation(() => new Promise<Response>((resolve) => { finish = resolve; }));
  render(<TrafficControlReview />); select("inspect");
  fireEvent.click(screen.getByRole("button", { name: "Run selected step" }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  act(() => { localStorage.setItem("cryptoscan_tenant", "b"); window.dispatchEvent(new Event("zelinx:tenant")); });
  await act(async () => finish(new Response('{"secret":"old-estate"}')));
  expect(screen.queryByText(/old-estate/)).not.toBeInTheDocument();
});
