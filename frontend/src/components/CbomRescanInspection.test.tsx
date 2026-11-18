import React from "react";
import { act,fireEvent,render,screen,waitFor } from "@testing-library/react";
import { describe,it,expect,vi } from "vitest";
import PrivateScope from "./PrivateScope";
import CbomRescanInspection from "./CbomRescanInspection";
import { mockFetch,offlineFetch } from "../test/setup";
const listing={total:1,page:1,page_size:50,systems:[{id:"system-a",name:"Payments"}]};
const proof={system_id:"system-a",job_id:"job-a",scan_id:"scan-a",source_snapshot_sha256:"a".repeat(64),result:"VERIFIED_SCOPED_RESCAN",
  parsed_files:2,unparsed_files:0,completed_at:"2026-10-24T00:00:00Z",inspected_at:"2026-10-24T00:00:01Z",integrity:{result:"PASS",records:1,content_intact:true,chain_intact:true,manifest_intact:true,hash_format_valid:true},clears_partial_history:false,bank_approved:false,whole_system_coverage_verified:false,absence_proven:false};
const routes=(extra={})=>({"/api/v1/cbom/retained-histories":listing,"/api/v1/cbom/system/system-a/rescan-inspection":proof,...extra});
function mount(){return render(<PrivateScope><CbomRescanInspection /></PrivateScope>);}
async function select(){fireEvent.click(screen.getByRole("button",{name:"Review retained histories"}));fireEvent.click(await screen.findByRole("button",{name:"Inspect rescan for Payments"}));}
async function inspect(){await select();fireEvent.change(screen.getByLabelText("Completed source job ID"),{target:{value:"job-a"}});fireEvent.click(screen.getByRole("button",{name:"Verify scoped rescan evidence"}));}
describe("Retained-source rescan inspection",()=>{
 it("reads only on demand and never presents scoped verification as clean coverage",async()=>{
  const fetcher=mockFetch(routes());mount();expect(fetcher).not.toHaveBeenCalled();await inspect();
  await screen.findByText("Committed source evidence verified for this scoped rescan.");
  expect(screen.getByTitle(/Partial history remains. No clean posture grade/)).toBeTruthy();
  expect(fetcher.mock.calls.every(([,init])=>!init?.method||init.method==="GET")).toBe(true);
  expect(fetcher.mock.calls.find(([url])=>String(url).includes("job_id=job-a"))).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Completed source job ID"),{target:{value:"job-b"}});
  expect(screen.queryByText("Committed source evidence verified for this scoped rescan.")).toBeNull();
 });
 it("clears the previous proof on refresh and does not silently repeat inspection",async()=>{
  const fetcher=mockFetch(routes());mount();await inspect();await screen.findByText("Committed source evidence verified for this scoped rescan.");
  fireEvent.click(screen.getByRole("button",{name:"Review retained histories"}));await screen.findByRole("button",{name:"Inspect rescan for Payments"});
  expect(screen.queryByText("Committed source evidence verified for this scoped rescan.")).toBeNull();
  expect(fetcher.mock.calls.filter(([url])=>String(url).includes("rescan-inspection"))).toHaveLength(1);
 });
 it("does not call an empty committed scope proof of absence",async()=>{
  mockFetch(routes({"/api/v1/cbom/system/system-a/rescan-inspection":{...proof,result:"VERIFIED_EMPTY_SCOPED_RESCAN",integrity:{...proof.integrity,result:"EMPTY",records:0}}}));
  mount();await inspect();expect(await screen.findByText(/Verified empty committed scope — absence is NOT proven/)).toBeTruthy();
 });
 it("handles blocked or unavailable proof without inventing a clearance",async()=>{
  mockFetch(routes({"/api/v1/cbom/system/system-a/rescan-inspection":()=>new Response("{}",{status:409})}));
  mount();await inspect();await screen.findByText(/No verified rescan or clearance assumed/);
  expect(screen.queryByText("Committed source evidence verified for this scoped rescan.")).toBeNull();
 });
 it("discards a pending inspection when the private estate changes",async()=>{
  let finish!:(value:unknown)=>void;
  mockFetch(routes({"/api/v1/cbom/system/system-a/rescan-inspection":()=>new Promise(resolve=>{finish=resolve;})}));
  mount();await inspect();await waitFor(()=>expect(finish).toBeTypeOf("function"));
  act(()=>{window.dispatchEvent(new StorageEvent("storage",{key:"cryptoscan_tenant",newValue:"other"}));});
  await screen.findByTitle(/Private evidence and unsubmitted drafts were cleared/);
  await act(async()=>{finish(proof);});expect(screen.queryByText("Committed source evidence verified for this scoped rescan.")).toBeNull();
 });
 it.each([
  { ...proof, result: "UNVERIFIABLE" }, { ...proof, bank_approved: true },
  { ...proof, job_id: "wrong-job" }, { ...proof, integrity: { ...proof.integrity, manifest_intact: false } },
 ])("rejects an unverified/mismatched live-shaped 200 response",async broken=>{
  mockFetch(routes({"/api/v1/cbom/system/system-a/rescan-inspection":broken}));mount();await inspect();
  await screen.findByText(/No verified rescan or clearance assumed/);
  expect(screen.queryByText("Committed source evidence verified for this scoped rescan.")).toBeNull();
 });
 it("does not substitute sample data when inventory is offline",async()=>{
  offlineFetch();mount();fireEvent.click(screen.getByRole("button",{name:"Review retained histories"}));
  expect(await screen.findByText(/Retained histories unavailable/)).toBeTruthy();expect(screen.queryByLabelText("Completed source job ID")).toBeNull();
 });
});
