import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import PrivateScope from "./PrivateScope";
import HostEvidencePanel from "./HostEvidencePanel";
import { mockFetch } from "../test/setup";
import fact from "../test/fixtures/tlsKeyShareFact.json";
const id="a".repeat(36),sha="b".repeat(64),P="/api/v1/host-evidence/approvals";
function detail(value: unknown=fact) {
  return {approval_id:id,scan_id:"scan-a",system_id:"system-a",snapshot_sha256:sha,evidence_count:1,
    source_basis:"IMPORTED",runtime_use:"UNKNOWN",pqc_assessment:"UNKNOWN",policy_result:"NOT_EVALUATED",whole_host_coverage_verified:false,host_identity_attested:false,
    integrity:{result:"PASS",content_intact:true,chain_intact:true,manifest_intact:true,hash_format_valid:true},
    snapshot:{manifest:{host_id:"fixture-tls",environment:"test"},finished_at:"2026-10-25T00:00:00Z",
      receipts:[{input_id:"session",status:"PARSED",reason:"METADATA_ONLY",facts:[value]}]}};
}
function mount(){render(<PrivateScope><HostEvidencePanel /></PrivateScope>);fireEvent.change(screen.getByLabelText("Host approval ID"),{target:{value:id}});fireEvent.click(screen.getByRole("button",{name:"Inspect host evidence"}));}
describe("TLS 1.3 public selected group, not PQC/HSM readiness",()=>{
  it("shows wire-selected group separately from certificate key and no app/HSM claim",async()=>{
    const fetcher=mockFetch({[`${P}/${id}/snapshot`]:detail()});mount();
    await screen.findByText(/final TLS 1.3 ServerHello selected group/);
    expect(screen.getByText(/PQC readiness, application\/HSM use UNKNOWN/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([{selected_group_id:23},{key_exchange_group:"RSA"},{group_classification:"REGISTERED_HYBRID_GROUP_SELECTED"},
    {pqc_readiness_verified:true},{pqc_implementation_verified:true},{all_groups_tested:true},{application_identity_verified:true},
    {runtime_use:"OBSERVED"},{pqc_assessment:"READY"},{group_classification_basis:"AI_GUESS"},{server_hello_hex:"00"},
    {server_hello_sha256:"bad"},{arbitrary:"promoted"},
  ])("rejects false group or readiness promotion",async patch=>{
    mockFetch({[`${P}/${id}/snapshot`]:detail({...fact,...patch})});mount();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByText(/final TLS 1.3 ServerHello selected group/)).toBeNull();
  });
  it.each(["good","wrong-snapshot"])("fences key-share export: %s",async mode=>{
    mockFetch({[`${P}/${id}/snapshot`]:detail(),[`${P}/${id}/tls-session/cyclonedx-1.6`]:{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{properties:[
      {name:"cryptoscan:profile",value:"PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN"},
      {name:"cryptoscan:snapshot_sha256",value:mode==="good"?sha:"c".repeat(64)}]}}});
    const create=vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:fixture"),revoke=vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{}),click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
    mount();await screen.findByText(/final TLS 1.3 ServerHello selected group/);
    await act(async()=>{fireEvent.click(screen.getByRole("button",{name:/Download CycloneDX 1.6 observed TLS session/}));});
    expect(create).toHaveBeenCalledTimes(mode==="good"?1:0);create.mockRestore();revoke.mockRestore();click.mockRestore();
  });
});
