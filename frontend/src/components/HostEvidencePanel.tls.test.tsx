import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import PrivateScope from "./PrivateScope";
import HostEvidencePanel from "./HostEvidencePanel";
import { mockFetch } from "../test/setup";
import fact from "../test/fixtures/tlsSessionFact.json";
const id = "a".repeat(36), sha = "b".repeat(64), P = "/api/v1/host-evidence/approvals";
function detail(value: unknown = fact) {
  return {approval_id:id, scan_id:"scan-a",system_id:"system-a",snapshot_sha256:sha,evidence_count:1,
    source_basis:"IMPORTED",runtime_use:"UNKNOWN",pqc_assessment:"UNKNOWN",policy_result:"NOT_EVALUATED",
    whole_host_coverage_verified:false,host_identity_attested:false,
    integrity:{result:"PASS",content_intact:true,chain_intact:true,manifest_intact:true,hash_format_valid:true},
    snapshot:{manifest:{host_id:"fixture-tls",environment:"test"},finished_at:"2026-10-25T00:00:00Z",
      receipts:[{input_id:"session",status:"PARSED",reason:"OK",facts:[value]}]}};
}
function mount() {
  render(<PrivateScope><HostEvidencePanel /></PrivateScope>);
  fireEvent.change(screen.getByLabelText("Host approval ID"),{target:{value:id}});
  fireEvent.click(screen.getByRole("button",{name:"Inspect host evidence"}));
}
describe("Stored approved TLS session, not a discovery console",()=>{
  it("shows one pinned session with unknown application/group and trust limitations, without probing",async()=>{
    const fetcher=mockFetch({[`${P}/${id}/snapshot`]:detail()});mount();
    await screen.findByText(/one pinned TLSv1.3 session/);
    expect(screen.getByText(/CA\/hostname\/revocation not validated/)).toBeTruthy();
    expect(screen.getByText(/Active TLS: operator-run only · production BLOCKED/)).toBeTruthy();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it.each([{hostname_validated:true},{certificate_chain_validated:true},{application_identity_verified:true},
    {all_tls_versions_tested:true},{application_data_sent:true},{negotiated_session_observed:false},
    {runtime_use:"OBSERVED"},{key_exchange_group:"X25519"},{cipher_suite:"RSA-AES128-SHA"},
    {authorized_operation:"READ_APPROVED_METADATA"},{reviewed_target_sha256:"bad"},{peer_der_bytes:65537},
    {address:"224.0.0.1"},{sni:"*.example"},{arbitrary:"promoted"},
    {certificate:{...fact.certificate,private_key:"not-allowed"}},{certificate:{...fact.certificate,key_size:null}},
  ])("rejects malformed or promoted session fields",async patch=>{
    mockFetch({[`${P}/${id}/snapshot`]:detail({...fact,...patch})});mount();
    await screen.findByText(/No verified receipt or security verdict assumed/);
    expect(screen.queryByRole("button",{name:/Download CycloneDX 1.6 observed TLS session/})).toBeNull();
  });
  it.each(["good","wrong-profile","wrong-snapshot","offline"])("fences stored export: %s",async mode=>{
    const result={bomFormat:"CycloneDX",specVersion:"1.6",metadata:{properties:[
      {name:"cryptoscan:profile",value:mode==="wrong-profile"?"CAPABILITY_SCAN":"PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN"},
      {name:"cryptoscan:snapshot_sha256",value:mode==="wrong-snapshot"?"c".repeat(64):sha}]}};
    mockFetch({[`${P}/${id}/snapshot`]:detail(),[`${P}/${id}/tls-session/cyclonedx-1.6`]:
      mode==="offline"?{status:503,body:{detail:"unavailable"}}:result});
    const create=vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:fixture"),revoke=vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});
    const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});
    mount();await screen.findByText(/one pinned TLSv1.3 session/);
    await act(async()=>{fireEvent.click(screen.getByRole("button",{name:/Download CycloneDX 1.6 observed TLS session/}));});
    expect(create).toHaveBeenCalledTimes(mode==="good"?1:0);
    if(mode==="good")expect(click).toHaveBeenCalledTimes(1);
    create.mockRestore();revoke.mockRestore();click.mockRestore();
  });
});
