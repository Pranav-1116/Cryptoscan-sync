import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PrivateScope from "./PrivateScope";
import HostEvidencePanel from "./HostEvidencePanel";
import { mockFetch } from "../test/setup";
import fact from "../test/fixtures/tlsHybridFact.json";
const id="a".repeat(36),sha="b".repeat(64),P="/api/v1/host-evidence/approvals";
function detail(value:unknown=fact) {
  return {approval_id:id,scan_id:"scan-a",system_id:"system-a",snapshot_sha256:sha,evidence_count:1,
    source_basis:"IMPORTED",runtime_use:"UNKNOWN",pqc_assessment:"UNKNOWN",policy_result:"NOT_EVALUATED",whole_host_coverage_verified:false,host_identity_attested:false,
    integrity:{result:"PASS",content_intact:true,chain_intact:true,manifest_intact:true,hash_format_valid:true},
    snapshot:{manifest:{host_id:"fixture-hybrid",environment:"test"},finished_at:"2026-10-25T00:00:00Z",
      receipts:[{input_id:"hybrid",status:"PARSED",reason:"METADATA_ONLY",facts:[value]}]}};
}
function mount(){render(<PrivateScope><HostEvidencePanel/></PrivateScope>);fireEvent.change(screen.getByLabelText("Host approval ID"),{target:{value:id}});fireEvent.click(screen.getByRole("button",{name:"Inspect host evidence"}));}
describe("Actual hybrid profile stays bounded",()=>{
 it("renders completed hybrid session without claiming HSM, app or readiness",async()=>{mockFetch({[`${P}/${id}/snapshot`]:detail()});mount();expect(await screen.findByText(/completed hybrid TLS X25519MLKEM768 session/)).toHaveTextContent("provider version self-reported; not HSM/application or PQC readiness proof");});
 it.each([{hybrid_session_completed:false},{tls_provider:"unreviewed"},{openssl_version:"OpenSSL 3.0.20 1 Jan 2026"},{provider_identity_basis:"MEASURED_EXECUTION"},{selected_group_id:29},{pqc_readiness_verified:true},{application_identity_verified:true},{provider_credential:"must-not-render"}])("refuses malformed or promoted hybrid fields %j",async(change)=>{mockFetch({[`${P}/${id}/snapshot`]:detail({...fact,...change})});mount();await screen.findByText(/No verified receipt or security verdict assumed/);expect(screen.queryByText(/completed hybrid TLS/)).not.toBeInTheDocument();expect(screen.queryByText(/must-not-render/)).not.toBeInTheDocument();});
});
