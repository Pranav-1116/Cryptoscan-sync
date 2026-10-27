import React from "react";
import { describe,expect,it,vi } from "vitest";
import { fireEvent,render,screen } from "@testing-library/react";
import CryptoAssurance from "./CryptoAssurance";
import * as api from "../lib/api";
vi.mock("../lib/api",()=>({apiTlsAudit:vi.fn(),apiCtMonitor:vi.fn(),apiExpiryAlerts:vi.fn(),apiHsmCheck:vi.fn(),apiTrustStore:vi.fn(),apiPqcDowngrade:vi.fn(),apiCodeRuleScan:vi.fn()}));
vi.mock("../components/HostQualification",()=>({default:()=>null}));
describe("Legacy HSM results are provider claims, not operation proof",()=>{
 it("labels a positive submitted sign receipt without claiming in-boundary use",async()=>{
  vi.mocked(api.apiHsmCheck).mockResolvedValue({source:"live",ok:true,data:{summary:{hardware_backed:1,software_keys:0,connectivity_failures:0},results:[{key_ref:"fixture",provider:"aws_kms",key_residence:"HSM",connectivity:"OK",sign_challenge:"OK",issues:[]}]}} as never);
  render(<CryptoAssurance/>);fireEvent.click(screen.getByText("HSM / KMS"));
  expect(screen.getByText(/a sign receipt is not signature verification/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button",{name:"Inspect reported residence"}));
  expect(await screen.findByText("1 provider-reported hardware")).toBeInTheDocument();
  expect(screen.getByText("unverified sign receipt")).toBeInTheDocument();
  expect(screen.queryByText(/sign challenge proves in-boundary use/)).not.toBeInTheDocument();
 });
});
