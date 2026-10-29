/* DevSecOps gates — the drawing contract.
 *
 * A gate result is a set of counts with severities, so it is drawn as cells and
 * a composition of the findings that actually matched. The previous arc swept
 * to `1 - findings/(findings+3)`, a shape no server ever reported; these tests
 * pin that the numbers on the screen are the server's own.
 */
import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import DevSecOps from "./DevSecOps";

const draw = () => render(<MemoryRouter><DevSecOps /></MemoryRouter>);
const containerResult = {
  vulnerabilities: 2,
  fixable: 1,
  worst_severity: "CRITICAL",
  dockerfile_findings: [{ code: "LATEST_TAG", severity: "HIGH", detail: "image uses :latest" }],
  cve_matches: [
    { cve_id: "CVE-2024-0001", severity: "CRITICAL", package: "openssl", version: "3.0.9", ecosystem: "debian", fixed_version: "3.0.11" },
    { cve_id: "CVE-2024-0002", severity: "LOW", package: "zlib", version: "1.2", ecosystem: "debian" },
  ],
};

describe("DevSecOps visualization", () => {
  it("draws a container gate as its own counts and a real severity composition", async () => {
    mockFetch({ "/api/v1/devsecops/container-scan": containerResult });
    draw();
    fireEvent.click(await screen.findByText("Scan image"));
    expect(await screen.findByText("CVEs matched")).toBeInTheDocument();
    expect(screen.getByText("worst severity")).toBeInTheDocument();
    expect(screen.getByText("Dockerfile issues")).toBeInTheDocument();
    // the composition is labelled with the findings it is made of
    expect(screen.getAllByText("critical").length).toBeGreaterThan(0);
    expect(screen.getByText(/Segment width is the count of matched CVEs/)).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-0001")).toBeInTheDocument();
  });

  it("leaves an unmatched gate drawn as a bounded absence, not a clean estate", async () => {
    mockFetch({ "/api/v1/devsecops/container-scan": { vulnerabilities: 0, fixable: 0, worst_severity: "NONE", dockerfile_findings: [], cve_matches: [] } });
    draw();
    fireEvent.click(await screen.findByText("Scan image"));
    expect(await screen.findByText("No finding in this input")).toBeInTheDocument();
    expect(screen.getAllByText(/not an unobserved clean estate/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/clean image/)).not.toBeInTheDocument();
  });

  it("draws the Kubernetes gate from the manifests it actually parsed", async () => {
    mockFetch({ "/api/v1/devsecops/k8s-manifest-scan": { total_findings: 2, manifests_scanned: 1, findings: [
      { code: "PRIVILEGED_CONTAINER", severity: "CRITICAL", location: "spec.containers[0].securityContext", detail: "privileged: true" },
      { code: "HOST_PID", severity: "HIGH", location: "spec", detail: "hostPID: true" },
    ] } });
    draw();
    fireEvent.click(await screen.findByText("K8s manifests"));
    fireEvent.click(await screen.findByText("Scan manifests"));
    expect(await screen.findByText("manifests scanned")).toBeInTheDocument();
    expect(screen.getByText(/Misconfig findings by severity across the manifests supplied/)).toBeInTheDocument();
    expect(screen.getByText("PRIVILEGED_CONTAINER")).toBeInTheDocument();
  });
});
