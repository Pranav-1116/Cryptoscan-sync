import React from "react";
import { PageHead } from "../components/ui.jsx";
import IntelligenceWorkbench from "../intelligence/IntelligenceWorkbench";

export default function Intelligence() {
  return (
    <>
      <PageHead
        crumb="intelligence / workbench"
        title="Intelligence workbench"
        sub="Roadmap models over live estate rows — evidence-linked findings, five risk dimensions, PQC claim stages, snapshot simulations"
      />
      <IntelligenceWorkbench />
    </>
  );
}
