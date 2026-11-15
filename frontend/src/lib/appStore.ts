/* appStore — application state that outlives a page (Zustand).
 *
 * Server state lives in TanStack Query (serverState.ts); this store holds
 * only CLIENT state the console shares across components: cross-page
 * filters, the selected asset, dependency-graph expansion (level-of-detail)
 * and live scan progress mirrored from the SSE stream.
 *
 * The graph entries exist for the bank rule: never render the entire estate
 * graph. `graphExpansion` records which nodes the operator opened and
 * `graphDepth` the current level-of-detail — components load a bounded
 * subgraph and expand progressively, never the full estate.
 */

import { create } from "zustand";

export interface ScanProgress {
  stage: string;
  status: string; // RUNNING | COMPLETED | FAILED
  findings?: number;
  ts?: string;
}

export interface ConsoleState {
  /** Cross-page filter memory, e.g. { assetsEnv: "prod", findingsClass: "..." }. */
  filters: Record<string, string>;
  selectedAssetId: string | null;
  /** Expanded dependency-graph node ids (progressive disclosure). */
  graphExpansion: Record<string, true>;
  /** Level-of-detail depth for the dependency graph (1 = immediate neighbours). */
  graphDepth: number;
  /** scan_id → last known pipeline progress (fed by the SSE stream). */
  scans: Record<string, ScanProgress>;

  setFilter: (name: string, value: string) => void;
  clearFilters: () => void;
  selectAsset: (id: string | null) => void;
  expandNode: (id: string, open: boolean) => void;
  resetGraph: () => void;
  setGraphDepth: (depth: number) => void;
  ingestScanEvent: (scanId: string, progress: ScanProgress) => void;
}

export const useConsoleStore = create<ConsoleState>()((set) => ({
  filters: {},
  selectedAssetId: null,
  graphExpansion: {},
  graphDepth: 1,
  scans: {},

  setFilter: (name, value) =>
    set((s) => ({ filters: { ...s.filters, [name]: value } })),
  clearFilters: () => set({ filters: {} }),
  selectAsset: (id) => set({ selectedAssetId: id }),
  expandNode: (id, open) =>
    set((s) => {
      const graphExpansion = { ...s.graphExpansion };
      if (open) graphExpansion[id] = true;
      else delete graphExpansion[id];
      return { graphExpansion };
    }),
  resetGraph: () => set({ graphExpansion: {}, graphDepth: 1 }),
  setGraphDepth: (depth) => set({ graphDepth: Math.max(1, Math.min(depth, 3)) }),
  ingestScanEvent: (scanId, progress) =>
    set((s) => ({ scans: { ...s.scans, [scanId]: progress } })),
}));
