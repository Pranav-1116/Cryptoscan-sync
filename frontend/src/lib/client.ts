/* API client — probes the real backend through the Vite /api proxy and
   reports liveness to the global header. There is no offline/cached
   dataset: when the backend is down the console shows zeros/empty. */

let live: boolean | null = null;
let checked = false;

import { tenantFetch } from "./api.js";

export async function isBackendLive(): Promise<boolean> {
  if (!checked) {
    checked = true;
    try {
      const resp = await tenantFetch("/api/v1/platform/scope", { signal: AbortSignal.timeout(2500) });
      live = resp.ok;
    } catch {
      live = false;
    }
  }
  return !!live;
}
