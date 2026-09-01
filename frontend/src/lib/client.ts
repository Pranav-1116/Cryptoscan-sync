/* API client — probes the real backend through the Vite /api proxy and
   reports liveness to the global header. The console runs on deterministic
   demo data; wiring each page to /api/v1/platform/* is incremental. */

let live: boolean | null = null;
let checked = false;

export async function isBackendLive(): Promise<boolean> {
  if (!checked) {
    checked = true;
    try {
      const resp = await fetch("/api/v1/platform/scope", { signal: AbortSignal.timeout(2500) });
      live = resp.ok;
    } catch {
      live = false;
    }
  }
  return !!live;
}
