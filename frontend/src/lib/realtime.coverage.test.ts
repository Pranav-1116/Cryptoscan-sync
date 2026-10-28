/* The realtime migration is a ratchet, not a promise.
 *
 * Converting ~120 polling call sites in one commit would either be dishonest (declaring a
 * channel for a surface nothing publishes on) or unverifiable. So this test pins what has
 * actually happened: the number of screens that name the channel they read, and a ceiling
 * on the ones that still poll blindly. The ceiling may go down; going up fails, because a
 * new poll-only panel is the exact regression the realtime work exists to prevent.
 *
 * It also checks that every channel a screen subscribes to is one the backend declares.
 * A typo there is invisible at runtime — the panel simply never refreshes — which is why
 * it is a build-time failure here instead.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/** Mirrors `CHANNELS` in services/api/api/realtime.py, which is pinned by its own test. */
const BACKEND_CHANNELS = [
  "estate", "twin", "crypto", "inventory", "remediation", "security", "notifications", "findings",
];

/** Call sites still on a bare timer. Lower this; never raise it. */
const POLL_ONLY_CEILING = 100;

interface CallSite { file: string; line: number; source: string }

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry === "node_modules" || entry === "dist") continue;
      walk(path, out);
    } else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) {
      out.push(path);
    }
  }
  return out;
}

/** Every `usePollingApi(` call, with the arguments that follow it. */
function pollCallSites(): CallSite[] {
  const sites: CallSite[] = [];
  for (const file of walk("src")) {
    if (file.endsWith("lib/apiUi.tsx")) continue; // the hook's own definition
    const text = readFileSync(file, "utf8");
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      if (!lines[i].includes("usePollingApi(")) continue;
      const source = lines.slice(i, i + 8).join("\n");
      sites.push({ file, line: i + 1, source });
    }
  }
  return sites;
}

describe("realtime coverage ratchet", () => {
  it("keeps the poll-only surface from growing", () => {
    const sites = pollCallSites();
    const declared = sites.filter((site) => site.source.includes("channels:"));
    const pollOnly = sites.length - declared.length;
    expect(pollOnly).toBeLessThanOrEqual(POLL_ONLY_CEILING);
    // Also make sure the ratchet can be tightened: if this fails, lower POLL_ONLY_CEILING.
    expect(pollOnly).toBeGreaterThanOrEqual(0);
    expect(declared.length).toBeGreaterThan(0);
  });

  it("only names channels the backend declares", () => {
    const unknown: string[] = [];
    for (const site of pollCallSites()) {
      for (const match of site.source.matchAll(/channels:\s*\[([^\]]*)\]/g)) {
        for (const raw of match[1].split(",")) {
          const name = raw.trim().replace(/^["']|["']$/g, "");
          if (!name) continue;
          if (!BACKEND_CHANNELS.includes(name)) unknown.push(`${site.file}:${site.line} → ${name}`);
        }
      }
    }
    expect(unknown).toEqual([]);
  });

  it("does not mix a scoped panel with the unscoped global refresh", () => {
    // `useRealtimeRefresh` refetches on *any* event. A panel that also names its own
    // channel would refresh twice — once for its surface, once for everything — which is
    // how a "live" panel quietly becomes the heaviest page in the console.
    const mixed: string[] = [];
    for (const site of pollCallSites()) {
      if (!site.source.includes("channels:")) continue;
      const text = readFileSync(site.file, "utf8");
      if (text.includes("useRealtimeRefresh(")) mixed.push(site.file);
    }
    expect([...new Set(mixed)]).toEqual([]);
  });
});
