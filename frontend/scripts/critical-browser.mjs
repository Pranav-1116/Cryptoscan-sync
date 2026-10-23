#!/usr/bin/env node
/** Local real-Chromium contracts against the BUILT console + stubbed HTTP.
 * Not a bank workstation, real backend, TLS/SSO, sandbox or endurance verdict.
 * Tools live outside product dependencies. See the dated workflow report.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");
assert(process.env.CRYPTOSCAN_BROWSER_TOOLS, "Set CRYPTOSCAN_BROWSER_TOOLS to an external node_modules directory containing playwright-core");
const requireTools = createRequire(path.resolve(process.env.CRYPTOSCAN_BROWSER_TOOLS, "quality-loader.cjs"));
const { chromium: playwright } = requireTools("playwright-core");
let executablePath = process.env.CRYPTOSCAN_BROWSER_EXECUTABLE;
let args = [];
if (!executablePath) {
  const module = requireTools("@sparticuz/chromium");
  const chromium = module.default || module;
  executablePath = await chromium.executablePath();
  args = chromium.args.filter(flag => !["--disable-web-security", "--allow-running-insecure-content", "--disable-site-isolation-trials", "--single-process"].includes(flag));
}
const browser = await playwright.launch({ executablePath, args, headless: true });
const browserVersion = await browser.version();
const base = "http://cryptoscan-quality.invalid";
const results = [];
const errors = [];
const gate = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const json = body => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
const within = async promise => { let timer; try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Browser fixture barrier timed out")), 10000); })]); } finally { clearTimeout(timer); } };
const marker = owner => `synthetic-private-${owner}`;
const inbox = owner => ({ estate_id: owner, as_of: "2026-10-23T00:00:00Z", uncertainty: "UNKNOWN coverage", sections: {
  tasks: { items: [{ id: "synthetic-task", owner: marker(owner), status: "COMPLETED", reported_complete: true, current_condition_verified: false, evidence_freshness: "UNKNOWN" }], has_more: false, next_offset: null },
} });

async function fixture(routePath, work) {
  const context = await browser.newContext({ acceptDownloads: true });
  context.setDefaultTimeout(10000);
  const state = { posts: [], expired: false, hold: null, exportHold: null, exportSeen: gate(), writeSeen: gate(), done: gate() };
  await context.addInitScript(() => { if (!localStorage.getItem("cryptoscan_tenant")) localStorage.setItem("cryptoscan_tenant", "a"); });
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    assert.equal(url.origin, base, "No external network is authorized by this browser exercise");
    const owner = request.headers()["x-tenant-id"] || "platform";
    const p = url.pathname;
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method())) state.posts.push({ path: p, owner, method: request.method() });
    if (p === "/api/v1/auth/me") return route.fulfill(state.expired ? { ...json({ detail: "synthetic expired session" }), status: 401 } : json({ username: "synthetic-browser-user", roles: ["superadmin"] }));
    if (request.method() === "POST" && p.startsWith("/api/v1/assurance/")) {
      state.writeSeen.resolve();
      if (state.hold) await state.hold.promise;
      await route.fulfill(state.validationStatus ? { ...json({ detail: "sensitive-validation-canary" }), status: state.validationStatus } : state.failWrite ? { ...json({ detail: "synthetic dependency failure" }), status: 503 } : json({ kind: "task", id: "synthetic-old-write", receipt: "synthetic-old-write" }));
      state.done.resolve(); return;
    }
    if (p === "/api/v1/auth/audit/export") {
      state.exportSeen.resolve();
      if (state.exportHold) await state.exportHold.promise;
      await route.fulfill({ status: 200, contentType: "application/octet-stream", body: "synthetic-private-export", headers: { "content-disposition": 'attachment; filename="synthetic.jsonl"' } });
      state.done.resolve(); return;
    }
    const api = {
      "/api/v1/assurance/operator-decisions": inbox(owner),
      "/api/v1/assurance/launch/operations": { marker: marker(owner) },
      "/api/v1/onboarding/state": { organization: { name: marker(owner) }, environments: [{ id: "synthetic-environment", name: marker(owner), region: "synthetic-region" }], scope: { entries: [] } },
      "/api/v1/report-snapshots": { snapshots: [] },
      "/api/v1/report-schedules": { schedules: [{ id: "synthetic-schedule", name: marker(owner), frequency: "quarterly" }] },
      "/api/v1/report-templates": { templates: [] },
      "/api/v1/scans": { scans: [{ scan_id: marker(owner), status: "COMPLETED", target_location: "synthetic-source" }], total_count: 1, page: 1, page_size: 20 },
      "/api/v1/findings": { findings: [], total_count: 0, page: 1, page_size: 50 },
      "/api/v1/auth/audit": { events: [], page: 1, page_size: 50 },
      "/api/v1/auth/audit/verify": { status: "OK", checked: 0 },
      "/api/v1/saas/memberships": { memberships: [] },
    };
    if (p in api) return route.fulfill(json(api[p]));
    if (p.startsWith("/api/")) return route.fulfill({ ...json({ detail: "Synthetic unavailable dependency; no fallback fixture" }), status: 503 });
    if (p === "/__storage-helper") return route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Same-origin storage test helper</title>" });
    const candidate = p.startsWith("/assets/") ? path.resolve(root, "." + p) : path.join(root, "index.html");
    assert(candidate.startsWith(root + path.sep));
    const contentType = ({ ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2" })[path.extname(candidate)] || "text/html";
    await route.fulfill({ contentType, body: await readFile(candidate) });
  });
  const page = await context.newPage();
  page.on("pageerror", error => errors.push(String(error)));
  try {
    await page.goto(base + routePath);
    await page.getByText(marker("a"), { exact: false }).first().waitFor();
    const other = await context.newPage();
    await other.goto(base + "/__storage-helper");
    const changeEstate = async () => { await other.evaluate(() => localStorage.setItem("cryptoscan_tenant", "b")); await page.getByText(marker("b"), { exact: false }).first().waitFor(); };
    await work({ page, state, other, changeEstate });
  } finally {
    state.hold?.resolve(); state.exportHold?.resolve();
    await context.close();
  }
}
async function exercise(name, action) {
  const start = Date.now();
  try {
    await action(); results.push({ name, status: "PASS", milliseconds: Date.now() - start });
  } catch (error) {
    results.push({ name, status: "FAIL", milliseconds: Date.now() - start, error: String(error) });
    throw error;
  }
}
async function form(page, name) {
  if (name === "operator") {
    await page.getByLabel("Workflow step").selectOption("create-task");
    await page.getByLabel("Original finding evidence ID").fill("synthetic-finding");
    await page.getByLabel("Accountable owner reference").fill("synthetic-owner");
    await page.getByLabel("Task context").fill("Synthetic browser exercise only");
  } else await page.getByLabel("Typed JSON body").fill("{}");
}
let failure;
try {
  for (const route of ["/operator-decisions", "/launch-readiness", "/evidence"])
    await exercise(`${route}: real cross-window storage clears old estate`, () => fixture(route, async ({ page, changeEstate }) => {
      await changeEstate(); assert.equal(await page.getByText(marker("a"), { exact: false }).count(), 0);
    }));
  for (const name of ["operator", "launch"])
    await exercise(`${name}: same-turn native form submission is single-flight`, () => fixture(name === "operator" ? "/operator-decisions" : "/launch-readiness", async ({ page, state }) => {
      state.hold = gate(); await form(page, name);
      await page.locator("form").evaluate(element => { element.requestSubmit(); element.requestSubmit(); });
      await within(state.writeSeen.promise); assert.equal(state.posts.length, 1);
      state.hold.resolve(); await within(state.done.promise);
    }));
  await exercise("operator: late old-estate write never restores old receipt/draft", () => fixture("/operator-decisions", async ({ page, state, changeEstate }) => {
    state.hold = gate(); await form(page, "operator");
    await page.getByRole("button", { name: "Submit bounded workflow action" }).click();
    await within(state.writeSeen.promise); await changeEstate(); state.hold.resolve(); await within(state.done.promise);
    assert.equal(await page.getByText(/synthetic-old-write/).count(), 0);
    assert.equal(await page.getByLabel("Accountable owner reference").inputValue(), "");
    assert.equal(state.posts.length, 1);
  }));
  await exercise("launch: dependency failure warns of uncertain write, no auto retry", () => fixture("/launch-readiness", async ({ page, state }) => {
    state.failWrite = true; await form(page, "launch");
    await page.getByRole("button", { name: "Submit bounded action" }).click();
    await page.getByRole("alert").filter({ hasText: /outcome not confirmed/ }).waitFor(); assert.equal(state.posts.length, 1);
  }));
  await exercise("session refusal removes private console content", () => fixture("/operator-decisions", async ({ page, state }) => {
    state.expired = true;
    await page.evaluate(() => window.dispatchEvent(new Event("zelinx:auth")));
    await page.waitForURL(base + "/login"); assert.equal(await page.getByText(marker("a"), { exact: false }).count(), 0);
  }));
  await exercise("audit export: estate change cancels pending bytes before browser download", () => fixture("/evidence", async ({ page, state, changeEstate }) => {
    const downloads = []; page.on("download", event => downloads.push(event));
    state.exportHold = gate(); await page.getByRole("tab", { name: "Audit Ledger" }).click();
    await page.getByRole("button", { name: "Export JSONL audit log" }).click();
    await within(state.exportSeen.promise); await changeEstate(); state.exportHold.resolve(); await within(state.done.promise);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(downloads.length, 0);
  }));
  for (const route of ["/organization", "/reports"])
    await exercise(`${route}: shared GET hook revalidates after real cross-window estate change`, () => fixture(route, async ({ page, state, changeEstate }) => {
      await changeEstate();
      assert.equal(await page.getByText(marker("a"), { exact: false }).count(), 0);
      assert.equal(state.posts.length, 0, "Scope revalidation must not perform an action");
    }));
  await exercise("launch: keyboard submission focuses safe validation and retains useful input", () => fixture("/launch-readiness", async ({ page, state }) => {
    await page.getByLabel("Typed JSON body").fill('{"private":"must-not-echo",');
    await page.getByLabel("Exact record ID", { exact: true }).fill("synthetic-kept-id");
    await page.getByLabel("Typed JSON body").focus();
    await page.keyboard.press("Tab");
    assert.equal(await page.getByRole("button", { name: "Submit bounded action" }).evaluate(e => e === document.activeElement), true);
    await page.keyboard.press("Enter");
    const alert = page.getByRole("alert"); await alert.waitFor();
    assert.equal(await alert.evaluate(e => e === document.activeElement), true);
    assert(!await alert.textContent().then(text => text.includes("must-not-echo")));
    assert.equal(await page.getByLabel("Exact record ID", { exact: true }).inputValue(), "synthetic-kept-id");
    assert.equal(await page.getByLabel("Typed JSON body").inputValue(), '{"private":"must-not-echo",');
    assert.equal(state.posts.length, 0);
  }));
  await exercise("launch: native disabled action has visible ID reason; rejected validation never auto-retries", () => fixture("/launch-readiness", async ({ page, state }) => {
    await page.getByLabel("Launch action").selectOption("Acknowledge assigned duty");
    assert.equal(await page.getByRole("button", { name: "Submit bounded action" }).isDisabled(), true);
    await page.getByText("Enter the exact record ID before this action is available.").waitFor({ state: "visible" });
    await page.getByLabel("Exact record ID", { exact: true }).fill("synthetic-assignment");
    await form(page, "launch"); state.validationStatus = 422;
    await page.getByRole("button", { name: "Submit bounded action" }).click();
    const alert = page.getByRole("alert"); await alert.filter({ hasText: /Validation rejected/ }).waitFor();
    assert(!await alert.textContent().then(text => /sensitive-validation-canary|not confirmed/.test(text)));
    assert.equal(await page.getByLabel("Typed JSON body").inputValue(), "{}");
    assert.equal(state.posts.length, 1);
  }));
  for (const scale of [2, 4])
    await exercise(`launch: Arabic RTL with ${scale}x device scale and ${1280 / scale}-CSS-pixel reflow`, () => fixture("/launch-readiness", async ({ page }) => {
      await page.getByRole("button", { name: "ع", exact: true }).click();
      await page.getByLabel("Selected estate").filter({ hasText: "البيئة المحددة" }).waitFor();
      const cdp = await page.context().newCDPSession(page);
      await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280 / scale, height: 960 / scale, deviceScaleFactor: scale, mobile: false });
      assert.equal(await page.locator("html").getAttribute("dir"), "rtl");
      assert.equal(await page.getByLabel("Exact record ID", { exact: true }).getAttribute("dir"), "ltr");
      assert.equal(await page.getByLabel("Typed JSON body").getAttribute("dir"), "ltr");
      await page.getByLabel("Typed JSON body").fill('{"expected_revision":0}');
      await page.getByLabel("Typed JSON body").scrollIntoViewIfNeeded();
      const layout = await page.locator(".launch-readiness").evaluate(e => ({ client: e.clientWidth, scroll: e.scrollWidth }));
      assert(layout.scroll <= layout.client + 1, `Launch form clips at ${scale}x: ${JSON.stringify(layout)}`);
      const box = await page.getByLabel("Typed JSON body").boundingBox();
      assert(box && box.width > 0 && box.width <= 1280 / scale);
      await cdp.detach();
    }));
  assert.deepEqual(errors, []);
} catch (error) { failure = error; }
finally {
  await browser.close();
  console.log(JSON.stringify({ schema: "cryptoscan.local-browser-exercise/1", browser: browserVersion,
    status: failure ? "FAIL" : "PASS", scope: "Built console + stubbed HTTP, synthetic identities; not site acceptance",
    results, page_errors: errors }, null, 2));
}
if (failure) throw failure;
