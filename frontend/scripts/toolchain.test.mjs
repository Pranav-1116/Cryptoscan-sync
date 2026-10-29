import assert from "node:assert/strict";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { request } from "node:http";
import { createServer } from "vite";

const root = new URL("../", import.meta.url);
const require = createRequire(import.meta.url);
const json = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

async function configuration() {
  const saved = ["VITE_DEV_HOST", "VITE_DEV_ALLOWED_HOSTS"].map((key) => [key, process.env[key]]);
  for (const [key] of saved) delete process.env[key];
  try {
    return (await import(new URL(`vite.config.js?contract=${randomUUID()}`, root))).default;
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
}

test("supported engines, exact compatible toolchain and mandatory frozen installs", async () => {
  const pkg = await json("package.json");
  const lock = await json("package-lock.json");
  for (const name of ["vite", "vitest", "@vitest/coverage-v8", "@vitejs/plugin-react"]) {
    assert.match(pkg.devDependencies[name], /^\d+\.\d+\.\d+$/);
    assert.equal(lock.packages[`node_modules/${name}`].version, pkg.devDependencies[name]);
  }
  assert.equal(pkg.devDependencies.vitest, pkg.devDependencies["@vitest/coverage-v8"]);
  assert.equal(pkg.engines.node, "^22.12.0 || ^24.0.0 || >=26.0.0");
  const npmrc = await readFile(new URL(".npmrc", root), "utf8");
  assert.match(npmrc, /^engine-strict=true$/m);
  assert.match(npmrc, /^save-exact=true$/m);
  const docker = await readFile(new URL("../.docker/frontend/Dockerfile", root), "utf8");
  assert.match(docker, /^COPY frontend\/package\.json frontend\/package-lock\.json frontend\/\.npmrc \.\/$/m);
  assert.match(docker, /RUN npm ci --no-audit --no-fund/);
  assert.doesNotMatch(docker, /RUN npm install/);
});

test("loopback defaults, named-host protection and same-origin API proxy remain intact", async () => {
  const config = await configuration();
  assert.equal(config.server.host, "127.0.0.1");
  assert.notEqual(config.server.allowedHosts, true);
  assert.equal(config.server.strictPort, true);
  assert.deepEqual(config.server.watch.ignored, ["**/coverage/**", "**/dist/**"]);
  assert.equal(config.server.proxy["/api"].target, "http://127.0.0.1:8010");
  assert.equal(config.server.proxy["/api"].changeOrigin, true);
});

test("prior browser targets and cross-platform Rolldown package boundaries stay explicit", async () => {
  const config = await configuration();
  assert.deepEqual(config.build.target, ["es2020", "edge88", "firefox78", "chrome87", "safari14"]);
  assert.equal(config.build.rollupOptions, undefined);
  const groups = config.build.rolldownOptions.output.codeSplitting.groups;
  for (const [name, path] of [
    ["vendor-react", "react/index.js"], ["vendor-react", "react-router/dist/index.js"],
    ["vendor-motion", "motion-dom/dist/index.js"], ["vendor-motion", "@formkit/auto-animate/index.js"],
    ["vendor-icons", "@phosphor-icons/react/dist/index.js"],
  ]) {
    const group = groups.find((group) => group.name === name);
    assert.ok(group.test.test(`/project/node_modules/${path}`));
    assert.ok(group.test.test(`C:\\project\\node_modules\\${path.replaceAll("/", "\\")}`));
    assert.ok(!group.test.test("/project/src/App.tsx"));
    assert.ok(!group.test.test("/project/node_modules/react-unrelated/index.js"));
  }
});

test("the complete stylesheet passes the strict production CSS parser", async () => {
  const viteRequire = createRequire(require.resolve("vite/package.json"));
  const { transform } = viteRequire("lightningcss");
  const result = transform({ filename: "global.css", code: await readFile(new URL("src/styles/global.css", root)), minify: true });
  assert.ok(result.code.length > 0);
});

test("real dev HTTP serves approved hosts, blocks rebinding and denies env files", { timeout: 15000 }, async () => {
  const name = `.env.toolchain-probe-${randomUUID()}`;
  const path = new URL(name, root);
  const marker = "PUBLIC-TEST-MARKER-NOT-A-REAL-SECRET";
  let server;
  await writeFile(path, marker, { flag: "wx" });
  try {
    server = await createServer({
      configFile: fileURLToPath(new URL("vite.config.js", root)), root: fileURLToPath(root),
      mode: "test", logLevel: "silent",
      server: { host: "0.0.0.0", port: 0, strictPort: false, hmr: false, watch: null,
        allowedHosts: ["approved-preview.example"] },
    });
    await server.listen();
    const address = server.httpServer.address();
    // node:http sends the deliberately chosen Host verbatim. Node's fetch
    // may replace a supplied Host with its URL host (loopback is allowed).
    const get = (path, host) => new Promise((resolve, reject) => {
      const req = request({ hostname: "127.0.0.1", port: address.port, path, headers: { Host: host }, agent: false }, (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("error", reject);
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
      });
      req.on("error", reject);
      req.setTimeout(5000, () => req.destroy(new Error("local toolchain smoke request timed out")));
      req.end();
    });
    const approved = await get("/", "approved-preview.example");
    assert.equal(approved.status, 200);
    assert.match(approved.body, /id="root"/);
    const denied = await get("/", "untrusted.example");
    assert.equal(denied.status, 403);
    const env = await get(`/${name}`, "approved-preview.example");
    assert.ok([403, 404].includes(env.status));
    assert.ok(!env.body.includes(marker));
  } finally {
    try { if (server) await server.close(); }
    finally { await unlink(path); }
  }
});

test("on-prem console entrypoint uses only same-origin or embedded assets", async () => {
  const { JSDOM } = await import("jsdom");
  const html = await readFile(new URL("index.html", root), "utf8");
  const origin = "https://console.bank.example";
  const dom = new JSDOM(html, { url: origin });
  try {
    for (const element of dom.window.document.querySelectorAll("[src], [href]")) {
      const value = element.getAttribute("src") ?? element.getAttribute("href");
      if (element.tagName === "LINK" && element.rel === "icon" && value.startsWith("data:image/svg+xml,")) continue;
      assert.equal(new URL(value, origin).origin, origin, `Remote bootstrap asset: ${value}`);
    }
    assert.equal(dom.window.document.querySelectorAll('link[rel="preconnect"], link[rel="dns-prefetch"]').length, 0);
  } finally {
    dom.window.close();
  }
  const css = await readFile(new URL("src/styles/global.css", root), "utf8");
  assert.doesNotMatch(css, /@import\b|url\(\s*["']?\s*(?:https?:)?\/\//i);
  assert.match(css, /--sans:[^;]*system-ui/);
  assert.match(css, /--mono:[^;]*ui-monospace/);
});

test("on-prem runtime CSP does not permit external font or stylesheet origins", async () => {
  const nginx = await readFile(new URL("../.docker/frontend/nginx.conf", root), "utf8");
  const policy = nginx.match(/add_header Content-Security-Policy "([^"]+)" always;/)?.[1];
  assert.ok(policy, "Runtime must retain an explicit CSP");
  const directives = Object.fromEntries(policy.split(";").filter((part) => part.trim()).map((part) => {
    const [name, ...values] = part.trim().split(/\s+/);
    return [name, values];
  }));
  assert.deepEqual(directives["font-src"], ["'self'"]);
  assert.deepEqual(directives["style-src"], ["'self'", "'unsafe-inline'"]);
});
