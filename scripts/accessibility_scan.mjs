// Automated accessibility scan (axe-core) of console and static pages in headless Chrome.
//
// Usage: node scripts/accessibility_scan.mjs <axe.min.js> <targets.json> <out.json>
//
// targets.json: {"cookie": {"name", "value"} | null, "origin": "http://127.0.0.1:<port>/",
//                "authenticated": [urls], "anonymous": [urls]}
//
// Scan a disposable console (its own checkout and synthetic data), never a workspace in
// use. axe-core is not vendored: fetch it with `npm pack axe-core@<version>` and check the
// tarball's sha512 against the registry before use. The browser runs with a throwaway
// profile and bypasses the page CSP only so the axe script can be injected. Every page is
// scanned in light and dark color schemes; a page whose stylesheets failed to load stops
// the scan, because an unstyled page gives misleading size and contrast results.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [axePath, targetsPath, outPath] = process.argv.slice(2);
if (!outPath) throw new Error("usage: accessibility_scan.mjs <axe.min.js> <targets.json> <out.json>");
const axe = readFileSync(axePath, "utf8");
const targets = JSON.parse(readFileSync(targetsPath, "utf8"));
const CHROME = process.env.CHROME || "C:/Program Files/Google/Chrome/Application/chrome.exe";
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const profile = mkdtempSync(join(tmpdir(), "sb-axe-"));
const chrome = spawn(
  CHROME,
  [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "about:blank",
  ],
  { stdio: "ignore" },
);

let port;
for (let i = 0; i < 100 && !port; i++) {
  const file = join(profile, "DevToolsActivePort");
  if (existsSync(file)) port = readFileSync(file, "utf8").split("\n")[0].trim();
  else await sleep(100);
}
if (!port) throw new Error("Chrome did not expose a DevTools port");
const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const ws = new WebSocket(pages.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((resolve) => ws.addEventListener("open", resolve, { once: true }));

let nextId = 0;
const pending = new Map();
const waiters = [];
ws.addEventListener("message", (message) => {
  const data = JSON.parse(message.data);
  if (data.id && pending.has(data.id)) {
    const { resolve, reject } = pending.get(data.id);
    pending.delete(data.id);
    if (data.error) reject(new Error(data.error.message));
    else resolve(data.result);
  } else if (data.method) {
    for (const waiter of waiters.filter((w) => w.method === data.method)) {
      waiters.splice(waiters.indexOf(waiter), 1);
      waiter.resolve(data.params);
    }
  }
});
const send = (method, params = {}) =>
  new Promise((resolve, reject) => {
    pending.set(++nextId, { resolve, reject });
    ws.send(JSON.stringify({ id: nextId, method, params }));
  });
const once = (method, ms = 20000) =>
  Promise.race([
    new Promise((resolve) => waiters.push({ method, resolve })),
    sleep(ms).then(() => {
      throw new Error("timeout waiting for " + method);
    }),
  ]);
const evaluate = async (expression, awaitPromise = false) => {
  const reply = await send("Runtime.evaluate", { expression, awaitPromise, returnByValue: true });
  if (reply.exceptionDetails) throw new Error("page evaluation failed");
  return reply.result.value;
};

await send("Page.enable");
await send("Network.enable");
await send("Page.setBypassCSP", { enabled: true });
await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

const results = [];
async function scan(url, cookie) {
  await send("Network.clearBrowserCookies");
  if (cookie) {
    await send("Network.setCookie", { name: cookie.name, value: cookie.value, url: targets.origin, httpOnly: true });
  }
  for (const scheme of ["light", "dark"]) {
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }] });
    const loaded = once("Page.loadEventFired");
    await send("Page.navigate", { url });
    await loaded;
    await sleep(300);
    const finalUrl = await evaluate("location.href");
    await evaluate(axe);
    const value = JSON.parse(
      await evaluate(
        `axe.run(document, {runOnly: {type: "tag", values: ${JSON.stringify(TAGS)}}, resultTypes: ["violations"]})
          .then(r => JSON.stringify({
            violations: r.violations.map(v => ({id: v.id, impact: v.impact,
              tags: v.tags.filter(t => t.startsWith("wcag") || t === "best-practice"),
              help: v.help, count: v.nodes.length, targets: v.nodes.slice(0, 40).map(n => n.target.join(" ")),
              summaries: v.nodes.slice(0, 40).map(n => (n.failureSummary || "").slice(0, 300))})),
            passes: r.passes.length, incomplete: r.incomplete.length, inapplicable: r.inapplicable.length,
            stylesheets: [...document.styleSheets].filter(s => { try { return s.cssRules.length > 0 } catch { return true } }).length,
            title: document.title, lang: document.documentElement.lang}))`,
        true,
      ),
    );
    if (value.stylesheets === 0) throw new Error("no stylesheet loaded for " + url);
    results.push({ url, scheme, finalUrl, ...value });
    const found = value.violations.map((v) => `${v.id}(${v.impact},${v.count})`).join(" ");
    console.log(`${scheme.padEnd(5)} css=${value.stylesheets} ${url} -> ${found || "no violations"}`);
  }
}

try {
  for (const url of targets.authenticated) await scan(url, targets.cookie);
  for (const url of targets.anonymous) await scan(url, null);
} finally {
  writeFileSync(
    outPath,
    JSON.stringify({ axe_version: axe.match(/axe v([\d.]+)/)?.[1] ?? "unknown", browser: version.Browser, tags: TAGS, results }, null, 2),
  );
  ws.close();
  chrome.kill();
  await sleep(500);
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    // Chrome may still hold the profile briefly; it lives in the temp folder.
  }
}
