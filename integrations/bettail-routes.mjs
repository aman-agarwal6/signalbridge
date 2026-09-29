/** Actual BetTail Next route lab. Importing this module never starts a request. */
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, readFile, realpath, rename, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import {
  LAB_BASE_URL, LabFailure, assertLabUrl, createTransport,
  expectSnapshotVisible, expectImageVisible, runLab, sha256,
} from "./supabase-http.mjs";

export const ROUTE_BASE_URL = "http://127.0.0.1:3101";
export const MAX_REQUESTS = 160;
export const RUN_TIMEOUT_MS = 120000;
export const RESTORATION_RESERVE_MS = 30000;
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/;
const must = (value, code) => { if (!value) throw new LabFailure(code); };
const safeCode = (error) => error instanceof LabFailure ? error.code : "unexpected_error";
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const REPLACE_RETRY_MS = [25, 50, 100, 200, 400, 800];
const TRANSIENT_REPLACE_CODES = new Set(["EACCES", "EPERM", "EBUSY"]);

export function validateInput(value) {
  must(exactKeys(value, ["publishableKey", "secretKey", "provenance", "runId"]), "invalid_input_keys");
  for (const key of [value.publishableKey, value.secretKey]) {
    must(typeof key === "string" && key.length >= 20 && key.length <= 8192 && !/[\s\r\n]/.test(key), "invalid_lab_keys");
  }
  must(UUID.test(value.runId), "invalid_run_id");
  validateSource(value.provenance);
  return value;
}

function validateSource(value) {
  must(exactKeys(value, ["migration_digest", "snapshot_digest", "source_revision"]) &&
    DIGEST.test(value.migration_digest) && DIGEST.test(value.snapshot_digest) &&
    /^[0-9a-f]{40}$/.test(value.source_revision), "invalid_route_provenance");
}

/** The final 24 requests and 30 seconds are reserved for attempted restoration. */
export function createBudget({ now = () => performance.now() } = {}) {
  const started = now();
  let count = 0, restoration = false;
  return {
    beginRestoration() { restoration = true; },
    endRestoration() { restoration = false; },
    consume() {
      const remaining = started + RUN_TIMEOUT_MS + (restoration ? RESTORATION_RESERVE_MS : 0) - now();
      must(remaining > 0, "overall_deadline_exceeded");
      must(count < (restoration ? MAX_REQUESTS : MAX_REQUESTS - 24), "request_budget_exceeded");
      count += 1;
      return Math.max(1, Math.min(3000, Math.floor(remaining)));
    },
    get count() { return count; },
  };
}

export function assertRouteUrl(value) {
  must(typeof value === "string" && value.startsWith(`${ROUTE_BASE_URL}/`) && !/[\\\r\n]/.test(value), "route_target_not_allowed");
  let url;
  try { url = new URL(value); } catch { throw new LabFailure("route_target_not_allowed"); }
  must(url.origin === ROUTE_BASE_URL && !url.username && !url.password && !url.hash &&
    ["/api/state", "/api/chat-image"].includes(url.pathname), "route_target_not_allowed");
  return url;
}

async function bodyBytes(response) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let count = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      count += value.byteLength;
      if (count > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new LabFailure("response_too_large");
      }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks);
}

/** Return a buffered Response so timeout and size bounds include response consumption. */
export function createBoundedFetch({ fetchImpl = globalThis.fetch, budget, kind }) {
  must(budget && ["service", "route", "session"].includes(kind), "invalid_transport_kind");
  return async (input, init = {}) => {
    must(typeof input === "string" || input instanceof URL, "request_input_not_allowed");
    const url = kind === "route" ? assertRouteUrl(String(input)) : assertLabUrl(String(input));
    const method = (init.method || "GET").toUpperCase();
    must(kind === "route" ? method === "GET" : ["GET", "POST"].includes(method), "method_not_allowed");
    if (kind === "session") {
      must((method === "POST" && url.pathname === "/auth/v1/token" && url.search === "?grant_type=password") ||
        (method === "GET" && url.pathname === "/auth/v1/user" && !url.search), "session_endpoint_not_allowed");
    }
    const deadline = AbortSignal.timeout(budget.consume());
    const signal = init.signal ? AbortSignal.any([init.signal, deadline]) : deadline;
    try {
      const response = await fetchImpl(url.href, { ...init, method, redirect: "error", signal });
      must(!response.redirected && !(response.status >= 300 && response.status < 400), "redirect_not_allowed");
      const bytes = await bodyBytes(response);
      return new Response([204, 205, 304].includes(response.status) ? null : bytes,
        { status: response.status, headers: response.headers });
    } catch (error) {
      if (error instanceof LabFailure) throw error;
      throw new LabFailure("transport_unavailable");
    }
  };
}

export function createRouteTransport({ fetchImpl = globalThis.fetch, budget = createBudget() } = {}) {
  const boundedFetch = createBoundedFetch({ fetchImpl, budget, kind: "route" });
  return async (path, cookie = "") => {
    must(typeof path === "string" && path.startsWith("/") && !path.startsWith("//"), "route_target_not_allowed");
    must(typeof cookie === "string" && cookie.length <= 32768 && !/[\r\n\x00]/.test(cookie), "invalid_cookie_header");
    const response = await boundedFetch(ROUTE_BASE_URL + path, { headers: cookie ? { Cookie: cookie } : {} });
    const bytes = Buffer.from(await response.arrayBuffer());
    let data = null;
    try { data = JSON.parse(bytes.toString("utf8")); } catch { /* No raw body reaches evidence. */ }
    return { status: response.status, bytes, data, contentType: response.headers.get("content-type") || "",
      cacheControl: response.headers.get("cache-control") || "", nosniff: response.headers.get("x-content-type-options") || "" };
  };
}

export function createServiceTransport({ publishableKey, secretKey, fetchImpl = globalThis.fetch, budget = createBudget() }) {
  const serviceFetch = createBoundedFetch({ fetchImpl, budget, kind: "service" });
  const transport = createTransport({ publishableKey, secretKey, fetchImpl: serviceFetch });
  return (path, options) => {
    // The reused service harness has its own finally block, before route checks start.
    // Its restore operation must retain access to the reserve even after normal exhaustion.
    if (path === "/rest/v1/rpc/bt_mutate" && options?.json?.action === "restore_member") budget.beginRestoration();
    return transport(path, options);
  };
}

/** The official SDK creates its own cookie format; no fabricated session claims. */
export function createCookieSessionFactory({ createServerClient, publishableKey, fetchImpl = globalThis.fetch, budget = createBudget() }) {
  must(typeof createServerClient === "function", "session_sdk_missing");
  const boundedFetch = createBoundedFetch({ fetchImpl, budget, kind: "session" });
  return async (actor) => {
    const jar = new Map();
    const client = createServerClient(LAB_BASE_URL, publishableKey, {
      cookieOptions: { sameSite: "lax", secure: false, path: "/" },
      global: { fetch: boundedFetch },
      auth: { autoRefreshToken: false, detectSessionInUrl: false },
      cookies: {
        getAll: () => [...jar].map(([name, value]) => ({ name, value })),
        setAll(values) {
          must(Array.isArray(values) && values.length <= 24, "invalid_session_cookies");
          for (const { name, value, options } of values) {
            must(typeof name === "string" && /^[A-Za-z0-9_.-]{1,200}$/.test(name) &&
              typeof value === "string" && value.length <= 8192 && !/[;\r\n\x00]/.test(value), "invalid_session_cookies");
            if (options?.maxAge === 0) jar.delete(name); else jar.set(name, value);
          }
        },
      },
    });
    const result = await client.auth.signInWithPassword({ email: actor.email, password: actor.password });
    const session = result.data?.session;
    must(!result.error && result.data?.user?.id === actor.id && typeof session?.access_token === "string", "session_login_failed");
    let claims;
    try { claims = JSON.parse(Buffer.from(session.access_token.split(".")[1], "base64url").toString("utf8")); } catch { /* Checked below. */ }
    must(claims?.sub === actor.id && claims?.role === "authenticated", "session_role_invalid");
    const verified = await client.auth.getUser(session.access_token);
    must(!verified.error && verified.data?.user?.id === actor.id, "session_identity_not_verified");
    const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
    must(cookie.length > 0 && cookie.length <= 32768, "session_cookie_missing");
    return { cookie, token: session.access_token };
  };
}

function privateCache(response) {
  must(/(?:^|,)\s*private(?:\s*,|$)/i.test(response.cacheControl) && /(?:^|,)\s*no-store(?:\s*,|$)/i.test(response.cacheControl), "private_cache_headers_missing");
}
export function expectRouteState(response, { status, postId, groupId }) {
  privateCache(response);
  if (status === 200) return expectSnapshotVisible(response, postId, groupId);
  const message = { 401: "Sign in to continue.", 403: "This group or bet is unavailable.", 400: "Invalid feed filters." }[status];
  must(response.status === status && exactKeys(response.data, ["error"]) && response.data.error === message, "route_state_denial_not_established");
  return { http_status: response.status, outcome: status === 400 ? "invalid_input_rejected" : "denied" };
}
export function expectRouteImage(response, status) {
  privateCache(response);
  must(response.nosniff === "nosniff", "image_nosniff_missing");
  if (status === 200) return expectImageVisible(response);
  must([400, 401, 404].includes(status) && response.status === status && response.bytes.length === 0, "route_image_denial_not_established");
  return { http_status: response.status, outcome: status === 400 ? "invalid_input_rejected" : "not_visible" };
}

/** All seams are injectable for mock-only tests; setup still defaults to the real service harness. */
export async function runRouteLab({ request, routeRequest, createSession, provenance, runId, savePrivate = async () => {},
  setupLab = runLab, budget = createBudget() }) {
  must(UUID.test(runId), "invalid_run_id");
  validateSource(provenance);
  const started = performance.now();
  let privateState, restoreRequired = false;
  const sessions = {};
  const report = { schema_version: 1, app: "bettail", environment: "isolated_next_routes", run_id: runId,
    started_at: new Date().toISOString(), status: "running", source: { ...provenance }, checks: [],
    restoration: { required: false, attempted: false, status: "not_needed" },
    limitations: [
      "Actual development Next API SSR-session consumption; not interactive OTP/OAuth login or full browser behavior.",
      "Synthetic password sessions use the official SDK; production Secure-cookie and refresh behavior remain unverified.",
      "Only GET /api/state and GET /api/chat-image are exercised; signed URLs and other routes remain unverified.",
      "No source-route security telemetry, transactional outbox, committed policy fault or full M1 gate is established.",
      "Source identity is supplied by the guarded launcher; review its before/after source and topology evidence separately.",
      "Private image 404 is non-disclosure for this known fixture, not proof that all upstream failures are distinguished by the source route.",
    ] };
  const persist = async () => savePrivate({ schema_version: 1, run_id: runId, service: privateState,
    sessions, route_restore_required: restoreRequired,
    restore_required: restoreRequired || privateState?.restore_required === true });
  async function check(id, stage, operation) {
    const clock = performance.now();
    try {
      const result = await operation();
      report.checks.push({ id, stage, status: "passed", duration_ms: Math.round(performance.now() - clock), ...result });
    } catch (error) {
      report.checks.push({ id, stage, status: "failed", duration_ms: Math.round(performance.now() - clock), error_code: safeCode(error) });
      throw error;
    }
  }
  let serviceReport;
  try {
    serviceReport = await setupLab({ request, provenance, runId, savePrivate: async (value) => { privateState = value; await persist(); } });
    budget.endRestoration();
    report.service_setup = { status: serviceReport.status, executed: serviceReport.checks.length,
      passed: serviceReport.checks.filter((item) => item.status === "passed").length, restoration: serviceReport.restoration.status };
    must(serviceReport.status === "passed" && serviceReport.restoration.status === "restored_and_retested" &&
      privateState?.restore_required === false, "service_setup_or_restoration_failed");
    must([privateState.group_id, privateState.post_id, privateState.comment_id].every((id) => UUID.test(id)), "service_fixture_invalid");
    for (const actor of ["owner", "member", "outsider"]) {
      await check(`${actor}_sdk_cookie_session_verified`, "setup", async () => {
        sessions[actor] = await createSession(privateState.actors[actor]);
        await persist();
        return { outcome: "authenticated_cookie_session" };
      });
    }
    const state = (actor) => routeRequest(`/api/state?group_id=${privateState.group_id}&post_id=${privateState.post_id}`, sessions[actor]?.cookie || "");
    const image = (actor) => routeRequest(`/api/chat-image?comment_id=${privateState.comment_id}`, sessions[actor]?.cookie || "");
    const visible = (response) => expectRouteState(response, { status: 200, postId: privateState.post_id, groupId: privateState.group_id });
    for (const actor of ["owner", "member"]) {
      await check(`${actor}_next_exact_state_visible`, "assertion", async () => visible(await state(actor)));
      await check(`${actor}_next_exact_image_visible`, "assertion", async () => expectRouteImage(await image(actor), 200));
    }
    await check("outsider_next_state_denied", "assertion", async () => expectRouteState(await state("outsider"), { status: 403 }));
    await check("outsider_next_image_hidden", "assertion", async () => expectRouteImage(await image("outsider"), 404));
    await check("anonymous_next_state_denied", "assertion", async () => expectRouteState(await state(null), { status: 401 }));
    await check("anonymous_next_image_denied", "assertion", async () => expectRouteImage(await image(null), 401));
    await check("invalid_next_state_filter_rejected", "assertion", async () => expectRouteState(
      await routeRequest("/api/state?group_id=invalid", sessions.member.cookie), { status: 400 }));
    await check("invalid_next_image_id_rejected", "assertion", async () => expectRouteImage(
      await routeRequest("/api/chat-image?comment_id=invalid", sessions.member.cookie), 400));
    await check("invalid_next_image_scope_rejected", "assertion", async () => expectRouteImage(
      await routeRequest(`/api/chat-image?comment_id=${privateState.comment_id}&scope=invalid`, sessions.member.cookie), 400));
    restoreRequired = true;
    report.restoration.required = true;
    await persist(); // A lost reply can hide a committed membership change.
    await check("route_member_removed", "setup", async () => { await mutate("remove_member"); return { outcome: "membership_removed" }; });
    await check("removed_member_same_session_still_auth_valid", "assertion", async () => {
      const response = await request("/auth/v1/user", { token: sessions.member.token });
      must(response.status === 200 && response.data?.id === privateState.actors.member.id, "retained_session_not_verified");
      return { http_status: response.status, outcome: "same_session_authenticated" };
    });
    await check("removed_member_same_cookie_next_state_denied", "assertion", async () => expectRouteState(await state("member"), { status: 403 }));
    await check("removed_member_same_cookie_next_image_hidden", "assertion", async () => expectRouteImage(await image("member"), 404));
    await check("owner_next_state_survives_removal", "assertion", async () => visible(await state("owner")));
    await check("owner_next_image_survives_removal", "assertion", async () => expectRouteImage(await image("owner"), 200));
  } catch (error) {
    report.status = "failed";
    report.error_code = safeCode(error);
  } finally {
    if (restoreRequired) {
      report.restoration.attempted = true;
      budget.beginRestoration();
      try {
        await check("route_membership_restored", "restoration", async () => { await mutate("restore_member"); return { outcome: "membership_restored" }; });
        await check("restored_member_next_state_visible", "restoration", async () => expectRouteState(
          await routeRequest(`/api/state?group_id=${privateState.group_id}&post_id=${privateState.post_id}`, sessions.member.cookie),
          { status: 200, postId: privateState.post_id, groupId: privateState.group_id }));
        await check("restored_member_next_image_visible", "restoration", async () => expectRouteImage(
          await routeRequest(`/api/chat-image?comment_id=${privateState.comment_id}`, sessions.member.cookie), 200));
        restoreRequired = false;
        await persist();
        report.restoration.status = "restored_and_retested";
      } catch (error) {
        report.status = "failed";
        report.restoration.status = "restore_or_retest_failed";
        report.restoration.error_code = safeCode(error);
      }
    }
  }
  if (report.status === "running") report.status = "passed";
  report.finished_at = new Date().toISOString();
  report.duration_ms = Math.round(performance.now() - started);
  report.request_count = budget.count;
  return { report, serviceReport };
  async function mutate(action) {
    const response = await request("/rest/v1/rpc/bt_mutate", { method: "POST", token: sessions.owner.token,
      json: { action, data: { group_id: privateState.group_id, member_id: privateState.actors.member.id }, request_id: randomUUID() } });
    must(response.status === 200 && response.data && typeof response.data === "object" && !response.data.error, "route_membership_mutation_failed");
  }
}

async function readInput(stream) {
  const chunks = [];
  let count = 0;
  const timeout = setTimeout(() => stream.destroy(new LabFailure("input_deadline_exceeded")), 10000);
  try {
    for await (const chunk of stream) {
      count += chunk.length;
      must(count <= 65536, "input_too_large");
      chunks.push(chunk);
    }
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new LabFailure("invalid_input_json"); }
    return validateInput(input);
  } finally { clearTimeout(timeout); }
}

/** Retry only transient sharing errors; never remove the old recovery record first.
 * Windows bind mounts can reject rename while a host reader briefly holds the
 * destination. The pending file remains available if bounded retries exhaust.
 * Atomic replacement is not an fsync-backed host-crash durability guarantee.
 */
export async function replacePrivateEvidence(path, temporary, {
  inspect = lstat, canonical = realpath, replace = rename,
  pause = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds)),
} = {}) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      for (const candidate of [path, temporary]) {
        const info = await inspect(candidate);
        must(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 &&
          await canonical(candidate) === candidate, "private_evidence_path_changed");
      }
    } catch (error) {
      if (error instanceof LabFailure) throw error;
      throw new LabFailure("private_evidence_metadata_unavailable");
    }
    try { await replace(temporary, path); return; }
    catch (error) {
      const transient = TRANSIENT_REPLACE_CODES.has(error?.code);
      if (!transient || attempt >= REPLACE_RETRY_MS.length) {
        throw new LabFailure(transient ? `private_evidence_replace_${error.code.toLowerCase()}` : "private_evidence_replace_failed");
      }
      await pause(REPLACE_RETRY_MS[attempt]);
    }
  }
}

export async function main(argv = process.argv.slice(2)) {
  must(argv.length === 0 && process.platform === "linux", "container_cli_required");
  must(!["1", "true"].includes(process.env.NODE_USE_ENV_PROXY?.toLowerCase()) &&
    !process.execArgv.includes("--use-env-proxy") && !process.env.NODE_OPTIONS?.includes("--use-env-proxy"), "proxy_configuration_not_allowed");
  const input = await readInput(process.stdin);
  must(await realpath("/evidence") === "/evidence" && (await lstat("/evidence")).isDirectory(), "evidence_directory_invalid");
  const harnessPath = fileURLToPath(import.meta.url);
  must(harnessPath === "/lab/bettail-routes.mjs" && await realpath(harnessPath) === harnessPath, "harness_path_invalid");
  const before = { harness_sha256: sha256(await readFile(harnessPath)), service_harness_sha256: sha256(await readFile("/lab/supabase-http.mjs")) };
  const require = createRequire("/app/package.json");
  const sdkPath = require.resolve("@supabase/ssr");
  must((await realpath(sdkPath)).startsWith("/app/node_modules/@supabase/ssr/"), "session_sdk_path_invalid");
  const { createServerClient } = require("@supabase/ssr");
  const sdkVersion = JSON.parse(await readFile("/app/node_modules/@supabase/ssr/package.json", "utf8")).version;
  must(sdkVersion === "0.12.7", "session_sdk_version_invalid");
  const budget = createBudget();
  const request = createServiceTransport({ ...input, budget });
  const prefix = `/evidence/${input.runId}`;
  for (const suffix of [".json", ".service.json"]) {
    let existing = false;
    try { await lstat(prefix + suffix); existing = true; }
    catch (error) { if (error.code !== "ENOENT") throw new LabFailure("evidence_path_unreadable"); }
    must(!existing, "run_evidence_already_exists");
  }
  // Reserve this run identity before any mutation; never overwrite another run's recovery file.
  await writeFile(`${prefix}.private.json`, JSON.stringify({ schema_version: 1, run_id: input.runId, state: "starting" }), { flag: "wx", mode: 0o600 });
  const savePrivate = async (value) => {
    const path = `${prefix}.private.json`;
    must((await lstat(path)).isFile() && await realpath(path) === path, "private_evidence_path_changed");
    const temporary = `${prefix}.${randomUUID()}.pending`;
    await writeFile(temporary, JSON.stringify(value, null, 2), { flag: "wx", mode: 0o600 });
    await replacePrivateEvidence(path, temporary);
  };
  const { report, serviceReport } = await runRouteLab({ request, provenance: input.provenance, runId: input.runId, budget, savePrivate,
    routeRequest: createRouteTransport({ budget }),
    createSession: createCookieSessionFactory({ createServerClient, publishableKey: input.publishableKey, budget }) });
  report.source = { ...report.source, ...before };
  for (const [field, path] of [["harness_sha256", harnessPath], ["service_harness_sha256", "/lab/supabase-http.mjs"]]) {
    let after = null;
    try { after = await realpath(path) === path ? sha256(await readFile(path)) : null; } catch { /* Unavailable evidence fails closed. */ }
    report.source[`${field}_unchanged`] = after === before[field];
    if (after !== before[field]) { report.status = "failed"; report.error_code ??= "harness_changed_or_unavailable"; }
  }
  report.runtime = { node_version: process.version, supabase_ssr_version: sdkVersion, next_mode: "development" };
  if (serviceReport) await writeFile(`${prefix}.service.json`, JSON.stringify(serviceReport, null, 2), { flag: "wx", mode: 0o600 });
  await writeFile(`${prefix}.json`, JSON.stringify(report, null, 2), { flag: "wx", mode: 0o600 });
  process.stdout.write(`BetTail Next route lab ${report.status}; ${report.checks.filter((row) => row.status === "passed").length}/${report.checks.length} executed route checks passed. Run ${input.runId}.\n`);
  if (report.status !== "passed") process.exitCode = 1;
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`BetTail Next route lab stopped: ${safeCode(error)}. No success claimed.\n`);
    process.exitCode = 1;
  });
}
