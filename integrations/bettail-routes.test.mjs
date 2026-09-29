import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rmdir, unlink, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { WEBP_FIXTURE, LabFailure } from "./supabase-http.mjs";
import {
  ROUTE_BASE_URL, MAX_REQUESTS, MAX_RESPONSE_BYTES, RUN_TIMEOUT_MS, RESTORATION_RESERVE_MS,
  assertRouteUrl, createBudget, createBoundedFetch, createRouteTransport, createServiceTransport, createCookieSessionFactory,
  expectRouteState, expectRouteImage, runRouteLab, validateInput, replacePrivateEvidence,
} from "./bettail-routes.mjs";
import { nextEnvironment } from "./bettail-route-runtime.mjs";

const source = { migration_digest: "a".repeat(64), snapshot_digest: "b".repeat(64), source_revision: "c".repeat(40) };
const input = () => ({ publishableKey: "synthetic-public-key-for-tests", secretKey: "synthetic-private-key-for-tests", provenance: { ...source }, runId: randomUUID() });
const reply = (status, data, bytes = Buffer.from(JSON.stringify(data))) => ({ status, data, bytes,
  contentType: "application/json", cacheControl: "private, no-store", nosniff: "nosniff" });
const stateDenied = (status) => reply(status, { error: { 401: "Sign in to continue.", 403: "This group or bet is unavailable.", 400: "Invalid feed filters." }[status] });
const imageDenied = (status) => reply(status, null, Buffer.alloc(0));
const imageVisible = () => ({ ...reply(200, null, Buffer.from(WEBP_FIXTURE)), contentType: "image/webp" });

test("Next child environment refuses any alternate destination or privileged/malformed public key", () => {
  const environment = { NEXT_PUBLIC_SUPABASE_URL: "http://127.0.0.1:55321", NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: "sb_publishable_" + "test".repeat(10) };
  for (const url of ["https://production.invalid", "http://localhost:55321", "http://127.0.0.1:55322", undefined]) {
    assert.throws(() => nextEnvironment({ ...environment, NEXT_PUBLIC_SUPABASE_URL: url }));
  }
  for (const key of ["sb_secret_" + "test".repeat(10), "legacy.jwt.value", environment.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY + "\n", "short", undefined]) {
    assert.throws(() => nextEnvironment({ ...environment, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key }));
  }
});

test("Next child receives only lab configuration, without inherited credentials, proxy or preload variables", () => {
  const key = "sb_publishable_" + "test".repeat(10);
  const environment = nextEnvironment({ NEXT_PUBLIC_SUPABASE_URL: "http://127.0.0.1:55321", NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key,
    SUPABASE_SERVICE_ROLE_KEY: "must-not-inherit", HTTP_PROXY: "http://outside.invalid", NODE_OPTIONS: "--require private-preload",
    NODE_USE_ENV_PROXY: "1", DOCKER_HOST: "remote", DATABASE_URL: "private", PUBLIC_LAUNCH: "true", HOME: "/private", PATH: "/untrusted" });
  assert.deepEqual(Object.keys(environment).sort(), ["PATH", "HOME", "TMPDIR", "NODE_ENV", "NEXT_TELEMETRY_DISABLED", "DO_NOT_TRACK",
    "NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY"].sort());
  assert.equal(environment.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY, key);
  assert.equal(environment.NODE_ENV, "development");
  assert.equal(environment.NEXT_TELEMETRY_DISABLED, "1");
  assert.equal(environment.HOME, "/tmp");
  assert.ok(!JSON.stringify(environment).includes("must-not-inherit"));
});

test("CLI input accepts only fixed keys, valid IDs and exact hash provenance", () => {
  assert.equal(validateInput(input()).provenance.snapshot_digest, source.snapshot_digest);
  for (const mutate of [
    (value) => { value.target = "https://example.invalid"; },
    (value) => { value.runId = "../../outside"; },
    (value) => { value.provenance.source_revision = "missing"; },
    (value) => { value.provenance.path = "/another/app"; },
    (value) => { value.secretKey += "\n"; },
  ]) { const value = input(); mutate(value); assert.throws(() => validateInput(value), LabFailure); }
});

test("route transport admits only the two exact local application paths", () => {
  assert.equal(assertRouteUrl(`${ROUTE_BASE_URL}/api/state?group_id=invalid`).pathname, "/api/state");
  for (const url of [
    "http://localhost:3101/api/state", "http://2130706433:3101/api/state",
    "http://127.0.0.1:55321/api/state", "https://127.0.0.1:3101/api/state",
    `${ROUTE_BASE_URL}/api/chat-video`, `${ROUTE_BASE_URL}/api/state#fragment`,
    `${ROUTE_BASE_URL}/api/state\\@outside.invalid`, `${ROUTE_BASE_URL}/auth/callback`,
  ]) assert.throws(() => assertRouteUrl(url), { code: "route_target_not_allowed" });
});

test("normal requests cannot consume reserved restoration capacity or time", () => {
  let clock = 0;
  const budget = createBudget({ now: () => clock });
  for (let i = 0; i < MAX_REQUESTS - 24; i += 1) assert.equal(budget.consume(), 3000);
  assert.throws(() => budget.consume(), { code: "request_budget_exceeded" });
  clock = RUN_TIMEOUT_MS + 1;
  assert.throws(() => budget.consume(), { code: "overall_deadline_exceeded" });
  budget.beginRestoration();
  for (let i = 0; i < 24; i += 1) budget.consume();
  assert.equal(budget.count, MAX_REQUESTS);
  assert.throws(() => budget.consume(), { code: "request_budget_exceeded" });
  const timeOnly = createBudget({ now: () => clock });
  clock += RUN_TIMEOUT_MS + RESTORATION_RESERVE_MS;
  timeOnly.beginRestoration();
  assert.throws(() => timeOnly.consume(), { code: "overall_deadline_exceeded" });
});

test("reused service harness restoration can consume its bounded reserve after normal exhaustion", async () => {
  const budget = createBudget();
  for (let i = 0; i < MAX_REQUESTS - 24; i += 1) budget.consume();
  let calls = 0;
  const request = createServiceTransport({ ...input(), budget, fetchImpl: async () => { calls += 1; return new Response("{}", { status: 200 }); } });
  await assert.rejects(request("/auth/v1/user", { token: "ordinary-test-token" }), { code: "request_budget_exceeded" });
  await request("/rest/v1/rpc/bt_mutate", { method: "POST", token: "ordinary-owner-token", json: { action: "restore_member" } });
  await request("/rest/v1/rpc/bt_snapshot", { method: "POST", token: "ordinary-member-token", json: {} });
  assert.equal(calls, 2);
  budget.endRestoration();
  await assert.rejects(request("/auth/v1/user", { token: "ordinary-test-token" }), { code: "request_budget_exceeded" });
});

test("route requests carry only supplied cookies, disable redirects and bound request/response data", async () => {
  const calls = [];
  const transport = createRouteTransport({ fetchImpl: async (url, init) => {
    calls.push({ url, init });
    return new Response("{}", { headers: { "cache-control": "private, no-store" } });
  } });
  await transport("/api/state", "sdk-session=synthetic");
  assert.equal(calls[0].init.redirect, "error");
  assert.ok(calls[0].init.signal instanceof AbortSignal);
  assert.deepEqual(calls[0].init.headers, { Cookie: "sdk-session=synthetic" });
  await assert.rejects(transport("/api/state", "bad\r\nheader"), { code: "invalid_cookie_header" });
  await assert.rejects(transport("//outside.invalid/api/state"), { code: "route_target_not_allowed" });
  const oversized = createRouteTransport({ fetchImpl: async () => new Response("x".repeat(MAX_RESPONSE_BYTES + 1)) });
  await assert.rejects(oversized("/api/state"), { code: "response_too_large" });
});

test("redirects, raw network errors and arbitrary SDK endpoints fail without raw error data", async () => {
  const redirected = createRouteTransport({ fetchImpl: async () => new Response(null, { status: 307, headers: { Location: "https://outside.invalid" } }) });
  await assert.rejects(redirected("/api/state"), { code: "redirect_not_allowed" });
  const failed = createRouteTransport({ fetchImpl: async () => { throw Error("private-session-value"); } });
  await assert.rejects(failed("/api/state"), (error) => error.code === "transport_unavailable" && !error.message.includes("private-session"));
  const session = createBoundedFetch({ budget: createBudget(), kind: "session", fetchImpl: async () => { throw Error("Must not execute"); } });
  await assert.rejects(session("http://127.0.0.1:55321/auth/v1/admin/users", { method: "POST" }), { code: "session_endpoint_not_allowed" });
  await assert.rejects(session("http://127.0.0.1:55321/auth/v1/token?grant_type=refresh_token", { method: "POST" }), { code: "session_endpoint_not_allowed" });
});

test("route denial assertions reject infrastructure errors, unexpected data and missing private headers", () => {
  assert.equal(expectRouteState(stateDenied(403), { status: 403 }).outcome, "denied");
  assert.equal(expectRouteImage(imageDenied(404), 404).outcome, "not_visible");
  for (const response of [reply(503, {}), stateDenied(401), reply(403, { error: "Database unavailable." }),
    reply(403, { error: "This group or bet is unavailable.", private_data: "leak" })]) {
    assert.throws(() => expectRouteState(response, { status: 403 }), LabFailure);
  }
  for (const response of [reply(503, null, Buffer.alloc(0)), imageDenied(401), reply(404, {}, Buffer.from("not empty")), imageVisible()]) {
    assert.throws(() => expectRouteImage(response, 404), LabFailure);
  }
  assert.throws(() => expectRouteImage({ ...imageDenied(404), cacheControl: "public, max-age=3600" }, 404), { code: "private_cache_headers_missing" });
  assert.throws(() => expectRouteImage({ ...imageVisible(), bytes: Buffer.from("wrong") }, 200), LabFailure);
});

test("official SDK adapter serializes its cookie chunks and verifies actual Auth identity", async () => {
  const id = randomUUID();
  const token = `test.${Buffer.from(JSON.stringify({ sub: id, role: "authenticated" })).toString("base64url")}.mock`;
  let options, logins = 0, verifications = 0;
  const factory = createCookieSessionFactory({ publishableKey: input().publishableKey, createServerClient(url, key, configuration) {
    assert.equal(url, "http://127.0.0.1:55321");
    options = configuration;
    return { auth: {
      async signInWithPassword(credentials) {
        logins += 1;
        assert.equal(credentials.password, "synthetic-password");
        configuration.cookies.setAll([{ name: "sb-sdk-auth.0", value: "sdk-first" }, { name: "sb-sdk-auth.1", value: "sdk-second" }]);
        return { data: { session: { access_token: token }, user: { id } } };
      },
      async getUser(value) { verifications += 1; assert.equal(value, token); return { data: { user: { id } } }; },
    } };
  } });
  const session = await factory({ id, email: "synthetic@example.test", password: "synthetic-password" });
  assert.equal(session.cookie, "sb-sdk-auth.0=sdk-first; sb-sdk-auth.1=sdk-second");
  assert.equal(session.token, token);
  assert.equal(logins, 1);
  assert.equal(verifications, 1);
  assert.equal(options.auth.autoRefreshToken, false);
  assert.equal(options.cookieOptions.secure, false);
});

test("SDK adapter never trusts a decoded token without matching Auth verification", async () => {
  const id = randomUUID();
  const factory = createCookieSessionFactory({ publishableKey: input().publishableKey, createServerClient() {
    return { auth: {
      async signInWithPassword() { return { data: { session: { access_token: `a.${Buffer.from(JSON.stringify({ sub: id, role: "authenticated" })).toString("base64url")}.c` }, user: { id } } }; },
      async getUser() { return { data: { user: { id: randomUUID() } } }; },
    } };
  } });
  await assert.rejects(factory({ id, email: "synthetic@example.test", password: "synthetic-password" }), { code: "session_identity_not_verified" });
});

function mockFlow({ lostRemoval = false, restoreFailure = false, revokedOutage = false, setupFailure = false, restoredImageFailure = false } = {}) {
  const runId = randomUUID(), group = randomUUID(), post = randomUUID(), comment = randomUUID();
  const actors = Object.fromEntries(["owner", "member", "outsider"].map((name) => [name, {
    id: randomUUID(), email: `${name}@example.test`, password: `${name}-private-password`, token: `${name}-service-token`,
  }]));
  const saves = [], routeCalls = [], mutations = [], sessionCalls = [];
  let memberActive = true, removalAttempted = false, restored = false;
  const setupLab = async ({ savePrivate }) => {
    await savePrivate({ actors, group_id: group, post_id: post, comment_id: comment, restore_required: setupFailure });
    return { status: setupFailure ? "failed" : "passed", checks: [{ status: setupFailure ? "failed" : "passed" }],
      restoration: { status: setupFailure ? "restore_or_retest_failed" : "restored_and_retested" } };
  };
  const savePrivate = async (value) => { saves.push(structuredClone(value)); };
  const request = async (path, options) => {
    if (path === "/auth/v1/user") { assert.equal(options.token, "member-sdk-token"); return reply(200, { id: actors.member.id }); }
    assert.equal(path, "/rest/v1/rpc/bt_mutate");
    assert.equal(options.token, "owner-sdk-token");
    assert.equal(options.json.data.group_id, group);
    assert.equal(options.json.data.member_id, actors.member.id);
    mutations.push(options.json.action);
    if (options.json.action === "remove_member") {
      assert.equal(saves.at(-1).restore_required, true, "On-disk marker write must be awaited before removal");
      memberActive = false;
      removalAttempted = true;
      if (lostRemoval) throw new LabFailure("transport_unavailable");
    } else {
      assert.equal(options.json.action, "restore_member");
      if (restoreFailure) return reply(503, {});
      memberActive = true;
      restored = true;
    }
    return reply(200, {});
  };
  const routeRequest = async (path, cookie) => {
    routeCalls.push({ path, cookie });
    const role = ["owner", "member", "outsider"].find((name) => cookie === `${name}-sdk-cookie`);
    const image = path.startsWith("/api/chat-image");
    if (path.includes("invalid")) return image ? imageDenied(400) : stateDenied(400);
    if (!role) return image ? imageDenied(401) : stateDenied(401);
    if (revokedOutage && removalAttempted && !restored && role === "member") return reply(503, {});
    if (role === "outsider" || role === "member" && !memberActive) return image ? imageDenied(404) : stateDenied(403);
    if (image) return restored && restoredImageFailure && role === "member" ? imageDenied(404) : imageVisible();
    return reply(200, { group: { id: group }, posts: [{ id: post, title: "Synthetic SignalBridge private pick" }] });
  };
  const createSession = async (actor) => {
    const role = Object.keys(actors).find((name) => actors[name].id === actor.id);
    sessionCalls.push(role);
    return { cookie: `${role}-sdk-cookie`, token: `${role}-sdk-token` };
  };
  return { options: { request, routeRequest, createSession, provenance: source, runId, savePrivate, setupLab },
    saves, routeCalls, mutations, sessionCalls, actors, group, post, comment };
}

test("full mocked route flow retains the same session, tests denial and positively restores", async () => {
  const mock = mockFlow();
  const { report, serviceReport } = await runRouteLab(mock.options);
  assert.equal(report.status, "passed");
  assert.equal(serviceReport.status, "passed");
  assert.equal(report.checks.length, 23);
  assert.equal(report.checks.filter((row) => row.stage === "assertion").length, 16);
  assert.deepEqual(mock.sessionCalls, ["owner", "member", "outsider"]);
  assert.deepEqual(mock.mutations, ["remove_member", "restore_member"]);
  assert.equal(report.restoration.status, "restored_and_retested");
  assert.equal(mock.saves.at(-1).restore_required, false);
  const text = JSON.stringify(report);
  for (const value of [mock.group, mock.post, mock.comment, ...Object.values(mock.actors).flatMap((actor) => Object.values(actor)), "member-sdk-cookie", "member-sdk-token"]) assert.ok(!text.includes(value));
  assert.ok(report.limitations.some((text) => text.includes("not interactive OTP/OAuth")));
});

test("a lost removal response still requires restoration and produces a failed run", async () => {
  const mock = mockFlow({ lostRemoval: true });
  const { report } = await runRouteLab(mock.options);
  assert.equal(report.status, "failed");
  assert.equal(report.error_code, "transport_unavailable");
  assert.deepEqual(mock.mutations, ["remove_member", "restore_member"]);
  assert.equal(report.restoration.status, "restored_and_retested");
  assert.equal(mock.saves.at(-1).restore_required, false);
  assert.ok(!report.checks.some((row) => row.id === "removed_member_same_cookie_next_state_denied"));
});

test("an outage after removal never counts as successful denial", async () => {
  const mock = mockFlow({ revokedOutage: true });
  const { report } = await runRouteLab(mock.options);
  assert.equal(report.status, "failed");
  assert.equal(report.checks.find((row) => row.id === "removed_member_same_cookie_next_state_denied").status, "failed");
  assert.equal(report.restoration.status, "restored_and_retested");
});

test("a simulated revoked-member record leak fails the unchanged boundary and still restores", async () => {
  const mock = mockFlow();
  const normal = mock.options.routeRequest;
  mock.options.routeRequest = async (path, cookie) => {
    if (cookie === "member-sdk-cookie" && mock.mutations.at(-1) === "remove_member" && path.startsWith("/api/state")) {
      return reply(200, { group: { id: mock.group }, posts: [{ id: mock.post, title: "Synthetic SignalBridge private pick" }] });
    }
    return normal(path, cookie);
  };
  const { report } = await runRouteLab(mock.options);
  assert.equal(report.status, "failed");
  assert.equal(report.checks.find((row) => row.id === "removed_member_same_cookie_next_state_denied").status, "failed");
  assert.equal(report.restoration.status, "restored_and_retested");
  assert.equal(mock.saves.at(-1).restore_required, false);
  assert.ok(!JSON.stringify(report).includes(mock.post));
});

test("a simulated revoked-member image leak fails after the record denial passed", async () => {
  const mock = mockFlow();
  const normal = mock.options.routeRequest;
  mock.options.routeRequest = async (path, cookie) => {
    if (cookie === "member-sdk-cookie" && mock.mutations.at(-1) === "remove_member" && path.startsWith("/api/chat-image")) return imageVisible();
    return normal(path, cookie);
  };
  const { report } = await runRouteLab(mock.options);
  assert.equal(report.status, "failed");
  assert.equal(report.checks.find((row) => row.id === "removed_member_same_cookie_next_state_denied").status, "passed");
  assert.equal(report.checks.find((row) => row.id === "removed_member_same_cookie_next_image_hidden").status, "failed");
  assert.equal(report.restoration.status, "restored_and_retested");
});

test("blocking the owner after removal cannot pass as healthy scoped revocation", async () => {
  const mock = mockFlow();
  const normal = mock.options.routeRequest;
  mock.options.routeRequest = async (path, cookie) => {
    if (cookie === "owner-sdk-cookie" && mock.mutations.at(-1) === "remove_member" && path.startsWith("/api/state")) return stateDenied(403);
    return normal(path, cookie);
  };
  const { report } = await runRouteLab(mock.options);
  assert.equal(report.status, "failed");
  assert.equal(report.checks.find((row) => row.id === "removed_member_same_cookie_next_image_hidden").status, "passed");
  assert.equal(report.checks.find((row) => row.id === "owner_next_state_survives_removal").status, "failed");
  assert.equal(report.restoration.status, "restored_and_retested");
});

test("failed restoration or positive retest retains the recovery marker", async () => {
  for (const options of [{ restoreFailure: true }, { restoredImageFailure: true }]) {
    const mock = mockFlow(options);
    const { report } = await runRouteLab(mock.options);
    assert.equal(report.status, "failed");
    assert.equal(report.restoration.status, "restore_or_retest_failed");
    assert.equal(mock.saves.at(-1).restore_required, true);
  }
});

test("a failed service setup preserves its restoration marker and never starts route/session checks", async () => {
  const mock = mockFlow({ setupFailure: true });
  const { report } = await runRouteLab(mock.options);
  assert.equal(report.status, "failed");
  assert.equal(report.error_code, "service_setup_or_restoration_failed");
  assert.deepEqual(report.checks, []);
  assert.deepEqual(mock.sessionCalls, []);
  assert.deepEqual(mock.routeCalls, []);
  assert.equal(mock.saves.at(-1).restore_required, true);
  assert.equal(mock.saves.at(-1).service.restore_required, true);
});

const regular = () => ({ isFile: () => true, isSymbolicLink: () => false, nlink: 1 });
const replacementSeams = () => ({ inspect: async () => regular(), canonical: async (path) => path, pause: async () => {} });

test("atomic private replacement retries sharing locks with bounded waits and rechecks paths", async () => {
  const waits = [], inspected = [], replaced = [];
  const codes = ["EACCES", "EPERM", "EBUSY"];
  await replacePrivateEvidence("/evidence/current.private.json", "/evidence/new.pending", {
    ...replacementSeams(), inspect: async (path) => { inspected.push(path); return regular(); },
    pause: async (delay) => { waits.push(delay); },
    replace: async (source, target) => {
      replaced.push({ source, target });
      const code = codes.shift();
      if (code) throw Object.assign(new Error("synthetic private path must never be emitted"), { code });
    },
  });
  assert.deepEqual(waits, [25, 50, 100]);
  assert.equal(replaced.length, 4);
  assert.equal(inspected.length, 8);
  assert.ok(replaced.every((call) => call.source === "/evidence/new.pending" && call.target === "/evidence/current.private.json"));
});

test("persistent sharing locks stop after seven attempts with a fixed code and leave pending state", async () => {
  let attempts = 0;
  const waits = [];
  await assert.rejects(replacePrivateEvidence("/evidence/current.private.json", "/evidence/new.pending", {
    ...replacementSeams(), pause: async (delay) => { waits.push(delay); },
    replace: async () => { attempts += 1; throw Object.assign(new Error("synthetic-private-value"), { code: "EACCES" }); },
  }), (error) => error.code === "private_evidence_replace_eacces" && !error.message.includes("synthetic-private-value"));
  assert.equal(attempts, 7);
  assert.deepEqual(waits, [25, 50, 100, 200, 400, 800]);
  assert.equal(waits.reduce((sum, value) => sum + value, 0), 1575);
});

test("nontransient replacement errors and changed links fail immediately without retrying", async () => {
  let calls = 0, waits = 0;
  await assert.rejects(replacePrivateEvidence("/evidence/current.private.json", "/evidence/new.pending", {
    ...replacementSeams(), pause: async () => { waits += 1; },
    replace: async () => { calls += 1; throw Object.assign(new Error("private file content"), { code: "EIO" }); },
  }), { code: "private_evidence_replace_failed" });
  assert.equal(calls, 1);
  assert.equal(waits, 0);
  for (const shape of [{ ...regular(), nlink: 2 }, { ...regular(), isSymbolicLink: () => true }]) {
    await assert.rejects(replacePrivateEvidence("/evidence/current.private.json", "/evidence/new.pending", {
      ...replacementSeams(), inspect: async () => shape, replace: async () => { throw Error("Must not replace"); },
    }), { code: "private_evidence_path_changed" });
  }
});

test("actual local private replacement preserves the old file until rename succeeds", async () => {
  const parent = resolve("var/tests");
  await mkdir(parent, { recursive: true });
  const directory = await mkdtemp(join(parent, "route-atomic-"));
  const current = join(directory, "current.private.json"), temporary = join(directory, "new.pending");
  try {
    assert.equal(await realpath(directory), directory);
    await writeFile(current, "synthetic-old", { flag: "wx", mode: 0o600 });
    await writeFile(temporary, "synthetic-new", { flag: "wx", mode: 0o600 });
    await assert.rejects(replacePrivateEvidence(current, temporary, {
      replace: async () => { throw Object.assign(new Error("synthetic IO failure"), { code: "EIO" }); },
    }), { code: "private_evidence_replace_failed" });
    assert.equal(await readFile(current, "utf8"), "synthetic-old");
    assert.equal(await readFile(temporary, "utf8"), "synthetic-new");
    await replacePrivateEvidence(current, temporary);
    assert.equal(await readFile(current, "utf8"), "synthetic-new");
    await assert.rejects(readFile(temporary), { code: "ENOENT" });
  } finally {
    assert.equal(await realpath(directory), directory);
    assert.ok(directory.startsWith(join(parent, "route-atomic-")));
    for (const file of [current, temporary]) {
      try { await unlink(file); } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    await rmdir(directory);
  }
});
