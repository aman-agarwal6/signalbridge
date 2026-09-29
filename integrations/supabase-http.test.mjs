import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  LAB_BASE_URL, REQUEST_TIMEOUT_MS, WEBP_FIXTURE, LabFailure, assertLabUrl,
  createTransport, expectRowsHidden, expectSnapshotDenied, expectAnonymousDenied,
  expectImageHidden, expectImageVisible, parseLabKeys, validateProvenance, runLab, sha256, finalizeExecutionEvidence,
} from "./supabase-http.mjs";

const keys = { publishableKey: "local-public-key".repeat(3), secretKey: "local-secret-key".repeat(3) };
const reply = (status, data, contentType = "application/json", bytes = Buffer.from(JSON.stringify(data))) =>
  ({ status, data, contentType, bytes });
const denied = () => reply(400, { code: "P0001", message: "Bet unavailable." });
const anonymous = () => reply(401, { code: "42501", message: "permission denied for table bet_posts" });
const invisibleImage = () => reply(404, { code: "NoSuchKey", message: "Object not found" });
const visibleImage = () => reply(200, null, "image/webp", Buffer.from(WEBP_FIXTURE));

test("only the fixed literal loopback origin and service paths are accepted", () => {
  assert.equal(assertLabUrl(`${LAB_BASE_URL}/rest/v1/bet_posts`).origin, LAB_BASE_URL);
  for (const url of [
    "https://127.0.0.1:55321/rest/v1/bet_posts",
    "http://localhost:55321/rest/v1/bet_posts",
    "http://127.0.0.1:54321/rest/v1/bet_posts",
    "http://example.test:55321/rest/v1/bet_posts",
    "http://127.0.0.1:55321@evil.test/rest/v1/bet_posts",
    "http://2130706433:55321/rest/v1/bet_posts",
    `${LAB_BASE_URL}/rest/v1/bet_posts#fragment`,
    `${LAB_BASE_URL}/rest/v1/../../admin`,
    `${LAB_BASE_URL}/api/state`,
    `${LAB_BASE_URL}\\@example.test/rest/v1/bet_posts`,
  ]) assert.throws(() => assertLabUrl(url), { code: "target_not_allowed" });
  assert.throws(() => createTransport({ ...keys, baseUrl: "https://production.invalid" }), { code: "target_not_allowed" });
});

test("every request disables redirects, bounds time and restricts privileged credentials", async () => {
  const calls = [];
  const request = createTransport({ ...keys, fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
  } });
  await request("/rest/v1/bet_posts", { token: "member.jwt.signature" });
  assert.equal(calls[0].options.redirect, "error");
  assert.ok(calls[0].options.signal instanceof AbortSignal);
  assert.equal(REQUEST_TIMEOUT_MS, 3000);
  assert.equal(calls[0].options.headers.apikey, keys.publishableKey);
  assert.equal(calls[0].options.headers.Authorization, "Bearer member.jwt.signature");
  await assert.rejects(request("/rest/v1/bet_posts", { admin: true }), { code: "admin_scope_not_allowed" });
  await assert.rejects(request("//evil.test/rest/v1/a"), { code: "target_not_allowed" });
  await assert.rejects(request("/rest/v1/bet_posts", { method: "DELETE" }), { code: "method_not_allowed" });
  assert.equal(calls.length, 1);
});

test("actual redirects and network errors cannot escape the lab or leak credentials", async () => {
  const redirect = createTransport({ ...keys, fetchImpl: async () => new Response(null, { status: 302, headers: { location: "https://production.invalid" } }) });
  await assert.rejects(redirect("/auth/v1/user"), { code: "redirect_not_allowed" });
  const failed = createTransport({ ...keys, fetchImpl: async () => { throw Error(keys.secretKey + " private response"); } });
  await assert.rejects(failed("/auth/v1/user"), (error) => error.code === "transport_unavailable" && !error.message.includes(keys.secretKey));
});

test("oversized responses are cancelled before accepting unbounded body data", async () => {
  const request = createTransport({ ...keys, fetchImpl: async () => new Response("x".repeat(2 * 1024 * 1024 + 1)) });
  await assert.rejects(request("/rest/v1/bet_posts"), { code: "response_too_large" });
});

test("503, expired identity and unrelated errors never pass authorization-negative checks", () => {
  for (const response of [
    reply(503, { code: "P0001", message: "Bet unavailable." }),
    reply(429, { code: "P0001", message: "Bet unavailable." }),
    reply(401, { code: "PGRST301", message: "JWT expired" }),
    reply(400, { code: "P0001", message: "Database unavailable." }),
  ]) assert.throws(() => expectSnapshotDenied(response), LabFailure);
  assert.throws(() => expectRowsHidden(reply(503, [])), LabFailure);
  assert.throws(() => expectRowsHidden(reply(200, [{ id: randomUUID() }])), LabFailure);
  assert.throws(() => expectAnonymousDenied(reply(401, { code: "PGRST301", message: "Invalid JWT" })), LabFailure);
  assert.equal(expectSnapshotDenied(denied()).outcome, "denied");
  assert.equal(expectRowsHidden(reply(200, [])).outcome, "not_visible");
  assert.equal(expectAnonymousDenied(anonymous()).response_code, "42501");
});

test("storage negative classification accepts only supported permission/not-visible codes", () => {
  for (const response of [
    invisibleImage(), reply(403, { code: "AccessDenied" }),
    reply(400, { statusCode: "404", error: "not_found" }),
    reply(403, { statusCode: "403", error: "unauthorized" }),
  ]) assert.equal(expectImageHidden(response).outcome, "not_visible");
  for (const response of [
    reply(503, { code: "NoSuchKey" }), reply(404, { code: "NoSuchBucket" }),
    reply(401, { code: "InvalidJWT" }), reply(400, { code: "InvalidMimeType" }),
    reply(500, { error: "internal_server_error" }), visibleImage(),
  ]) assert.throws(() => expectImageHidden(response), LabFailure);
});

test("the observed HTTP-400 NoSuchKey envelope requires the exact supported not-found fields", () => {
  const body = { code: "NoSuchKey", error: "not_found", statusCode: "404", message: "Object not found" };
  assert.deepEqual(expectImageHidden(reply(400, body)), {
    http_status: 400, outcome: "not_visible", response_code: "NoSuchKey",
  });
  for (const response of [
    reply(503, body), reply(429, body), reply(200, body),
    reply(400, { ...body, error: "internal_server_error" }),
    reply(400, { ...body, error: "unauthorized" }),
    reply(400, { ...body, statusCode: "503" }),
    reply(400, { ...body, statusCode: "403" }),
    reply(400, { ...body, statusCode: undefined }),
    reply(400, { ...body, error: undefined }),
    reply(400, { code: "AccessDenied", error: "unauthorized", statusCode: "403" }),
    reply(400, { ...body, code: "NoSuchBucket" }),
  ]) assert.throws(() => expectImageHidden(response), { code: "image_denial_not_established" });
});

test("file delivery requires exact bytes and type, not a successful status alone", () => {
  assert.equal(expectImageVisible(visibleImage()).content_digest, sha256(WEBP_FIXTURE));
  assert.throws(() => expectImageVisible(reply(200, {}, "application/json")), LabFailure);
  assert.throws(() => expectImageVisible(reply(200, null, "image/webp", Buffer.from("wrong image"))), LabFailure);
  assert.equal(WEBP_FIXTURE.toString("ascii", 0, 4), "RIFF");
  assert.equal(WEBP_FIXTURE.toString("ascii", 8, 12), "WEBP");
  assert.equal(WEBP_FIXTURE.readUInt32LE(4) + 8, WEBP_FIXTURE.length);
});

test("key parser reads only named local keys and rejects duplicates/interpolation", () => {
  const result = parseLabKeys(`OTHER_SECRET=ignored\nSUPABASE_AUTH_PUBLISHABLE_KEY="${keys.publishableKey}"\nSUPABASE_AUTH_SECRET_KEY='${keys.secretKey}'\n`);
  assert.deepEqual(result, keys);
  assert.throws(() => parseLabKeys("SUPABASE_AUTH_SECRET_KEY=a\nSUPABASE_AUTH_SECRET_KEY=b"), { code: "duplicate_lab_key" });
  assert.throws(() => parseLabKeys("SUPABASE_AUTH_SECRET_KEY=${OTHER}"), { code: "invalid_lab_env" });
});

function state() {
  const files = [{ file: "202609080001_foundation.sql", sha256: "b".repeat(64) }];
  return { schema_version: 1, app: "bettail", isolation_verified: true,
    migrations: { status: "passed", count: 1, source_revision: "a".repeat(40), files, digest: sha256(JSON.stringify(files)) } };
}
test("provenance requires completed isolated migrations and the exact manifest digest", () => {
  const valid = state();
  assert.deepEqual(validateProvenance(valid), { migration_digest: valid.migrations.digest });
  for (const mutate of [
    (s) => { s.isolation_verified = false; },
    (s) => { s.migrations.status = "pending"; },
    (s) => { s.migrations.count = 0; },
    (s) => { s.migrations.count = 2; },
    (s) => { s.migrations.files[0].file = "../secret.sql"; },
    (s) => { s.migrations.source_revision = "short"; },
    (s) => { s.migrations.digest = "f".repeat(64); },
  ]) { const value = state(); mutate(value); assert.throws(() => validateProvenance(value), LabFailure); }
});

test("execution evidence binds exact harness/readiness bytes and Node version without raw input", () => {
  const before = { harness_sha256: sha256("module before"), lab_state_sha256: sha256("private readiness bytes"), node_version: process.version };
  const report = { status: "passed", source: { migration_digest: "a".repeat(64) } };
  const result = finalizeExecutionEvidence(report, before, before);
  assert.equal(result.status, "passed");
  assert.deepEqual(result.source, { migration_digest: "a".repeat(64), harness_sha256: before.harness_sha256,
    lab_state_sha256: before.lab_state_sha256, harness_unchanged: true, lab_state_unchanged: true });
  assert.deepEqual(result.runtime, { node_version: process.version });
  assert.ok(!JSON.stringify(result).includes("private readiness bytes"));
});

test("changed or unavailable harness/readiness evidence invalidates passing checks", () => {
  const before = { harness_sha256: "a".repeat(64), lab_state_sha256: "b".repeat(64), node_version: process.version };
  for (const [field, prefix] of [["harness_sha256", "harness"], ["lab_state_sha256", "lab_state"]]) {
    for (const [value, suffix] of [["c".repeat(64), "changed_during_run"], [null, "unavailable_after_run"]]) {
      const result = finalizeExecutionEvidence({ status: "passed", source: {} }, before, { ...before, [field]: value });
      assert.equal(result.status, "failed");
      assert.equal(result.error_code, `${prefix}_${suffix}`);
      assert.deepEqual(result.evidence_errors, [`${prefix}_${suffix}`]);
      assert.equal(result.source[`${prefix}_unchanged`], false);
    }
  }
  const earlierFailure = finalizeExecutionEvidence({ status: "failed", source: {}, error_code: "mutation_failed" }, before, {});
  assert.equal(earlierFailure.error_code, "mutation_failed");
  assert.equal(earlierFailure.evidence_errors.length, 2);
});

/** A deliberately synthetic transport model. No service, socket, JWT signer or database is used. */
function mockLab({ afterRemoval503 = false, removeResponseLost = false, restoreFails = false, outageBeforeSetup = false } = {}) {
  const identities = {}, calls = [], privateStates = [];
  let groupId, postId, active = false, attached = false, imagePath, removed = false;
  function actor(token) { return Object.keys(identities).find((role) => identities[role].token === token); }
  const request = async (path, options = {}) => {
    calls.push({ path, options });
    if (outageBeforeSetup) return reply(503, { code: "InternalError" });
    const role = actor(options.token);
    if (path === "/auth/v1/admin/users") {
      const role = options.json.email.split("-")[0];
      const id = randomUUID();
      const payload = Buffer.from(JSON.stringify({ sub: id, role: "authenticated" })).toString("base64url");
      identities[role] = { id, token: `mockheader.${payload}.mocksignature` };
      return reply(200, { id: identities[role].id });
    }
    if (path.startsWith("/auth/v1/token?")) {
      const role = options.json.email.split("-")[0];
      return reply(200, { access_token: identities[role].token, user: { id: identities[role].id } });
    }
    if (path === "/auth/v1/user") return reply(200, { id: identities[role].id });
    if (path === "/rest/v1/rpc/bt_mutate") {
      const { action, data } = options.json;
      if (action === "profile") return reply(200, {});
      if (action === "create_group") { groupId = randomUUID(); return reply(200, { group_id: groupId }); }
      if (action === "create_invite") return reply(200, { code: "synthetic-invite" });
      if (action === "join_group") { active = true; return reply(200, { group_id: groupId }); }
      if (action === "post") { postId = randomUUID(); return reply(200, { post_id: postId }); }
      if (action === "comment") { attached = true; return reply(200, {}); }
      if (action === "remove_member") {
        assert.equal(role, "owner"); assert.equal(data.member_id, identities.member.id);
        active = false; removed = true;
        if (removeResponseLost) throw new LabFailure("transport_unavailable");
        return reply(200, {});
      }
      if (action === "restore_member") {
        if (restoreFails) return reply(503, {});
        active = true; return reply(200, {});
      }
    }
    if (path.startsWith("/rest/v1/bet_posts?")) {
      if (!role) return anonymous();
      if (afterRemoval503 && removed && !active && role === "member") return reply(503, []);
      return reply(200, role === "owner" || (role === "member" && active)
        ? [{ id: postId, title: "Synthetic SignalBridge private pick" }] : []);
    }
    if (path === "/rest/v1/rpc/bt_snapshot") {
      if (!role) return anonymous();
      return role === "owner" || (role === "member" && active)
        ? reply(200, { group: { id: groupId }, posts: [{ id: postId, title: "Synthetic SignalBridge private pick" }] }) : denied();
    }
    if (path === "/rest/v1/rpc/bt_prepare_chat_image") {
      imagePath = `${groupId}/${identities.owner.id}/${options.json.upload_id}.webp`;
      return reply(200, imagePath);
    }
    if (path.startsWith("/storage/v1/object/chat-images/")) {
      assert.equal(path, `/storage/v1/object/chat-images/${imagePath}`);
      if (options.method === "POST") { assert.deepEqual(options.bytes, WEBP_FIXTURE); return reply(200, {}); }
      return role === "owner" || (role === "member" && active && attached) ? visibleImage() : invisibleImage();
    }
    if (path.startsWith("/rest/v1/comments?")) return reply(200, [{ id: randomUUID() }]);
    throw new LabFailure("unexpected_mock_request");
  };
  return { request, calls, identities, privateStates, savePrivate: async (data) => privateStates.push(structuredClone(data)),
    get active() { return active; } };
}

test("full mocked flow covers genuine-call boundaries, same-token removal and positive restoration", async () => {
  const lab = mockLab();
  const report = await runLab({ ...lab, provenance: { migration_digest: "a".repeat(64) } });
  assert.equal(report.status, "passed");
  assert.equal(report.restoration.status, "restored_and_retested");
  assert.ok(lab.active);
  assert.ok(report.checks.some((item) => item.id === "member_unattached_draft_hidden" && item.status === "passed"));
  assert.ok(report.checks.some((item) => item.id === "removed_member_same_jwt_still_valid" && item.status === "passed"));
  assert.ok(report.checks.some((item) => item.id === "restored_member_image_visible" && item.status === "passed"));
  assert.ok(report.limitations.some((text) => text.includes("Next application routes were not exercised")));
  assert.equal(lab.privateStates.at(-1).restore_required, false);
  const json = JSON.stringify(report);
  for (const identity of Object.values(lab.identities)) {
    assert.ok(!json.includes(identity.id)); assert.ok(!json.includes(identity.token));
  }
  assert.ok(!json.includes("@example.test")); assert.ok(!json.includes('"password":'));
  for (const identity of Object.values(lab.privateStates.at(-1).actors)) assert.ok(!json.includes(identity.password));
  for (const pseudonym of Object.values(report.identities)) assert.match(pseudonym, /^[0-9a-f]{64}$/);
  for (const call of lab.calls.filter((call) => call.options.admin)) assert.equal(call.path, "/auth/v1/admin/users");
});

test("503 after removal fails the check and still restores/retests in finally", async () => {
  const lab = mockLab({ afterRemoval503: true });
  const report = await runLab({ ...lab, provenance: { migration_digest: "a".repeat(64) } });
  assert.equal(report.status, "failed");
  assert.equal(report.restoration.status, "restored_and_retested");
  assert.equal(report.checks.find((item) => item.id === "removed_member_exact_row_hidden").status, "failed");
  assert.ok(lab.active);
});

test("lost removal response still triggers restoration because the mutation may have committed", async () => {
  const lab = mockLab({ removeResponseLost: true });
  const report = await runLab({ ...lab, provenance: { migration_digest: "a".repeat(64) } });
  assert.equal(report.status, "failed");
  assert.equal(report.restoration.status, "restored_and_retested");
  assert.ok(lab.active);
});

test("failed restoration remains failed and leaves a private recovery marker", async () => {
  const lab = mockLab({ restoreFails: true });
  const report = await runLab({ ...lab, provenance: { migration_digest: "a".repeat(64) } });
  assert.equal(report.status, "failed");
  assert.equal(report.restoration.status, "restore_or_retest_failed");
  assert.equal(lab.privateStates.at(-1).restore_required, true);
  assert.ok(!lab.active);
});

test("setup outage cannot produce passing coverage or pretend later checks ran", async () => {
  const lab = mockLab({ outageBeforeSetup: true });
  const report = await runLab({ ...lab, provenance: { migration_digest: "a".repeat(64) } });
  assert.equal(report.status, "failed");
  assert.equal(report.checks.length, 1);
  assert.equal(report.checks[0].status, "failed");
  assert.equal(report.restoration.status, "not_needed");
});
