/** Fixed BetTail Auth/PostgREST/Storage lab. Importing this module never starts a run. */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFile, realpath, mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const LAB_BASE_URL = "http://127.0.0.1:55321";
export const REQUEST_TIMEOUT_MS = 3000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/;
const TITLE = "Synthetic SignalBridge private pick";
// Synthetic one-pixel WebP protocol fixture. No user image or external asset is used.
export const WEBP_FIXTURE = Buffer.from(
  "UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA", "base64",
);
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export class LabFailure extends Error {
  constructor(code) {
    super(`Local HTTP lab failed: ${code}.`);
    this.name = "LabFailure";
    this.code = code;
  }
}
const requireThat = (condition, code) => { if (!condition) throw new LabFailure(code); };
const safeCode = (error) => error instanceof LabFailure ? error.code : "unexpected_error";
const validUser = (value) => value && typeof value === "object" && UUID.test(value.id);

function ordinaryAccessToken(token, userId) {
  if (typeof token !== "string" || token.split(".").length !== 3) return false;
  try {
    const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    return claims.sub === userId && claims.role === "authenticated";
  } catch { return false; }
}

export function assertLabUrl(value) {
  requireThat(typeof value === "string" && value.startsWith(`${LAB_BASE_URL}/`), "target_not_allowed");
  let url;
  try { url = new URL(value); } catch { throw new LabFailure("target_not_allowed"); }
  requireThat(
    url.origin === LAB_BASE_URL && !url.username && !url.password && !url.hash &&
      !value.includes("\\") && /^\/(auth|rest|storage)\/v1\//.test(url.pathname),
    "target_not_allowed",
  );
  return url;
}

async function boundedBody(response) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new LabFailure("response_too_large");
      }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks);
}

export function createTransport({ publishableKey, secretKey, fetchImpl = globalThis.fetch, baseUrl = LAB_BASE_URL }) {
  requireThat(baseUrl === LAB_BASE_URL, "target_not_allowed");
  for (const key of [publishableKey, secretKey]) {
    requireThat(typeof key === "string" && key.length >= 20 && key.length <= 8192 && !/[\s\r\n]/.test(key), "invalid_lab_keys");
  }
  return async function request(path, { method = "GET", token, admin = false, json, bytes } = {}) {
    requireThat(typeof path === "string" && path.startsWith("/") && !path.startsWith("//"), "target_not_allowed");
    const url = assertLabUrl(baseUrl + path);
    requireThat(["GET", "POST"].includes(method), "method_not_allowed");
    requireThat(!admin || (method === "POST" && url.pathname === "/auth/v1/admin/users" && !url.search), "admin_scope_not_allowed");
    requireThat(!(json !== undefined && bytes !== undefined), "invalid_request_body");
    if (token !== undefined) requireThat(typeof token === "string" && !/[\s\r\n]/.test(token), "invalid_actor_token");
    const key = admin ? secretKey : publishableKey;
    const headers = { apikey: key, Authorization: `Bearer ${admin ? secretKey : token || publishableKey}` };
    if (json !== undefined) headers["Content-Type"] = "application/json";
    if (bytes !== undefined) {
      requireThat(Buffer.isBuffer(bytes) && bytes.length <= 262144, "invalid_image_body");
      headers["Content-Type"] = "image/webp";
      headers["x-upsert"] = "false";
    }
    try {
      const response = await fetchImpl(url.href, {
        method, headers, redirect: "error", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        body: json !== undefined ? JSON.stringify(json) : bytes,
      });
      requireThat(!response.redirected && !(response.status >= 300 && response.status < 400), "redirect_not_allowed");
      const raw = await boundedBody(response);
      let data = null;
      try { data = JSON.parse(raw.toString("utf8")); } catch { /* Binary and error bodies stay private. */ }
      return { status: response.status, data, bytes: raw, contentType: response.headers.get("content-type") || "" };
    } catch (error) {
      if (error instanceof LabFailure) throw error;
      throw new LabFailure("transport_unavailable");
    }
  };
}

export function expectRowsVisible(response, postId) {
  requireThat(response.status === 200 && Array.isArray(response.data) && response.data.length === 1 &&
    response.data[0].id === postId && response.data[0].title === TITLE, "private_row_not_visible");
  return { http_status: response.status, outcome: "allowed" };
}
export function expectRowsHidden(response) {
  requireThat(response.status === 200 && Array.isArray(response.data) && response.data.length === 0, "private_row_not_filtered");
  return { http_status: response.status, outcome: "not_visible" };
}
export function expectSnapshotVisible(response, postId, groupId) {
  requireThat(response.status === 200 && response.data?.group?.id === groupId &&
    Array.isArray(response.data.posts) && response.data.posts.length === 1 &&
    response.data.posts[0].id === postId && response.data.posts[0].title === TITLE, "snapshot_not_visible");
  return { http_status: response.status, outcome: "allowed" };
}
export function expectSnapshotDenied(response) {
  const messages = ["Bet unavailable.", "Group unavailable.", "This group or bet is unavailable.", "This record is unavailable."];
  requireThat(response.status === 400 && response.data?.code === "P0001" && messages.includes(response.data.message), "snapshot_denial_not_established");
  return { http_status: response.status, outcome: "denied", response_code: "P0001" };
}
export function expectAnonymousDenied(response) {
  requireThat([401, 403].includes(response.status) && response.data?.code === "42501" &&
    typeof response.data.message === "string" && /permission denied/i.test(response.data.message), "anonymous_denial_not_established");
  return { http_status: response.status, outcome: "denied", response_code: "42501" };
}
export function expectImageVisible(response) {
  requireThat(response.status === 200 && response.contentType.split(";")[0].trim() === "image/webp" &&
    Buffer.isBuffer(response.bytes) && sha256(response.bytes) === sha256(WEBP_FIXTURE), "private_image_not_visible");
  return { http_status: response.status, outcome: "allowed", content_digest: sha256(WEBP_FIXTURE) };
}
export function expectImageHidden(response) {
  const code = response.data?.code || response.data?.error;
  const modern = (response.status === 404 && code === "NoSuchKey") || (response.status === 403 && code === "AccessDenied");
  // Observed from the isolated Storage service: a modern object code inside the
  // legacy HTTP-400 envelope. Do not accept arbitrary HTTP-400 or AccessDenied bodies.
  const mixedNotFound = response.status === 400 && response.data?.code === "NoSuchKey" &&
    response.data.error === "not_found" && response.data.statusCode === "404";
  const legacy = [400, 403, 404].includes(response.status) &&
    ((code === "not_found" && [undefined, 404, "404"].includes(response.data?.statusCode)) ||
     (code === "unauthorized" && [undefined, 403, "403"].includes(response.data?.statusCode)));
  requireThat(modern || mixedNotFound || legacy, "image_denial_not_established");
  return { http_status: response.status, outcome: "not_visible", response_code: code };
}

export function validateProvenance(state) {
  requireThat(state && state.schema_version === 1 && state.app === "bettail" &&
    state.isolation_verified === true && state.migrations?.status === "passed", "lab_state_not_ready");
  const migration = state.migrations;
  requireThat(Number.isInteger(migration.count) && migration.count > 0 && migration.count <= 1000 &&
    /^[0-9a-f]{40}$/.test(migration.source_revision) && DIGEST.test(migration.digest) &&
    Array.isArray(migration.files) && migration.files.length === migration.count, "invalid_migration_manifest");
  const names = new Set();
  for (const row of migration.files) {
    requireThat(row && typeof row === "object" && Object.keys(row).length === 2 &&
      /^\d{12,14}_[a-z0-9_]+\.sql$/.test(row.file) && DIGEST.test(row.sha256) && !names.has(row.file), "invalid_migration_manifest");
    names.add(row.file);
  }
  requireThat(sha256(JSON.stringify(migration.files)) === migration.digest, "migration_manifest_digest_mismatch");
  return { migration_digest: migration.digest };
}

/** Runs against an injected fixed transport. Report contains no raw identities or response bodies. */
export async function runLab({ request, provenance, savePrivate = async () => {}, runId = randomUUID() }) {
  requireThat(UUID.test(runId) && provenance && DIGEST.test(provenance.migration_digest), "invalid_run_provenance");
  const clock = performance.now();
  const report = {
    schema_version: 1, app: "bettail", environment: "isolated_supabase_http", run_id: runId,
    started_at: new Date().toISOString(), status: "running", source: { migration_digest: provenance.migration_digest },
    checks: [], identities: {}, restoration: { required: false, attempted: false, status: "not_needed" },
    limitations: [
      "Next application routes were not exercised; these are direct Auth, PostgREST and Storage HTTP checks.",
      "Administrative email confirmation does not test email delivery or ownership verification.",
      "No policy fault was introduced; no signed-URL revocation, source-route emitter or outbox was tested.",
      "The source binding is the supplied migration manifest digest; it is not a claim that a Next source snapshot ran.",
    ],
  };
  const actors = {};
  let groupId, postId, imagePath, commentId, restoreRequired = false;
  const persist = () => savePrivate({ schema_version: 1, run_id: runId, actors, group_id: groupId, post_id: postId,
    image_path: imagePath, comment_id: commentId, restore_required: restoreRequired });
  async function check(id, stage, operation) {
    const started = performance.now();
    try {
      const detail = await operation();
      report.checks.push({ id, stage, status: "passed", duration_ms: Math.round(performance.now() - started), ...detail });
    } catch (error) {
      report.checks.push({ id, stage, status: "failed", duration_ms: Math.round(performance.now() - started), error_code: safeCode(error) });
      throw error;
    }
  }
  const rpc = (actor, name, json) => request(`/rest/v1/rpc/${name}`, { method: "POST", token: actors[actor].token, json });
  async function mutate(actor, action, data) {
    const response = await rpc(actor, "bt_mutate", { action, data, request_id: randomUUID() });
    requireThat(response.status === 200 && response.data && typeof response.data === "object" && !response.data.error, "mutation_failed");
    return response.data;
  }
  const rows = (actor) => request(`/rest/v1/bet_posts?id=eq.${postId}&select=id,title`, { token: actor ? actors[actor].token : undefined });
  const snapshot = (actor) => rpc(actor, "bt_snapshot", { options: { group_id: groupId, post_id: postId } });
  const image = (actor) => request(`/storage/v1/object/chat-images/${imagePath}`, { token: actors[actor].token });
  async function verifyUser(actor) {
    const response = await request("/auth/v1/user", { token: actors[actor].token });
    requireThat(response.status === 200 && validUser(response.data) && response.data.id === actors[actor].id, "issued_jwt_not_verified");
    return { http_status: response.status, outcome: "authenticated" };
  }
  try {
    for (const role of ["owner", "member", "outsider"]) {
      actors[role] = { email: `${role}-${runId}@example.test`, password: randomBytes(30).toString("base64url") };
      await persist();
      await check(`${role}_auth_creation_and_password_login`, "setup", async () => {
        const actor = actors[role];
        const created = await request("/auth/v1/admin/users", { method: "POST", admin: true,
          json: { email: actor.email, password: actor.password, email_confirm: true } });
        requireThat([200, 201].includes(created.status) && validUser(created.data), "auth_user_creation_failed");
        actor.id = created.data.id;
        const login = await request("/auth/v1/token?grant_type=password", { method: "POST", json: { email: actor.email, password: actor.password } });
        requireThat(login.status === 200 && validUser(login.data?.user) && login.data.user.id === actor.id &&
          ordinaryAccessToken(login.data.access_token, actor.id), "password_login_failed");
        actor.token = login.data.access_token;
        await persist();
        report.identities[role] = sha256(runId + ":" + actor.id);
        return verifyUser(role);
      });
      await check(`${role}_profile_ready`, "setup", async () => {
        await mutate(role, "profile", { display_name: "Synthetic lab member", username: `lab_${actorId(role).replaceAll("-", "").slice(0, 24)}`,
          timezone: "UTC", unit_cents: 2000, preferences: {} });
        return { outcome: "profile_completed" };
      });
    }
    await check("synthetic_group_and_pick_seeded", "setup", async () => {
      groupId = (await mutate("owner", "create_group", { name: "SignalBridge isolated lab" })).group_id;
      requireThat(UUID.test(groupId), "group_creation_failed");
      await persist();
      const invite = await mutate("owner", "create_invite", { group_id: groupId, max_uses: 2, days: 1 });
      requireThat(typeof invite.code === "string" && invite.code.length <= 100, "invite_creation_failed");
      const joined = await mutate("member", "join_group", { code: invite.code });
      requireThat(joined.group_id === groupId, "membership_creation_failed");
      postId = (await mutate("owner", "post", { group_id: groupId, title: TITLE, selection: "Synthetic team", market: "spread", line: "+3.5",
        sport: "NFL", league: "NFL", event_name: "Synthetic A vs B", event_start_time: "2030-09-10T00:20:00Z", bet_type: "spread",
        sportsbook: "draftkings", sportsbook_url: "", accepted_odds: -110, stake_cents: 2000, legs: [] })).post_id;
      requireThat(UUID.test(postId), "pick_creation_failed");
      await persist();
      return { outcome: "synthetic_fixture_ready" };
    });
    for (const actor of ["owner", "member"]) {
      await check(`${actor}_exact_row_visible`, "assertion", async () => expectRowsVisible(await rows(actor), postId));
      await check(`${actor}_snapshot_visible`, "assertion", async () => expectSnapshotVisible(await snapshot(actor), postId, groupId));
    }
    await check("outsider_exact_row_hidden", "assertion", async () => expectRowsHidden(await rows("outsider")));
    await check("outsider_snapshot_denied", "assertion", async () => expectSnapshotDenied(await snapshot("outsider")));
    await check("anonymous_table_read_denied", "assertion", async () => expectAnonymousDenied(await rows(null)));
    await check("anonymous_snapshot_denied", "assertion", async () => expectAnonymousDenied(await request("/rest/v1/rpc/bt_snapshot", {
      method: "POST", json: { options: { group_id: groupId, post_id: postId } },
    })));
    const imageId = randomUUID();
    await check("private_image_reserved_and_uploaded", "setup", async () => {
      const reserved = await rpc("owner", "bt_prepare_chat_image", { p_id: postId, upload_id: imageId });
      const expected = `${groupId}/${actorId("owner")}/${imageId}.webp`;
      requireThat(reserved.status === 200 && reserved.data === expected, "image_reservation_failed");
      imagePath = expected;
      await persist();
      const uploaded = await request(`/storage/v1/object/chat-images/${imagePath}`, { method: "POST", token: actors.owner.token, bytes: WEBP_FIXTURE });
      requireThat([200, 201].includes(uploaded.status), "image_upload_failed");
      return { http_status: uploaded.status, outcome: "private_object_created", content_digest: sha256(WEBP_FIXTURE) };
    });
    await check("owner_draft_image_visible", "assertion", async () => expectImageVisible(await image("owner")));
    await check("member_unattached_draft_hidden", "assertion", async () => expectImageHidden(await image("member")));
    await check("owner_image_attached_to_comment", "setup", async () => {
      await mutate("owner", "comment", { post_id: postId, text: "Synthetic image", image_id: imageId });
      const response = await request(`/rest/v1/comments?image_id=eq.${imageId}&select=id`, { token: actors.owner.token });
      requireThat(response.status === 200 && Array.isArray(response.data) && response.data.length === 1 && UUID.test(response.data[0].id), "image_comment_not_found");
      commentId = response.data[0].id;
      await persist();
      return { outcome: "attachment_recorded" };
    });
    for (const actor of ["owner", "member"]) await check(`${actor}_attached_image_visible`, "assertion", async () => expectImageVisible(await image(actor)));
    await check("outsider_attached_image_hidden", "assertion", async () => expectImageHidden(await image("outsider")));
    restoreRequired = true;
    report.restoration.required = true;
    await persist(); // Removal may commit even if its HTTP response is interrupted.
    await check("member_removed", "setup", async () => {
      await mutate("owner", "remove_member", { group_id: groupId, member_id: actorId("member") });
      return { outcome: "membership_removed" };
    });
    await check("removed_member_same_jwt_still_valid", "assertion", () => verifyUser("member"));
    await check("removed_member_exact_row_hidden", "assertion", async () => expectRowsHidden(await rows("member")));
    await check("removed_member_snapshot_denied", "assertion", async () => expectSnapshotDenied(await snapshot("member")));
    await check("removed_member_new_image_request_hidden", "assertion", async () => expectImageHidden(await image("member")));
    await check("owner_read_survives_removal", "assertion", async () => expectRowsVisible(await rows("owner"), postId));
  } catch (error) {
    report.status = "failed";
    report.error_code = safeCode(error);
  } finally {
    if (restoreRequired) {
      report.restoration.attempted = true;
      try {
        await check("membership_restored", "restoration", async () => {
          await mutate("owner", "restore_member", { group_id: groupId, member_id: actorId("member") });
          return { outcome: "membership_restored" };
        });
        await check("restored_member_exact_row_visible", "restoration", async () => expectRowsVisible(await rows("member"), postId));
        await check("restored_member_snapshot_visible", "restoration", async () => expectSnapshotVisible(await snapshot("member"), postId, groupId));
        await check("restored_member_image_visible", "restoration", async () => expectImageVisible(await image("member")));
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
  report.duration_ms = Math.round(performance.now() - clock);
  return report;
  function actorId(role) { return actors[role].id; }
}

export function parseLabKeys(text) {
  requireThat(typeof text === "string" && Buffer.byteLength(text) <= 65536, "invalid_lab_env");
  const wanted = new Set(["SUPABASE_AUTH_PUBLISHABLE_KEY", "SUPABASE_AUTH_SECRET_KEY"]);
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || !wanted.has(match[1])) continue;
    requireThat(values[match[1]] === undefined, "duplicate_lab_key");
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    requireThat(!value.includes("$") && !value.includes("\\"), "invalid_lab_env");
    values[match[1]] = value;
  }
  return { publishableKey: values.SUPABASE_AUTH_PUBLISHABLE_KEY, secretKey: values.SUPABASE_AUTH_SECRET_KEY };
}

/** Pure metadata finalizer; missing/changed input evidence cannot produce a passed run. */
export function finalizeExecutionEvidence(report, before, after) {
  requireThat(DIGEST.test(before.harness_sha256) && DIGEST.test(before.lab_state_sha256) &&
    /^v\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(before.node_version), "invalid_execution_evidence");
  report.source.harness_sha256 = before.harness_sha256;
  report.source.lab_state_sha256 = before.lab_state_sha256;
  report.source.harness_unchanged = after.harness_sha256 === before.harness_sha256;
  report.source.lab_state_unchanged = after.lab_state_sha256 === before.lab_state_sha256;
  report.runtime = { node_version: before.node_version };
  const failures = [];
  for (const [name, field] of [["harness", "harness_sha256"], ["lab_state", "lab_state_sha256"]]) {
    if (!DIGEST.test(after[field])) failures.push(`${name}_unavailable_after_run`);
    else if (after[field] !== before[field]) failures.push(`${name}_changed_during_run`);
  }
  if (failures.length) {
    report.status = "failed";
    report.evidence_errors = failures;
    report.error_code ??= failures[0];
  }
  return report;
}

export async function main(argv = process.argv.slice(2)) {
  requireThat(!["1", "true"].includes(process.env.NODE_USE_ENV_PROXY?.toLowerCase()) &&
    !process.execArgv.includes("--use-env-proxy") && !process.env.NODE_OPTIONS?.includes("--use-env-proxy"), "proxy_configuration_not_allowed");
  const harnessPath = fileURLToPath(import.meta.url);
  const root = resolve(dirname(harnessPath), "..");
  const labDir = join(root, "var", "labs", "bettail");
  requireThat(argv.length === 0 || (argv.length === 1 && resolve(argv[0]) === labDir), "lab_directory_not_allowed");
  requireThat(await realpath(labDir) === labDir, "lab_directory_not_allowed");
  const statePath = join(labDir, "lab-state.json");
  requireThat(await realpath(harnessPath) === harnessPath && await realpath(statePath) === statePath, "evidence_path_not_allowed");
  const harnessBytes = await readFile(harnessPath);
  const stateBytes = await readFile(statePath);
  const executionBefore = { harness_sha256: sha256(harnessBytes), lab_state_sha256: sha256(stateBytes), node_version: process.version };
  requireThat(stateBytes.byteLength <= MAX_RESPONSE_BYTES, "lab_state_too_large");
  const state = JSON.parse(stateBytes.toString("utf8"));
  const provenance = validateProvenance(state);
  const keys = parseLabKeys(await readFile(join(labDir, ".env"), "utf8"));
  const request = createTransport(keys);
  const runId = randomUUID();
  const outputDir = join(labDir, "http-runs");
  await mkdir(outputDir, { recursive: true });
  requireThat(await realpath(outputDir) === outputDir, "lab_directory_not_allowed");
  const report = await runLab({ request, provenance, runId, savePrivate: async (data) => {
    await writeFile(join(outputDir, `${runId}.private.json`), JSON.stringify(data, null, 2), { mode: 0o600 });
  } });
  async function finalDigest(path) {
    try { return await realpath(path) === path ? sha256(await readFile(path)) : null; }
    catch { return null; }
  }
  finalizeExecutionEvidence(report, executionBefore, {
    harness_sha256: await finalDigest(harnessPath), lab_state_sha256: await finalDigest(statePath),
  });
  await writeFile(join(outputDir, `${runId}.json`), JSON.stringify(report, null, 2), { flag: "wx" });
  process.stdout.write(`BetTail local HTTP lab ${report.status}; ${report.checks.filter((item) => item.status === "passed").length}/${report.checks.length} executed checks passed. Run ${runId}.\n`);
  if (report.status !== "passed") process.exitCode = 1;
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`BetTail local HTTP lab stopped: ${safeCode(error)}. No success claimed.\n`);
    process.exitCode = 1;
  });
}
