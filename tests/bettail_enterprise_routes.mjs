// Execute the two actual patched handlers offline with modeled Supabase/storage.
// stdin: verified source text; argv[2]: existing frozen runtime dependency folder.
// This proves route wiring, not real authentication, SQL permissions or storage.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
const require = createRequire(path.resolve(process.argv[2], "package.json"));
const ts = require("typescript");
const z = require("zod");
const files = JSON.parse(fs.readFileSync(0, "utf8"));
assert.deepEqual(Object.keys(files).sort(), ["image", "state"]);
const actor = "10000000-0000-4000-8000-000000000001";
const post = "20000000-0000-4000-8000-000000000001";
const comment = "20000000-0000-4000-8000-000000000002";
let controls = 0;
function load(source, client, observe) {
  const exports = {};
  const imports = {
    "zod": z, "@/lib/supabase/server": { serverClient: async () => client },
    "@/lib/sport-catalog": { canonicalSport: v => v },
    "@/lib/last-group": { lastGroup: () => "", lastGroupCookie: () => "" },
    "@/lib/auth-error-status": { authErrorStatus: e => e ? 503 : 401 },
    "@/lib/signalbridge/telemetry": { observeAccess: observe },
    "@/lib/request-origin": {}, "@/lib/request-body": {}, "@/lib/chat-photo": {},
    "@/lib/deleted-group-files": {}, "@/lib/chat-media-server": {},
  };
  const code = ts.transpileModule(source, { compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS,
  }, reportDiagnostics: true });
  assert.equal(code.diagnostics.length, 0);
  vm.runInNewContext(code.outputText, { exports, URL, Response, Headers,
    require: name => { assert.ok(Object.hasOwn(imports, name), "unreviewed import"); return imports[name]; } },
  { timeout: 1000 });
  return exports.GET;
}
async function stateTest(snapshot, expectedStatus, expectedOutcome, options = {}) {
  const notes = [];
  const client = {
    auth: { getUser: async () => options.auth ?? ({ data: { user: { id: actor } }, error: null }) },
    rpc: async (name, args) => {
      if (name !== "bt_snapshot") return { data: false, error: null };
      assert.equal(args.options.observed_outcome, undefined);
      if (options.rpcThrows) throw Error("synthetic unavailable dependency");
      return snapshot;
    },
    from: () => ({ select: () => ({ eq: () => ({ in: async () => ({ data: [] }) }) }) }),
  };
  const get = load(files.state, client, async (...args) => { notes.push(args); if (options.failRecorder) throw Error("unavailable"); });
  const response = await get(new Request(`https://lab.invalid/api/state?post_id=${options.invalidQuery ? "invalid" : post}&observed_outcome=allowed`));
  assert.equal(response.status, expectedStatus);
  assert.equal(notes[0]?.[4], expectedOutcome);
  assert.equal(notes.length, expectedOutcome === undefined ? 0 : 1);
  if (notes.length) {
    assert.equal(notes[0][1], actor);
    assert.equal(notes[0][3], post);
  }
  controls++;
}
await stateTest({ data: { posts: [{ id: post }] }, error: null }, 200, "allowed");
await stateTest({ data: { posts: [] }, error: null }, 200, "not_visible");
await stateTest({ data: { posts: [{ id: comment, source_post_id: post }] }, error: null }, 200, "not_visible");
for (const message of ["Bet unavailable.", "Group unavailable."]) {
  await stateTest({ data: null, error: { code: "P0001", message } }, 403, "denied");
}
for (const error of [
  { code: "P0001", message: "Unexpected source failure." },
  { code: "42501", message: "Bet unavailable." },
  { code: "42501", message: "permission denied for function bt_snapshot" },
  { code: "PGRST301", message: "JWT expired" },
  { code: "P0001" },
]) await stateTest({ data: null, error }, 503, "error");
await stateTest({ data: null, error: { code: "08006" } }, 503, "error");
await stateTest({ data: { posts: [{ id: post }] }, error: null }, 503, "allowed", { failRecorder: true });
await stateTest(null, 503, undefined, { rpcThrows: true });
await stateTest(null, 400, undefined, { invalidQuery: true });
await stateTest(null, 401, undefined, { auth: { data: { user: null }, error: null } });
await stateTest(null, 503, undefined, { auth: { data: { user: null }, error: { status: 503 } } });

async function imageTest(stage, expectedStatus, expectedOutcome, options = {}) {
  const notes = [];
  let downloaded = false;
  const commentResult = stage === "query_error" ? { data: null, error: { code: "08006" } } :
    { data: stage === "hidden" ? null : { image_id: post }, error: null };
  const client = {
    auth: { getUser: async () => ({ data: { user: options.anonymous ? null : { id: actor } } }) },
    from: () => ({ select: () => ({ eq: () => ({ is: () => ({ maybeSingle: async () => commentResult }) }) }) }),
    rpc: async () => stage === "path_error" ? { data: null, error: { code: "08006" } } :
      { data: stage === "hidden_path" ? null : "synthetic/path.webp", error: null },
    storage: { from: () => ({ download: async () => {
      downloaded = true;
      return stage === "storage_error" ? { data: null, error: { code: "503" } } :
        { data: new Blob(["synthetic bytes"]), error: null };
    } }) },
  };
  const get = load(files.image, client, async (...args) => {
    if (args[4] === "allowed") assert.equal(downloaded, true);
    notes.push(args); if (options.failRecorder) throw Error("unavailable");
  });
  const response = await get(new Request(`https://lab.invalid/api/chat-image?comment_id=${options.invalidId ? "invalid" : comment}${options.scope ? `&scope=${options.scope}` : ""}`));
  assert.equal(response.status, expectedStatus);
  assert.equal(notes[0]?.[4], expectedOutcome);
  assert.equal(notes.length, expectedOutcome === undefined ? 0 : 1);
  if (notes.length) {
    assert.equal(notes[0][1], actor);
    assert.equal(notes[0][3], comment);
  }
  if (expectedStatus === 200) assert.equal(await response.text(), "synthetic bytes");
  controls++;
}
await imageTest("allowed", 200, "allowed");
await imageTest("hidden", 404, "not_visible");
await imageTest("query_error", 503, "error");
await imageTest("path_error", 503, "error");
await imageTest("hidden_path", 404, "not_visible");
await imageTest("storage_error", 503, "error");
await imageTest("allowed", 503, "allowed", { failRecorder: true });
await imageTest("allowed", 401, undefined, { anonymous: true });
await imageTest("allowed", 400, undefined, { invalidId: true });
await imageTest("allowed", 400, undefined, { scope: "invalid" });
await imageTest("allowed", 200, undefined, { scope: "group" });
await imageTest("allowed", 200, undefined, { scope: "dm" });
console.log(JSON.stringify({ offline_handler_controls: controls, native_proof: false }));
