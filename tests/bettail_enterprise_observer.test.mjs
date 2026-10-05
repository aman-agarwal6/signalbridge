import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { observer, attestationText, validateConfiguration } from "../integrations/bettail_enterprise/observer.mjs";

// Deterministic nonfunctional test material; never an installed lab credential.
const key = "01".repeat(32);
const actor = "10000000-0000-4000-8000-000000000001";
const post = "20000000-0000-4000-8000-000000000001";
const image = "20000000-0000-4000-8000-000000000002";
const config = () => ({ profile: "bettail-access-v1", observer_key: key,
  watched: [{ kind: "post", ref: post }, { kind: "image", ref: image }] });

test("a watched actual result is signed for the authenticated actor and exact resource", async () => {
  let packet;
  const client = { rpc: async (name, args) => {
    assert.equal(name, "sb_bettail_observe"); packet = args;
    return { data: { event_id: args.event_id, status: "recorded" }, error: null };
  } };
  await observer(config())(client, actor, "post", post, "allowed");
  const original = attestationText(packet.event_id, actor, "post", post, packet.observed_at, "allowed");
  const proof = text => createHmac("sha256", Buffer.from(key, "hex")).update(text).digest("hex");
  assert.equal(packet.proof, proof(original));
  for (const change of [original.replace(actor, image), original.replace(post, image),
    original.replace("allowed\nmember", "error\ndependency_unavailable")]) {
    assert.notEqual(proof(change), packet.proof);
  }
  assert.equal(Object.keys(packet).sort().join(), "event_id,observed_at,observed_outcome,proof,resource_kind,resource_ref");
});

test("an unwatched publication does not inherit another post's telemetry identity", async () => {
  await observer(config())({ rpc: () => { throw Error("must not be called"); } }, actor,
    "post", "20000000-0000-4000-8000-000000000099", "allowed");
});

test("invalid and duplicate watched configuration is rejected", () => {
  const bad = config(); bad.watched[1] = { ...bad.watched[0] };
  assert.throws(() => validateConfiguration(bad));
  assert.throws(() => validateConfiguration({ ...config(), unexpected: "field" }));
  assert.throws(() => validateConfiguration({ ...config(), observer_key: "bad" }));
});

test("an unretained observation fails closed instead of returning success", async () => {
  for (const response of [{ data: null, error: { message: "synthetic failure" } },
    { data: { event_id: post, status: "recorded" }, error: null }]) {
    await assert.rejects(observer(config())({ rpc: async () => response }, actor, "image", image, "allowed"));
  }
});

test("unknown outcomes and actor injection are rejected before RPC", async () => {
  const client = { rpc: () => { throw Error("must not be called"); } };
  await assert.rejects(observer(config())(client, actor + "\ninjected", "post", post, "allowed"));
  await assert.rejects(observer(config())(client, actor, "post", post, "policy_regression"));
});
