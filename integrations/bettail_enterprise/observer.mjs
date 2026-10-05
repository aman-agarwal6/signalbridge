// Server-only implementation. The TS entry point imports `server-only`.
import { createHmac, randomUUID } from "node:crypto";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RESULT = Object.freeze({
  allowed: "member",
  denied: "membership_required",
  not_visible: "resource_unavailable",
  error: "dependency_unavailable",
});

export function validateConfiguration(value) {
  if (!value || Object.keys(value).sort().join() !== "observer_key,profile,watched" ||
      value.profile !== "bettail-access-v1" ||
      !/^[0-9a-f]{64}$/.test(value.observer_key) ||
      !Array.isArray(value.watched) || ![2, 4].includes(value.watched.length)) {
    throw new Error("Invalid isolated BetTail observation configuration.");
  }
  const seen = new Set();
  for (const row of value.watched) {
    if (!row || Object.keys(row).sort().join() !== "kind,ref" ||
        !["post", "image"].includes(row.kind) || !UUID.test(row.ref) ||
        seen.has(`${row.kind}:${row.ref}`)) {
      throw new Error("Invalid isolated BetTail watched resource.");
    }
    seen.add(`${row.kind}:${row.ref}`);
  }
  return value;
}

export function attestationText(eventId, actor, kind, ref, at, outcome) {
  if (!UUID.test(eventId) || !UUID.test(actor) || !UUID.test(ref) ||
      !["post", "image"].includes(kind) || !Object.hasOwn(RESULT, outcome) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(at) ||
      !Number.isFinite(Date.parse(at))) {
    throw new Error("Invalid isolated BetTail observation.");
  }
  return ["signalbridge.bettail.read.v1", eventId, actor, kind, ref, at,
    outcome, RESULT[outcome]].join("\n");
}

export function observer(configuration) {
  const config = validateConfiguration(configuration);
  const watched = new Set(config.watched.map((row) => `${row.kind}:${row.ref}`));
  const key = Buffer.from(config.observer_key, "hex");
  return async function record(client, actor, kind, ref, outcome) {
    if (!watched.has(`${kind}:${ref}`)) return null;
    const eventId = randomUUID();
    const at = new Date().toISOString();
    const text = attestationText(eventId, actor, kind, ref, at, outcome);
    const proof = createHmac("sha256", key).update(text, "utf8").digest("hex");
    // The same authenticated Supabase client is used for the real read and RPC.
    // No outcome, actor, or proof is accepted from browser request parameters.
    const { data, error } = await client.rpc("sb_bettail_observe", {
      event_id: eventId, resource_kind: kind, resource_ref: ref, observed_at: at,
      observed_outcome: outcome, proof,
    });
    if (error || !data || data.event_id !== eventId ||
        !["recorded", "duplicate"].includes(data.status) ||
        Object.keys(data).sort().join() !== "event_id,status") {
      throw new Error("Isolated BetTail observation could not be retained.");
    }
    return eventId;
  };
}
