import "server-only";
import { readFileSync, lstatSync } from "node:fs";
import { observer } from "./observer.mjs";

type Client = { rpc: (name: string, args: Record<string, string>) => PromiseLike<{
  data: unknown; error: unknown;
}> };
type Outcome = "allowed" | "denied" | "not_visible" | "error";

// This file exists only in the derived lab source. It cannot silently run as an
// uninstrumented copy or inherit credentials/configuration from the real app.
function configuredObserver() {
  if (process.env.SB_BETTAIL_ACCESS_LAB !== "1") {
    throw new Error("The copied BetTail access profile is not enabled.");
  }
  const path = "/run/secrets/bettail-access.json";
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 2048 || info.nlink !== 1) {
    throw new Error("Invalid isolated BetTail configuration file.");
  }
  return observer(JSON.parse(readFileSync(path, "utf8")));
}

export async function observeAccess(
  client: Client, actor: string, kind: "post" | "image", ref: string | undefined,
  outcome: Outcome,
) {
  return configuredObserver()(client, actor, kind, ref ?? "", outcome);
}
