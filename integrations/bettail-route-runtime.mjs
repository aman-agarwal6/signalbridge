/** Fixed entry point for the internal-only, disposable BetTail Next route lab. */
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export function nextEnvironment(environment) {
  const key = environment.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (environment.NEXT_PUBLIC_SUPABASE_URL !== "http://127.0.0.1:55321" ||
      typeof key !== "string" || !/^sb_publishable_[A-Za-z0-9_-]{20,200}$/.test(key)) {
    throw new Error("Route lab requires its fixed local endpoint and disposable publishable key.");
  }
  return {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/tmp", TMPDIR: "/tmp", NODE_ENV: "development",
    NEXT_TELEMETRY_DISABLED: "1", DO_NOT_TRACK: "1",
    NEXT_PUBLIC_SUPABASE_URL: "http://127.0.0.1:55321",
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key,
  };
}

export function startRuntime({ environment = process.env, createServer = net.createServer,
  connect = net.createConnection, launch = spawn } = {}) {
  const childEnvironment = nextEnvironment(environment);
  let connections = 0;
  const sockets = new Set();
  const forwarder = createServer((client) => {
    if (connections >= 128) { client.destroy(); return; }
    connections += 1;
    const upstream = connect({ host: "supabase_kong_signalbridge-bettail-lab", port: 8000 });
    sockets.add(client); sockets.add(upstream);
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true; connections -= 1;
      clearTimeout(deadline);
      for (const socket of [client, upstream]) { sockets.delete(socket); socket.destroy(); }
    };
    const deadline = setTimeout(close, 3000);
    upstream.once("connect", () => {
      clearTimeout(deadline);
      client.pipe(upstream); upstream.pipe(client);
    });
    for (const socket of [client, upstream]) {
      socket.setTimeout(15000, close);
      socket.on("error", close); socket.on("close", close);
    }
  });
  let child;
  const stop = () => {
    for (const socket of sockets) socket.destroy();
    forwarder.close();
    if (child && child.exitCode === null) child.kill("SIGTERM");
  };
  forwarder.once("error", () => { process.exitCode = 1; stop(); });
  forwarder.listen(55321, "127.0.0.1", () => {
    child = launch(process.execPath, ["/app/node_modules/next/dist/bin/next", "dev",
      "--webpack", "--hostname", "0.0.0.0", "--port", "3101"],
    { cwd: "/app", env: childEnvironment, stdio: "inherit", shell: false });
    child.once("error", () => { process.exitCode = 1; stop(); });
    child.once("exit", (code) => { process.exitCode = code === 0 ? 0 : 1; stop(); });
  });
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return { stop, forwarder };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) {
    process.stderr.write("The route runtime accepts no target or command arguments.\n");
    process.exitCode = 1;
  } else {
    try { startRuntime(); }
    catch { process.stderr.write("Route runtime configuration rejected.\n"); process.exitCode = 1; }
  }
}
