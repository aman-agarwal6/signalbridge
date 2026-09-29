/** Fixed TCP destinations for the isolated local lab; no HTTP proxy or target input. */
import net from "node:net";

const routes = [
  [55321, "supabase_kong_signalbridge-bettail-lab", 8000],
  [55322, "supabase_db_signalbridge-bettail-lab", 5432],
  [55324, "supabase_inbucket_signalbridge-bettail-lab", 8025],
];
let connections = 0;
for (const [port, host, targetPort] of routes) {
  const server = net.createServer((client) => {
    if (connections >= 128) { client.destroy(); return; }
    connections += 1;
    const target = net.createConnection({ host, port: targetPort });
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      connections -= 1;
      client.destroy();
      target.destroy();
    };
    const deadline = setTimeout(close, 3000);
    target.once("connect", () => {
      clearTimeout(deadline);
      client.pipe(target);
      target.pipe(client);
    });
    for (const socket of [client, target]) {
      socket.setTimeout(60000, close);
      socket.on("error", close);
      socket.on("close", () => { clearTimeout(deadline); close(); });
    }
  });
  server.on("error", () => { process.exitCode = 1; process.exit(1); });
  // Docker publishes only 127.0.0.1; container interfaces must accept its forwarding.
  server.listen(port, "0.0.0.0");
}
