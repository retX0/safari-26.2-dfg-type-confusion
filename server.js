import { readFileSync, existsSync, appendFileSync } from "fs";
import { join, resolve } from "path";

const DIR = import.meta.dir;
const LOG = join(DIR, "log.txt");
const MIME = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css" };

function ts() { return new Date().toISOString().slice(11, 23); }

const server = Bun.serve({
  port: 8080,
  hostname: "0.0.0.0",

  async fetch(req, server) {
    if (req.method === "POST") {
      let buf = await req.arrayBuffer();
      let body = new TextDecoder('utf-8').decode(buf);
      let lines = body.split('\n');
      for (let line of lines) {
        let stamped = `[${ts()}] ${line}`;
        console.log(stamped);
        appendFileSync(LOG, stamped + '\n');
      }
      return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*" } });
    }

    // WebSocket upgrade
    if (server.upgrade(req)) return;

    // Static files
    let url = new URL(req.url);
    let path = url.pathname === "/" ? "/index.html" : url.pathname;
    let file = resolve(join(DIR, path));
    if (!file.startsWith(DIR) || !existsSync(file)) {
      return new Response("404", { status: 404 });
    }
    let ext = "." + file.split(".").pop();
    return new Response(readFileSync(file), {
      headers: { "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": "no-cache" },
    });
  },

  websocket: {
    open(ws) { console.log(`\x1b[36m[ws] ${ws.remoteAddress} connected\x1b[0m`); },
    message(ws, msg) { console.log(String(msg)); },
    close(ws) { console.log(`\x1b[36m[ws] ${ws.remoteAddress} disconnected\x1b[0m`); },
  },
});

console.log(`\x1b[32m==================================================`);
console.log(`  http://${server.hostname}:${server.port}/`);
console.log(`==================================================\x1b[0m`);
