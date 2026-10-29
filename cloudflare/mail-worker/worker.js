// Stores inbound mail (Email Routing catch-all) in D1 and serves the newest per recipient behind a bearer token.
import PostalMime from "postal-mime";

const MAX_BODY = 200 * 1024; // chars per html/text: worst-case UTF-8 stays under D1's 2 MB row limit
const MAX_RAW = 5 * 1024 * 1024; // reject bigger mail before parsing
const TTL_MS = 60 * 60 * 1000; // keep mail for 1 hour

function sameToken(a, b) { // constant-time compare (hash first so length doesn't leak)
  const enc = new TextEncoder();
  return Promise.all([a, b].map((s) => crypto.subtle.digest("SHA-256", enc.encode(s)))).then(([x, y]) => {
    const u = new Uint8Array(x), v = new Uint8Array(y);
    let d = 0;
    for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
    return d === 0;
  });
}

export default {
  async email(message, env) {
    if (message.rawSize > MAX_RAW) return message.setReject("message too large");
    const parsed = await PostalMime.parse(message.raw);
    const now = Date.now();
    await env.DB.batch([ // throws on parse/insert failure, so Email Routing logs it instead of dropping silently
      env.DB.prepare("INSERT INTO mail (to_addr, subject, text, html, created) VALUES (?, ?, ?, ?, ?)")
        .bind(message.to.toLowerCase(), parsed.subject || "", (parsed.text || "").slice(0, MAX_BODY), (parsed.html || "").slice(0, MAX_BODY), now),
      env.DB.prepare("DELETE FROM mail WHERE created < ?").bind(now - TTL_MS),
    ]);
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const auth = request.headers.get("Authorization") || "";
    if (!env.API_TOKEN || !(await sameToken(auth, `Bearer ${env.API_TOKEN}`))) return new Response("unauthorized", { status: 401 });
    if (url.pathname === "/health") return new Response("ok");
    if (url.pathname === "/latest") {
      const to = (url.searchParams.get("to") || "").toLowerCase();
      const row = to && await env.DB.prepare("SELECT subject, text, html FROM mail WHERE to_addr = ? AND created > ? ORDER BY created DESC, id DESC LIMIT 1").bind(to, Date.now() - TTL_MS).first();
      if (!row) return new Response("not found", { status: 404 });
      return Response.json({ subject: row.subject, text: row.text, html: row.html });
    }
    return new Response("not found", { status: 404 });
  },
};
