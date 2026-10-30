// Teste ponta a ponta com KV e Google simulados: node test/flow.test.mjs
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import worker from "../src/index.js";

const store = new Map();
const KV = {
  async get(k) { return store.has(k) ? store.get(k) : null; },
  async put(k, v) { store.set(k, v); },
  async delete(k) { store.delete(k); },
};
const env = {
  OAUTH_KV: KV,
  GOOGLE_CLIENT_ID: "gid",
  GOOGLE_CLIENT_SECRET: "gsecret",
  ENCRYPTION_KEY: "uma-chave-de-teste-bem-longa-123",
  ALLOWED_EMAILS: "mastergaia2323@gmail.com",
  ADS_API_VERSION: "v26",
};
const ORIGIN = "https://google-ads-mcp.teste.workers.dev";
const b64u = (b) => Buffer.from(b).toString("base64url");
let emailForLogin = "mastergaia2323@gmail.com";
const adsCalls = [];

const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === "string" ? input : input.url;
  if (url === "https://oauth2.googleapis.com/token") {
    const p = new URLSearchParams(init.body);
    if (p.get("grant_type") === "authorization_code") {
      const idt = `x.${b64u(JSON.stringify({ email: emailForLogin, email_verified: true }))}.y`;
      return Response.json({ access_token: "g-at", refresh_token: "g-rt", expires_in: 3599, id_token: idt, scope: "openid email https://www.googleapis.com/auth/adwords" });
    }
    assert.equal(p.get("refresh_token"), "g-rt");
    return Response.json({ access_token: "g-at2", expires_in: 3599 });
  }
  if (url.startsWith("https://googleads.googleapis.com/v26/")) {
    const h = init.headers || {};
    assert.match(h.Authorization, /^Bearer g-at/);
    const body = init.body ? JSON.parse(init.body) : null;
    adsCalls.push({ url, login: h["login-customer-id"], body });
    if (url.endsWith("customers:listAccessibleCustomers")) return Response.json({ resourceNames: ["customers/1112223333"] });
    const q = body.query;
    if (q.startsWith("SELECT bad")) {
      return Response.json({ error: { code: 400, status: "INVALID_ARGUMENT", details: [{ errors: [{ errorCode: { queryError: "UNRECOGNIZED_FIELD" }, message: "Campo inválido" }] }] } }, { status: 400 });
    }
    if (q.includes("FROM customer_client")) {
      return Response.json({ results: [{ customerClient: { id: "4445556666", descriptiveName: "Cliente A", manager: false, currencyCode: "BRL", timeZone: "America/Sao_Paulo", status: "ENABLED", level: "1" } }] });
    }
    if (q.includes("FROM customer ")) {
      return Response.json({ results: [{ customer: { id: "1112223333", descriptiveName: "MCC Agência", manager: true, currencyCode: "BRL", timeZone: "America/Sao_Paulo", status: "ENABLED" } }] });
    }
    if (q.includes("FROM campaign")) {
      if (!body.pageToken) {
        return Response.json({ results: [{ campaign: { resourceName: "x", id: "1", name: "Pesquisa Marca", status: "ENABLED" }, campaignBudget: { amountMicros: "50000000" }, metrics: { clicks: "10", costMicros: "123456789", averageCpc: "12345678", ctr: 0.0523456 } }], nextPageToken: "p2" });
      }
      return Response.json({ results: [{ campaign: { id: "2", name: "PMax" }, metrics: { costMicros: "1000000" } }] });
    }
  }
  throw new Error(`fetch inesperado: ${url}`);
};

const call = (path, init = {}) => worker.fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env);

// 1) metadados e 401
let r = await call("/.well-known/oauth-authorization-server");
assert.equal((await r.json()).token_endpoint, `${ORIGIN}/token`);
r = await call("/.well-known/oauth-protected-resource/mcp");
assert.equal((await r.json()).resource, `${ORIGIN}/mcp`);
r = await call("/mcp", { method: "POST", body: "{}" });
assert.equal(r.status, 401);
assert.match(r.headers.get("WWW-Authenticate"), /resource_metadata=/);

// 2) registro: host não permitido é recusado
r = await call("/register", { method: "POST", body: JSON.stringify({ redirect_uris: ["https://evil.com/cb"] }) });
assert.equal(r.status, 400);
r = await call("/register", { method: "POST", body: JSON.stringify({ client_name: "Claude", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "client_secret_post" }) });
assert.equal(r.status, 201);
const client = await r.json();
assert.ok(client.client_secret);

// 3) authorize -> Google
const verifier = b64u(randomBytes(32));
const challenge = createHash("sha256").update(verifier).digest("base64url");
const authQs = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", state: "st123", code_challenge: challenge, code_challenge_method: "S256", scope: "ads.read" });
r = await call(`/authorize?${authQs}`);
assert.equal(r.status, 302);
const g = new URL(r.headers.get("Location"));
assert.equal(g.hostname, "accounts.google.com");
assert.equal(g.searchParams.get("redirect_uri"), `${ORIGIN}/callback`);
assert.equal(g.searchParams.get("access_type"), "offline");

// 3b) e-mail não autorizado
emailForLogin = "intruso@gmail.com";
r = await call(`/callback?code=abc&state=${g.searchParams.get("state")}`);
assert.equal(r.status, 403);
emailForLogin = "mastergaia2323@gmail.com";

// 4) callback com e-mail autorizado
r = await call(`/authorize?${authQs}`);
const g2 = new URL(r.headers.get("Location"));
r = await call(`/callback?code=abc&state=${g2.searchParams.get("state")}`);
assert.equal(r.status, 302);
const back = new URL(r.headers.get("Location"));
assert.equal(back.origin + back.pathname, "https://claude.ai/api/mcp/auth_callback");
assert.equal(back.searchParams.get("state"), "st123");
const code = back.searchParams.get("code");

// 5) token: PKCE errado falha, certo funciona, código não reutilizável
const tokenBody = (extra) => new URLSearchParams({ grant_type: "authorization_code", client_id: client.client_id, client_secret: client.client_secret, redirect_uri: "https://claude.ai/api/mcp/auth_callback", ...extra }).toString();
r = await call("/token", { method: "POST", body: tokenBody({ code, code_verifier: "errado" }) });
assert.equal(r.status, 400);
// o código foi consumido na tentativa errada -> refaz o fluxo
r = await call(`/authorize?${authQs}`);
const g3 = new URL(r.headers.get("Location"));
r = await call(`/callback?code=abc&state=${g3.searchParams.get("state")}`);
const code2 = new URL(r.headers.get("Location")).searchParams.get("code");
r = await call("/token", { method: "POST", body: tokenBody({ code: code2, code_verifier: verifier, client_secret: "x" }) });
assert.equal(r.status, 401, "secret errado deve falhar");
r = await call("/token", { method: "POST", body: tokenBody({ code: code2, code_verifier: verifier }) });
assert.equal(r.status, 200);
const tokens = await r.json();
assert.ok(tokens.access_token && tokens.refresh_token);
r = await call("/token", { method: "POST", body: tokenBody({ code: code2, code_verifier: verifier }) });
assert.equal(r.status, 400, "código não pode ser reutilizado");

// 6) MCP
const mcp = (msg) => call("/mcp", { method: "POST", headers: { Authorization: `Bearer ${tokens.access_token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" }, body: JSON.stringify(msg) });
r = await mcp({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
let j = await r.json();
assert.equal(j.result.protocolVersion, "2025-06-18");
r = await mcp({ jsonrpc: "2.0", method: "notifications/initialized" });
assert.equal(r.status, 202);
r = await mcp({ jsonrpc: "2.0", id: 2, method: "tools/list" });
j = await r.json();
assert.deepEqual(j.result.tools.map((t) => t.name), ["list_accounts", "campaign_performance", "daily_performance", "keyword_performance", "search_terms", "ad_performance", "run_gaql"]);

r = await mcp({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_accounts", arguments: {} } });
j = await r.json();
const accts = JSON.parse(j.result.content[0].text);
assert.equal(accts.total, 2);
assert.equal(accts.contas[1].acessar_via, "1112223333");

// subconta deve usar automaticamente o MCC como login-customer-id
adsCalls.length = 0;
r = await mcp({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "campaign_performance", arguments: { customer_id: "444-555-6666", date_range: "LAST_7_DAYS" } } });
j = await r.json();
const perf = JSON.parse(j.result.content[0].text);
assert.equal(adsCalls[0].login, "1112223333");
assert.equal(adsCalls.length, 2, "deve paginar");
assert.equal(perf.linhas, 2);
assert.equal(perf.resultados[0]["metrics.cost"], 123.46);
assert.equal(perf.resultados[0]["metrics.averageCpc"], 12.35);
assert.equal(perf.resultados[0]["campaignBudget.amount"], 50);
assert.match(adsCalls[0].body.query, /DURING LAST_7_DAYS/);

// injeção e validações
r = await mcp({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "campaign_performance", arguments: { customer_id: "4445556666", start_date: "2026-01-01' OR 1=1", end_date: "2026-01-31" } } });
j = await r.json();
assert.equal(j.result.isError, true);
r = await mcp({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "run_gaql", arguments: { customer_id: "4445556666", query: "DELETE campaign" } } });
assert.equal((await r.json()).result.isError, true);
r = await mcp({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "run_gaql", arguments: { customer_id: "4445556666", query: "SELECT bad FROM campaign" } } });
j = await r.json();
assert.equal(j.result.isError, true);
assert.match(j.result.content[0].text, /queryError.UNRECOGNIZED_FIELD: Campo inválido/);

// 7) refresh: rotação; token antigo deixa de valer
r = await call("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id, client_secret: client.client_secret }).toString() });
assert.equal(r.status, 200);
const t2 = await r.json();
assert.notEqual(t2.refresh_token, tokens.refresh_token);
r = await call("/token", { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id, client_secret: client.client_secret }).toString() });
assert.equal(r.status, 400);

// 8) refresh token do Google fica criptografado no KV
const grantRaw = [...store.entries()].find(([k]) => k.startsWith("grant:"))[1];
assert.ok(!grantRaw.includes("g-rt"));

// 9) token do Google expirado -> renova via refresh
for (const k of [...store.keys()]) if (k.startsWith("gat:")) store.delete(k);
r = await mcp({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "run_gaql", arguments: { customer_id: "1112223333", query: "SELECT customer.id FROM customer LIMIT 1" } } });
j = await r.json();
assert.ok(!j.result.isError, j.result.content[0].text);

globalThis.fetch = realFetch;
console.log("OK — todos os testes passaram");
