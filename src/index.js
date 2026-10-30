/**
 * Google Ads MCP — servidor MCP remoto (somente leitura) para conectar o Google Ads ao Claude.
 *
 * - Roda como Cloudflare Worker, sem dependências externas.
 * - É um servidor OAuth 2.1 próprio (registro dinâmico + PKCE) que delega o login ao Google.
 * - Só aceita as contas Google listadas em ALLOWED_EMAILS.
 * - Só faz consultas (googleAds:search). Nenhuma alteração é possível.
 *
 * Bindings/variáveis esperadas:
 *   OAUTH_KV                (KV)      armazenamento de clientes, códigos e tokens
 *   GOOGLE_CLIENT_ID        (secret)  cliente OAuth "Aplicativo da Web" do projeto Google Cloud aprovado
 *   GOOGLE_CLIENT_SECRET    (secret)
 *   ENCRYPTION_KEY          (secret)  texto aleatório longo; criptografa o refresh token do Google
 *   ALLOWED_EMAILS          (var)     e-mails autorizados, separados por vírgula
 *   ALLOWED_REDIRECT_HOSTS  (var)     hosts aceitos como redirect (padrão: claude.ai,claude.com)
 *   ADS_API_VERSION         (var)     ex.: v26
 *   LOGIN_CUSTOMER_ID       (var)     opcional: ID da conta administradora (MCC) padrão
 */

const SERVER_NAME = "google-ads-mcp";
const SERVER_VERSION = "1.0.0";
const SUPPORTED_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const GOOGLE_SCOPES = "openid email https://www.googleapis.com/auth/adwords";
const ACCESS_TTL = 3600; // 1 h
const REFRESH_TTL = 60 * 60 * 24 * 90; // 90 dias
const MAX_OUTPUT_CHARS = 120000;

// ---------------------------------------------------------------- utilidades

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
function randomToken(n = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(n)));
}
async function sha256(text) {
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function aesKey(env) {
  if (!env.ENCRYPTION_KEY || env.ENCRYPTION_KEY.length < 16) {
    throw new Error("ENCRYPTION_KEY ausente ou curta demais (mínimo 16 caracteres).");
  }
  const raw = await crypto.subtle.digest("SHA-256", enc.encode(env.ENCRYPTION_KEY));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), enc.encode(text));
  return `${b64url(iv)}.${b64url(ct)}`;
}
async function decrypt(env, payload) {
  const [iv, ct] = payload.split(".");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64urlDecode(iv) }, await aesKey(env), b64urlDecode(ct));
  return dec.decode(pt);
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Accept",
  "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id",
};
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS, ...extra },
  });
}
function oauthError(error, description, status = 400) {
  return json({ error, error_description: description }, status);
}
function html(body, status = 200) {
  return new Response(
    `<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Google Ads MCP</title><style>body{font-family:system-ui,Arial,sans-serif;max-width:560px;margin:48px auto;padding:0 20px;line-height:1.5;color:#222}code{background:#f2f2f2;padding:2px 5px;border-radius:4px}</style></head><body>${body}</body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } },
  );
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function csv(v) {
  return String(v || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
}
async function kvGet(env, key) {
  const v = await env.OAUTH_KV.get(key);
  return v ? JSON.parse(v) : null;
}
async function kvPut(env, key, value, ttl) {
  await env.OAUTH_KV.put(key, JSON.stringify(value), ttl ? { expirationTtl: Math.max(60, ttl) } : undefined);
}

// ---------------------------------------------------------------- metadados OAuth

function asMetadata(origin) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    revocation_endpoint: `${origin}/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    scopes_supported: ["ads.read"],
  };
}
function prMetadata(origin) {
  return {
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: ["ads.read"],
    resource_name: "Google Ads (somente leitura)",
  };
}

// ---------------------------------------------------------------- OAuth: registro dinâmico

function redirectAllowed(env, uri) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  const hosts = csv(env.ALLOWED_REDIRECT_HOSTS || "claude.ai,claude.com");
  if (u.protocol === "https:" && hosts.some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`))) return true;
  if (env.ALLOW_LOCALHOST_REDIRECTS === "true" && u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname)) return true;
  return false;
}

async function handleRegister(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return oauthError("invalid_client_metadata", "Corpo JSON inválido.");
  }
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  if (!redirectUris.length) return oauthError("invalid_redirect_uri", "redirect_uris é obrigatório.");
  for (const r of redirectUris) {
    if (!redirectAllowed(env, r)) return oauthError("invalid_redirect_uri", `redirect_uri não permitido: ${r}`);
  }
  const method = ["none", "client_secret_post", "client_secret_basic"].includes(body.token_endpoint_auth_method)
    ? body.token_endpoint_auth_method
    : "client_secret_basic";
  const clientId = randomToken(16);
  const client = {
    client_id: clientId,
    client_name: String(body.client_name || "cliente MCP").slice(0, 100),
    redirect_uris: redirectUris,
    token_endpoint_auth_method: method,
    created: Date.now(),
  };
  const response = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: client.client_name,
    redirect_uris: redirectUris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: method,
  };
  if (method !== "none") {
    const secret = randomToken(32);
    client.secret_hash = await sha256(secret);
    response.client_secret = secret;
    response.client_secret_expires_at = 0;
  }
  await kvPut(env, `client:${clientId}`, client);
  return json(response, 201);
}

// ---------------------------------------------------------------- OAuth: autorização

async function handleAuthorize(url, env) {
  const p = url.searchParams;
  const client = await kvGet(env, `client:${p.get("client_id") || ""}`);
  if (!client) return html("<h2>Cliente desconhecido</h2><p>Remova e adicione o conector novamente no Claude.</p>", 400);
  const redirectUri = p.get("redirect_uri") || (client.redirect_uris.length === 1 ? client.redirect_uris[0] : "");
  if (!client.redirect_uris.includes(redirectUri)) return html("<h2>redirect_uri inválido</h2>", 400);

  const back = (error, desc) => {
    const r = new URL(redirectUri);
    r.searchParams.set("error", error);
    if (desc) r.searchParams.set("error_description", desc);
    if (p.get("state")) r.searchParams.set("state", p.get("state"));
    return Response.redirect(r.toString(), 302);
  };
  if (p.get("response_type") !== "code") return back("unsupported_response_type", "Use response_type=code.");
  if (!p.get("code_challenge") || (p.get("code_challenge_method") || "plain") !== "S256") {
    return back("invalid_request", "PKCE com S256 é obrigatório.");
  }
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return back("server_error", "Credenciais do Google não configuradas.");

  const reqId = randomToken(24);
  await kvPut(
    env,
    `authreq:${reqId}`,
    {
      clientId: client.client_id,
      redirectUri,
      state: p.get("state"),
      codeChallenge: p.get("code_challenge"),
      scope: p.get("scope") || "ads.read",
    },
    600,
  );
  const g = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  g.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  g.searchParams.set("redirect_uri", `${url.origin}/callback`);
  g.searchParams.set("response_type", "code");
  g.searchParams.set("scope", GOOGLE_SCOPES);
  g.searchParams.set("access_type", "offline");
  g.searchParams.set("prompt", "consent");
  g.searchParams.set("include_granted_scopes", "true");
  g.searchParams.set("state", reqId);
  return Response.redirect(g.toString(), 302);
}

async function handleCallback(url, env) {
  const reqId = url.searchParams.get("state") || "";
  const authReq = await kvGet(env, `authreq:${reqId}`);
  if (!authReq) return html("<h2>Pedido expirado</h2><p>Volte ao Claude e clique em conectar de novo.</p>", 400);
  await env.OAUTH_KV.delete(`authreq:${reqId}`);

  const back = (params) => {
    const r = new URL(authReq.redirectUri);
    for (const [k, v] of Object.entries(params)) r.searchParams.set(k, v);
    if (authReq.state) r.searchParams.set("state", authReq.state);
    return Response.redirect(r.toString(), 302);
  };
  if (url.searchParams.get("error")) return back({ error: "access_denied", error_description: "Login no Google cancelado." });

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code: url.searchParams.get("code") || "",
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${url.origin}/callback`,
      grant_type: "authorization_code",
    }),
  });
  const tok = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tok.id_token) {
    return html(`<h2>Falha no login do Google</h2><p><code>${escapeHtml(tok.error_description || tok.error || tokenRes.status)}</code></p>`, 502);
  }
  // O id_token veio direto do Google por TLS, então dá para ler o conteúdo sem validar assinatura.
  let claims = {};
  try {
    claims = JSON.parse(dec.decode(b64urlDecode(tok.id_token.split(".")[1])));
  } catch {
    /* segue com claims vazias */
  }
  const email = String(claims.email || "").toLowerCase();
  const allowed = csv(env.ALLOWED_EMAILS);
  if (!email || claims.email_verified === false || !allowed.includes(email)) {
    return html(`<h2>Conta não autorizada</h2><p>A conta <code>${escapeHtml(email || "?")}</code> não está na lista de acesso deste servidor.</p>`, 403);
  }
  if (!String(tok.scope || "").includes("auth/adwords")) {
    return html("<h2>Permissão do Google Ads não concedida</h2><p>Na tela do Google, marque a caixa de acesso ao Google Ads e tente de novo.</p>", 400);
  }
  if (!tok.refresh_token) {
    return html("<h2>O Google não devolveu um refresh token</h2><p>Remova o acesso em myaccount.google.com/permissions e conecte de novo.</p>", 400);
  }

  const grantId = randomToken(16);
  await kvPut(env, `grant:${grantId}`, {
    email,
    clientId: authReq.clientId,
    googleRefresh: await encrypt(env, tok.refresh_token),
    created: Date.now(),
  });
  if (tok.access_token) {
    await kvPut(env, `gat:${grantId}`, { t: await encrypt(env, tok.access_token) }, Math.min(3300, (tok.expires_in || 3600) - 120));
  }
  const code = randomToken(32);
  await kvPut(
    env,
    `code:${await sha256(code)}`,
    { clientId: authReq.clientId, redirectUri: authReq.redirectUri, codeChallenge: authReq.codeChallenge, grantId, scope: authReq.scope },
    300,
  );
  return back({ code });
}

// ---------------------------------------------------------------- OAuth: token

async function authenticateClient(request, params, env) {
  let clientId = params.get("client_id");
  let secret = params.get("client_secret");
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Basic ")) {
    try {
      const [id, sec] = atob(auth.slice(6)).split(":");
      clientId = decodeURIComponent(id);
      secret = decodeURIComponent(sec || "");
    } catch {
      return null;
    }
  }
  const client = await kvGet(env, `client:${clientId || ""}`);
  if (!client) return null;
  if (client.token_endpoint_auth_method === "none") return client;
  if (!secret || !timingSafeEqual(await sha256(secret), client.secret_hash)) return null;
  return client;
}

async function issueTokens(env, grantId, clientId, scope) {
  const access = randomToken(32);
  const refresh = randomToken(32);
  await kvPut(env, `at:${await sha256(access)}`, { grantId, clientId }, ACCESS_TTL);
  await kvPut(env, `rt:${await sha256(refresh)}`, { grantId, clientId, scope }, REFRESH_TTL);
  return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refresh, scope: scope || "ads.read" });
}

async function handleToken(request, env) {
  const params = new URLSearchParams(await request.text());
  const client = await authenticateClient(request, params, env);
  if (!client) return oauthError("invalid_client", "Autenticação do cliente falhou.", 401);
  const grantType = params.get("grant_type");

  if (grantType === "authorization_code") {
    const key = `code:${await sha256(params.get("code") || "")}`;
    const rec = await kvGet(env, key);
    if (!rec) return oauthError("invalid_grant", "Código inválido ou expirado.");
    await env.OAUTH_KV.delete(key);
    if (rec.clientId !== client.client_id) return oauthError("invalid_grant", "Código pertence a outro cliente.");
    if (params.get("redirect_uri") && params.get("redirect_uri") !== rec.redirectUri) return oauthError("invalid_grant", "redirect_uri diferente.");
    const verifier = params.get("code_verifier") || "";
    if (!verifier || (await sha256(verifier)) !== rec.codeChallenge) return oauthError("invalid_grant", "PKCE inválido.");
    return issueTokens(env, rec.grantId, client.client_id, rec.scope);
  }

  if (grantType === "refresh_token") {
    const key = `rt:${await sha256(params.get("refresh_token") || "")}`;
    const rec = await kvGet(env, key);
    if (!rec || rec.clientId !== client.client_id) return oauthError("invalid_grant", "Refresh token inválido.");
    if (!(await kvGet(env, `grant:${rec.grantId}`))) return oauthError("invalid_grant", "Acesso revogado.");
    await env.OAUTH_KV.delete(key); // rotação
    return issueTokens(env, rec.grantId, client.client_id, rec.scope);
  }

  return oauthError("unsupported_grant_type", "Use authorization_code ou refresh_token.");
}

async function handleRevoke(request, env) {
  const params = new URLSearchParams(await request.text());
  const token = params.get("token") || "";
  const h = await sha256(token);
  await env.OAUTH_KV.delete(`at:${h}`);
  await env.OAUTH_KV.delete(`rt:${h}`);
  return new Response(null, { status: 200, headers: CORS });
}

// ---------------------------------------------------------------- Google Ads API

async function googleAccessToken(env, grantId) {
  const cached = await kvGet(env, `gat:${grantId}`);
  if (cached) return decrypt(env, cached.t);
  const grant = await kvGet(env, `grant:${grantId}`);
  if (!grant) throw new Error("Acesso não encontrado. Reconecte o conector no Claude.");
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: await decrypt(env, grant.googleRefresh),
      grant_type: "refresh_token",
    }),
  });
  const tok = await res.json().catch(() => ({}));
  if (!res.ok || !tok.access_token) {
    if (tok.error === "invalid_grant") {
      throw new Error("O acesso ao Google expirou ou foi revogado. Desconecte e conecte o conector de novo no Claude.");
    }
    throw new Error(`Falha ao renovar o token do Google: ${tok.error_description || tok.error || res.status}`);
  }
  await kvPut(env, `gat:${grantId}`, { t: await encrypt(env, tok.access_token) }, Math.min(3300, (tok.expires_in || 3600) - 120));
  return tok.access_token;
}

function adsErrorMessage(status, body) {
  const err = body && body.error;
  if (!err) return `HTTP ${status}`;
  const parts = [];
  for (const d of err.details || []) {
    for (const e of d.errors || []) {
      const code = e.errorCode ? Object.entries(e.errorCode).map(([k, v]) => `${k}.${v}`).join(",") : "";
      parts.push(`${code}${code ? ": " : ""}${e.message}`);
    }
  }
  return parts.length ? parts.join(" | ") : `${err.status || status}: ${err.message}`;
}

function digits(id, field = "customer_id") {
  const d = String(id ?? "").replace(/[\s-]/g, "");
  if (!/^\d{6,12}$/.test(d)) throw new Error(`${field} inválido: "${id}". Use o ID de 10 dígitos (com ou sem traços).`);
  return d;
}

class Ads {
  constructor(env, grantId) {
    this.env = env;
    this.grantId = grantId;
    this.version = env.ADS_API_VERSION || "v26";
  }
  async token() {
    if (!this.t) this.t = await googleAccessToken(this.env, this.grantId);
    return this.t;
  }
  async call(method, path, body, loginCustomerId) {
    const headers = { Authorization: `Bearer ${await this.token()}`, "Content-Type": "application/json" };
    if (loginCustomerId) headers["login-customer-id"] = loginCustomerId;
    const res = await fetch(`https://googleads.googleapis.com/${this.version}/${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`Google Ads API: ${adsErrorMessage(res.status, data)}`);
    return data;
  }
  async loginFor(customerId, explicit) {
    if (explicit) return digits(explicit, "login_customer_id");
    const route = await kvGet(this.env, `route:${this.grantId}:${customerId}`);
    if (route && route.via && route.via !== customerId) return route.via;
    if (this.env.LOGIN_CUSTOMER_ID) return digits(this.env.LOGIN_CUSTOMER_ID, "LOGIN_CUSTOMER_ID");
    return undefined;
  }
  async search(customerId, query, { loginCustomerId, maxRows = 1000 } = {}) {
    const cid = digits(customerId);
    const login = await this.loginFor(cid, loginCustomerId);
    const rows = [];
    let pageToken;
    let truncated = false;
    do {
      const body = { query };
      if (pageToken) body.pageToken = pageToken;
      const data = await this.call("POST", `customers/${cid}/googleAds:search`, body, login);
      for (const r of data.results || []) {
        if (rows.length >= maxRows) {
          truncated = true;
          break;
        }
        rows.push(r);
      }
      pageToken = data.nextPageToken;
      if (rows.length >= maxRows && pageToken) truncated = true;
    } while (pageToken && !truncated);
    return { rows, truncated };
  }
}

// Campos em micros que a API REST devolve sem o sufixo "Micros".
const MICROS_FIELDS = new Set([
  "averageCpc", "averageCpm", "averageCpv", "averageCpe", "averageCost", "costPerConversion",
  "costPerAllConversions", "costPerCurrentModelAttributedConversion",
]);

function flatten(obj, prefix = "", out = {}) {
  for (const [k, v] of Object.entries(obj || {})) {
    if (k === "resourceName") continue;
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      flatten(v, key, out);
    } else if (/Micros$/.test(k) && v !== null && v !== "" && !isNaN(Number(v))) {
      out[key.replace(/Micros$/, "")] = Math.round(Number(v) / 10000) / 100;
    } else if (MICROS_FIELDS.has(k) && v !== null && !isNaN(Number(v))) {
      out[key] = Math.round(Number(v) / 10000) / 100;
    } else if (typeof v === "number" && !Number.isInteger(v)) {
      out[key] = Math.round(v * 10000) / 10000;
    } else {
      out[key] = v;
    }
  }
  return out;
}

function pack(meta, rows, truncated) {
  const flat = rows.map((r) => flatten(r));
  let text = JSON.stringify({ ...meta, linhas: flat.length, truncado: truncated || undefined, resultados: flat });
  if (text.length > MAX_OUTPUT_CHARS) {
    let n = flat.length;
    while (n > 1 && text.length > MAX_OUTPUT_CHARS) {
      n = Math.floor(n * 0.7);
      text = JSON.stringify({ ...meta, linhas: n, truncado: true, aviso: "Resultado cortado por tamanho; filtre mais ou reduza o período.", resultados: flat.slice(0, n) });
    }
  }
  return text;
}

// ---------------------------------------------------------------- filtros reutilizáveis

const DATE_PRESETS = [
  "TODAY", "YESTERDAY", "LAST_7_DAYS", "LAST_14_DAYS", "LAST_30_DAYS", "LAST_BUSINESS_WEEK",
  "THIS_WEEK_SUN_TODAY", "THIS_WEEK_MON_TODAY", "LAST_WEEK_SUN_SAT", "LAST_WEEK_MON_SUN", "THIS_MONTH", "LAST_MONTH",
];

function dateClause(args) {
  const iso = /^\d{4}-\d{2}-\d{2}$/;
  if (args.start_date || args.end_date) {
    if (!iso.test(args.start_date || "") || !iso.test(args.end_date || "")) {
      throw new Error("Use start_date e end_date juntos, no formato AAAA-MM-DD.");
    }
    return `segments.date BETWEEN '${args.start_date}' AND '${args.end_date}'`;
  }
  const preset = args.date_range || "LAST_30_DAYS";
  if (!DATE_PRESETS.includes(preset)) throw new Error(`date_range inválido. Opções: ${DATE_PRESETS.join(", ")}`);
  return `segments.date DURING ${preset}`;
}
function periodLabel(args) {
  return args.start_date ? `${args.start_date} a ${args.end_date}` : args.date_range || "LAST_30_DAYS";
}
function limitOf(args, def, max) {
  const n = Number(args.limit || def);
  return Math.max(1, Math.min(max, Number.isFinite(n) ? Math.floor(n) : def));
}
function campaignFilter(args) {
  return args.campaign_id ? ` AND campaign.id = ${digits(args.campaign_id, "campaign_id")}` : "";
}
function statusFilter(args, field) {
  return args.include_paused === false ? ` AND ${field} = 'ENABLED'` : ` AND ${field} != 'REMOVED'`;
}

// ---------------------------------------------------------------- ferramentas

const periodProps = {
  date_range: { type: "string", enum: DATE_PRESETS, description: "Período pré-definido (padrão LAST_30_DAYS). Ignorado se start_date/end_date forem enviados." },
  start_date: { type: "string", description: "Data inicial AAAA-MM-DD (use junto com end_date)." },
  end_date: { type: "string", description: "Data final AAAA-MM-DD." },
};
const commonProps = {
  customer_id: { type: "string", description: "ID da conta Google Ads (10 dígitos, com ou sem traços)." },
  login_customer_id: { type: "string", description: "Opcional: ID da conta administradora (MCC) usada para acessar a conta. Normalmente detectado sozinho após list_accounts." },
};
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

const TOOLS = [
  {
    name: "list_accounts",
    title: "Listar contas Google Ads",
    description:
      "Lista todas as contas Google Ads que o usuário acessa, incluindo as contas-clientes dentro de contas administradoras (MCC), com nome, moeda, fuso e status. Chame primeiro para descobrir os IDs.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { ...RO, title: "Listar contas" },
    async run(ads) {
      const list = await ads.call("GET", "customers:listAccessibleCustomers");
      const ids = (list.resourceNames || []).map((r) => r.split("/")[1]);
      const accounts = [];
      const seen = new Set();
      for (const id of ids) {
        let info;
        try {
          const { rows } = await ads.search(id, "SELECT customer.id, customer.descriptive_name, customer.manager, customer.currency_code, customer.time_zone, customer.status, customer.test_account FROM customer LIMIT 1", { maxRows: 1, loginCustomerId: id });
          info = rows[0] && flatten(rows[0]);
        } catch (e) {
          accounts.push({ id, erro: String(e.message).slice(0, 200) });
          continue;
        }
        if (!info) continue;
        if (!seen.has(id)) {
          seen.add(id);
          accounts.push({
            id, nome: info["customer.descriptiveName"], administradora: !!info["customer.manager"],
            moeda: info["customer.currencyCode"], fuso: info["customer.timeZone"], status: info["customer.status"],
            teste: info["customer.testAccount"] || undefined, acessar_via: id,
          });
          await kvPut(ads.env, `route:${ads.grantId}:${id}`, { via: id });
        }
        if (info["customer.manager"]) {
          try {
            const { rows } = await ads.search(
              id,
              "SELECT customer_client.id, customer_client.descriptive_name, customer_client.manager, customer_client.currency_code, customer_client.time_zone, customer_client.status, customer_client.level FROM customer_client WHERE customer_client.level > 0",
              { maxRows: 2000, loginCustomerId: id },
            );
            for (const r of rows) {
              const c = flatten(r);
              const cid = String(c["customerClient.id"]);
              if (seen.has(cid)) continue;
              seen.add(cid);
              accounts.push({
                id: cid, nome: c["customerClient.descriptiveName"], administradora: !!c["customerClient.manager"],
                moeda: c["customerClient.currencyCode"], fuso: c["customerClient.timeZone"], status: c["customerClient.status"],
                nivel: c["customerClient.level"], acessar_via: id,
              });
              await kvPut(ads.env, `route:${ads.grantId}:${cid}`, { via: id });
            }
          } catch (e) {
            accounts.push({ id, aviso_subcontas: String(e.message).slice(0, 200) });
          }
        }
      }
      return JSON.stringify({ total: accounts.length, contas: accounts });
    },
  },
  {
    name: "campaign_performance",
    title: "Desempenho por campanha",
    description: "Métricas por campanha no período: impressões, cliques, CTR, CPC médio, custo, conversões, valor, CPA, parcela de impressões (Search), orçamento diário, tipo e estratégia de lance. Valores monetários já na moeda da conta.",
    inputSchema: {
      type: "object",
      properties: { ...commonProps, ...periodProps, include_paused: { type: "boolean", description: "Incluir campanhas pausadas (padrão true; removidas nunca entram)." } },
      required: ["customer_id"],
      additionalProperties: false,
    },
    annotations: { ...RO, title: "Desempenho por campanha" },
    async run(ads, a) {
      const q = `SELECT campaign.id, campaign.name, campaign.status, campaign.advertising_channel_type, campaign.bidding_strategy_type, campaign_budget.amount_micros, metrics.impressions, metrics.clicks, metrics.ctr, metrics.average_cpc, metrics.cost_micros, metrics.conversions, metrics.conversions_value, metrics.cost_per_conversion, metrics.search_impression_share, metrics.search_budget_lost_impression_share, metrics.search_rank_lost_impression_share FROM campaign WHERE ${dateClause(a)}${statusFilter(a, "campaign.status")} ORDER BY metrics.cost_micros DESC`;
      const { rows, truncated } = await ads.search(a.customer_id, q, { loginCustomerId: a.login_customer_id, maxRows: 1000 });
      return pack({ conta: digits(a.customer_id), periodo: periodLabel(a) }, rows, truncated);
    },
  },
  {
    name: "daily_performance",
    title: "Desempenho diário da conta",
    description: "Série diária da conta (ou de uma campanha): impressões, cliques, custo, conversões e valor por dia. Bom para ver tendências e quedas.",
    inputSchema: {
      type: "object",
      properties: { ...commonProps, ...periodProps, campaign_id: { type: "string", description: "Opcional: filtrar uma campanha." } },
      required: ["customer_id"],
      additionalProperties: false,
    },
    annotations: { ...RO, title: "Desempenho diário" },
    async run(ads, a) {
      const from = a.campaign_id ? "campaign" : "customer";
      const q = `SELECT segments.date, metrics.impressions, metrics.clicks, metrics.cost_micros, metrics.conversions, metrics.conversions_value FROM ${from} WHERE ${dateClause(a)}${campaignFilter(a)} ORDER BY segments.date`;
      const { rows, truncated } = await ads.search(a.customer_id, q, { loginCustomerId: a.login_customer_id, maxRows: 400 });
      return pack({ conta: digits(a.customer_id), periodo: periodLabel(a) }, rows, truncated);
    },
  },
  {
    name: "keyword_performance",
    title: "Desempenho das palavras-chave",
    description: "Palavras-chave das campanhas de pesquisa com tipo de correspondência, status, índice de qualidade e métricas no período, ordenadas por custo.",
    inputSchema: {
      type: "object",
      properties: {
        ...commonProps, ...periodProps,
        campaign_id: { type: "string", description: "Opcional: filtrar uma campanha." },
        include_paused: { type: "boolean", description: "Incluir palavras pausadas (padrão true)." },
        limit: { type: "integer", description: "Máximo de linhas (padrão 300, máx. 2000)." },
      },
      required: ["customer_id"],
      additionalProperties: false,
    },
    annotations: { ...RO, title: "Palavras-chave" },
    async run(ads, a) {
      const n = limitOf(a, 300, 2000);
      const q = `SELECT campaign.name, ad_group.name, ad_group_criterion.criterion_id, ad_group_criterion.keyword.text, ad_group_criterion.keyword.match_type, ad_group_criterion.status, ad_group_criterion.quality_info.quality_score, metrics.impressions, metrics.clicks, metrics.ctr, metrics.average_cpc, metrics.cost_micros, metrics.conversions, metrics.cost_per_conversion, metrics.search_impression_share FROM keyword_view WHERE ${dateClause(a)}${campaignFilter(a)}${statusFilter(a, "ad_group_criterion.status")} ORDER BY metrics.cost_micros DESC LIMIT ${n}`;
      const { rows, truncated } = await ads.search(a.customer_id, q, { loginCustomerId: a.login_customer_id, maxRows: n });
      return pack({ conta: digits(a.customer_id), periodo: periodLabel(a) }, rows, truncated);
    },
  },
  {
    name: "search_terms",
    title: "Termos de pesquisa",
    description: "Relatório de termos de pesquisa (o que as pessoas digitaram) com a palavra-chave que acionou, campanha, grupo e métricas, ordenado por custo. Útil para achar negativas e novas palavras.",
    inputSchema: {
      type: "object",
      properties: {
        ...commonProps, ...periodProps,
        campaign_id: { type: "string", description: "Opcional: filtrar uma campanha." },
        min_clicks: { type: "integer", description: "Opcional: só termos com pelo menos N cliques." },
        limit: { type: "integer", description: "Máximo de linhas (padrão 500, máx. 5000)." },
      },
      required: ["customer_id"],
      additionalProperties: false,
    },
    annotations: { ...RO, title: "Termos de pesquisa" },
    async run(ads, a) {
      const n = limitOf(a, 500, 5000);
      const minClicks = a.min_clicks ? ` AND metrics.clicks >= ${Math.max(0, Math.floor(Number(a.min_clicks)) || 0)}` : "";
      const q = `SELECT search_term_view.search_term, search_term_view.status, segments.keyword.info.text, segments.keyword.info.match_type, campaign.name, ad_group.name, metrics.impressions, metrics.clicks, metrics.ctr, metrics.cost_micros, metrics.conversions, metrics.conversions_value FROM search_term_view WHERE ${dateClause(a)}${campaignFilter(a)}${minClicks} ORDER BY metrics.cost_micros DESC LIMIT ${n}`;
      const { rows, truncated } = await ads.search(a.customer_id, q, { loginCustomerId: a.login_customer_id, maxRows: n });
      return pack({ conta: digits(a.customer_id), periodo: periodLabel(a) }, rows, truncated);
    },
  },
  {
    name: "ad_performance",
    title: "Desempenho dos anúncios",
    description: "Anúncios com tipo, status, força do anúncio, URL final, títulos e descrições (RSA) e métricas no período.",
    inputSchema: {
      type: "object",
      properties: {
        ...commonProps, ...periodProps,
        campaign_id: { type: "string", description: "Opcional: filtrar uma campanha." },
        include_paused: { type: "boolean", description: "Incluir anúncios pausados (padrão true)." },
        limit: { type: "integer", description: "Máximo de linhas (padrão 200, máx. 1000)." },
      },
      required: ["customer_id"],
      additionalProperties: false,
    },
    annotations: { ...RO, title: "Anúncios" },
    async run(ads, a) {
      const n = limitOf(a, 200, 1000);
      const q = `SELECT campaign.name, ad_group.name, ad_group_ad.ad.id, ad_group_ad.ad.type, ad_group_ad.status, ad_group_ad.ad_strength, ad_group_ad.ad.final_urls, ad_group_ad.ad.responsive_search_ad.headlines, ad_group_ad.ad.responsive_search_ad.descriptions, metrics.impressions, metrics.clicks, metrics.ctr, metrics.cost_micros, metrics.conversions FROM ad_group_ad WHERE ${dateClause(a)}${campaignFilter(a)}${statusFilter(a, "ad_group_ad.status")} ORDER BY metrics.cost_micros DESC LIMIT ${n}`;
      const { rows, truncated } = await ads.search(a.customer_id, q, { loginCustomerId: a.login_customer_id, maxRows: n });
      // Deixa títulos/descrições como listas simples de texto.
      for (const r of rows) {
        const rsa = r.adGroupAd?.ad?.responsiveSearchAd;
        if (rsa) {
          r.adGroupAd.ad.responsiveSearchAd = {
            headlines: (rsa.headlines || []).map((h) => h.text).join(" | "),
            descriptions: (rsa.descriptions || []).map((d) => d.text).join(" | "),
          };
        }
        if (Array.isArray(r.adGroupAd?.ad?.finalUrls)) r.adGroupAd.ad.finalUrls = r.adGroupAd.ad.finalUrls.join(" ");
      }
      return pack({ conta: digits(a.customer_id), periodo: periodLabel(a) }, rows, truncated);
    },
  },
  {
    name: "run_gaql",
    title: "Consulta GAQL livre",
    description:
      "Executa qualquer consulta GAQL de leitura (SELECT ... FROM ...) na conta. Use para relatórios que as outras ferramentas não cobrem: Performance Max (asset_group, campaign_search_term_insight), geográfico, dispositivos, horários, conversões (conversion_action), extensões/assets, lances, recomendações, change_event etc. Campos *_micros voltam convertidos para moeda (sem o sufixo).",
    inputSchema: {
      type: "object",
      properties: {
        ...commonProps,
        query: { type: "string", description: "Consulta GAQL completa, ex.: SELECT campaign.name, metrics.clicks FROM campaign WHERE segments.date DURING LAST_7_DAYS" },
        max_rows: { type: "integer", description: "Máximo de linhas (padrão 500, máx. 5000)." },
      },
      required: ["customer_id", "query"],
      additionalProperties: false,
    },
    annotations: { ...RO, title: "Consulta GAQL" },
    async run(ads, a) {
      const query = String(a.query || "").trim();
      if (!/^select\s/i.test(query)) throw new Error("Só consultas SELECT são permitidas.");
      const n = Math.max(1, Math.min(5000, Math.floor(Number(a.max_rows) || 500)));
      const { rows, truncated } = await ads.search(a.customer_id, query, { loginCustomerId: a.login_customer_id, maxRows: n });
      return pack({ conta: digits(a.customer_id) }, rows, truncated);
    },
  },
];

const TOOL_MAP = Object.fromEntries(TOOLS.map((t) => [t.name, t]));

// ---------------------------------------------------------------- MCP (Streamable HTTP, sem sessão)

async function bearerGrant(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  return kvGet(env, `at:${await sha256(auth.slice(7).trim())}`);
}

function unauthorized(origin, desc = "Token ausente ou inválido.") {
  return json({ error: "invalid_token", error_description: desc }, 401, {
    "WWW-Authenticate": `Bearer realm="${SERVER_NAME}", error="invalid_token", resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
  });
}

async function handleRpc(msg, ctx) {
  const { id, method, params } = msg || {};
  const isNotification = id === undefined || id === null;
  const ok = (result) => ({ jsonrpc: "2.0", id, result });
  const fail = (code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

  if (!msg || msg.jsonrpc !== "2.0" || typeof method !== "string") {
    return msg && "result" in msg ? null : fail(-32600, "Requisição JSON-RPC inválida.");
  }
  if (isNotification) return null;

  switch (method) {
    case "initialize": {
      const requested = params?.protocolVersion;
      return ok({
        protocolVersion: SUPPORTED_PROTOCOLS.includes(requested) ? requested : SUPPORTED_PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: SERVER_NAME, title: "Google Ads (somente leitura)", version: SERVER_VERSION },
        instructions:
          "Acesso somente leitura ao Google Ads. Comece por list_accounts para obter os IDs das contas. Use campaign_performance, keyword_performance, search_terms, ad_performance e daily_performance para relatórios comuns, e run_gaql para qualquer outra consulta. A cota é de cerca de 2.880 consultas por dia: prefira poucas consultas bem filtradas.",
      });
    }
    case "ping":
      return ok({});
    case "tools/list":
      return ok({ tools: TOOLS.map(({ name, title, description, inputSchema, annotations }) => ({ name, title, description, inputSchema, annotations })) });
    case "tools/call": {
      const tool = TOOL_MAP[params?.name];
      if (!tool) return fail(-32602, `Ferramenta desconhecida: ${params?.name}`);
      try {
        const text = await tool.run(new Ads(ctx.env, ctx.grant.grantId), params.arguments || {});
        return ok({ content: [{ type: "text", text }] });
      } catch (e) {
        return ok({ content: [{ type: "text", text: `Erro: ${e.message}` }], isError: true });
      }
    }
    case "resources/list":
      return ok({ resources: [] });
    case "prompts/list":
      return ok({ prompts: [] });
    default:
      return fail(-32601, `Método não suportado: ${method}`);
  }
}

async function handleMcp(request, env, origin) {
  if (request.method === "GET") {
    return new Response("Este servidor não oferece stream SSE; use POST.", { status: 405, headers: { Allow: "POST", ...CORS } });
  }
  if (request.method === "DELETE") return new Response(null, { status: 204, headers: CORS });
  if (request.method !== "POST") return new Response(null, { status: 405, headers: CORS });

  const grant = await bearerGrant(request, env);
  if (!grant) return unauthorized(origin);
  if (!(await kvGet(env, `grant:${grant.grantId}`))) return unauthorized(origin, "Acesso revogado.");

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "JSON inválido." } }, 400);
  }
  const ctx = { env, grant };
  if (Array.isArray(body)) {
    const out = (await Promise.all(body.map((m) => handleRpc(m, ctx)))).filter(Boolean);
    return out.length ? json(out) : new Response(null, { status: 202, headers: CORS });
  }
  const out = await handleRpc(body, ctx);
  return out ? json(out) : new Response(null, { status: 202, headers: CORS });
}

// ---------------------------------------------------------------- roteador

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = url.origin;
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    try {
      if (path === "/.well-known/oauth-authorization-server" || path.startsWith("/.well-known/oauth-authorization-server/") || path === "/.well-known/openid-configuration") {
        return json(asMetadata(origin));
      }
      if (path === "/.well-known/oauth-protected-resource" || path.startsWith("/.well-known/oauth-protected-resource/")) {
        return json(prMetadata(origin));
      }
      if (path === "/register" && request.method === "POST") return handleRegister(request, env);
      if (path === "/authorize" && request.method === "GET") return handleAuthorize(url, env);
      if (path === "/callback" && request.method === "GET") return handleCallback(url, env);
      if (path === "/token" && request.method === "POST") return handleToken(request, env);
      if (path === "/revoke" && request.method === "POST") return handleRevoke(request, env);
      if (path === "/mcp" || path === "/sse") return handleMcp(request, env, origin);
      if (path === "/status" && request.method === "GET") {
        const ok = (v, min = 1) => (typeof v === "string" && v.trim().length >= min ? "✅ configurado" : "❌ faltando");
        const kv = env.OAUTH_KV ? "✅ ligado" : "❌ faltando";
        const rows = [
          ["GOOGLE_CLIENT_ID", ok(env.GOOGLE_CLIENT_ID, 10) + (env.GOOGLE_CLIENT_ID && !env.GOOGLE_CLIENT_ID.trim().endsWith(".apps.googleusercontent.com") ? " (⚠️ formato estranho)" : "")],
          ["GOOGLE_CLIENT_SECRET", ok(env.GOOGLE_CLIENT_SECRET, 10)],
          ["ENCRYPTION_KEY", ok(env.ENCRYPTION_KEY, 16)],
          ["OAUTH_KV", kv],
          ["ALLOWED_EMAILS", escapeHtml(env.ALLOWED_EMAILS || "❌ vazio")],
          ["ADS_API_VERSION", escapeHtml(env.ADS_API_VERSION || "v26")],
          ["URI de redirecionamento (Google)", `<code>${escapeHtml(origin)}/callback</code>`],
          ["URL do conector (Claude)", `<code>${escapeHtml(origin)}/mcp</code>`],
        ];
        return html(`<h2>Verificação da configuração</h2><table cellpadding="6">${rows.map(([k, v]) => `<tr><td><b>${k}</b></td><td>${v}</td></tr>`).join("")}</table>`);
      }
      if (path === "/" && request.method === "GET") {
        return html(`<h2>Google Ads MCP</h2><p>Servidor ativo. No Claude, adicione um conector personalizado com o endereço:</p><p><code>${escapeHtml(origin)}/mcp</code></p>`);
      }
      return new Response("Não encontrado", { status: 404 });
    } catch (e) {
      console.error(e);
      return json({ error: "server_error", error_description: String(e.message || e) }, 500);
    }
  },
};

export const _test = { flatten, dateClause, digits, TOOLS };
