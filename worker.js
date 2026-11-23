// ============================================================
// Cloudflare Worker - Gestor de enlaces y QR con roles
// Versión con DURABLE OBJECTS (consistencia fuerte)
//
// ARQUITECTURA
//   Worker (este archivo)  -> rutas, sesiones, validaciones, contraseñas.
//   Durable Object Registry -> ÚNICA fuente de verdad (SQLite): enlaces,
//        usuarios e intentos de login. Procesa una operación a la vez,
//        por eso reclamar un enlace tiene un único ganador, siempre.
//   KV (binding "app")     -> solo se lee una vez para migrar tus datos
//        anteriores al Durable Object. Luego ya no se usa.
//
// ROLES
//   admin -> crea (uno a uno o por CSV), edita, elimina, activa/desactiva
//            enlaces, asigna propietarios y gestiona usuarios.
//   user  -> ve los enlaces activos SIN propietario (para reclamarlos) y los
//            suyos. Solo cambia el destino (URL) de sus propios enlaces.
//
// REQUISITOS (ver wrangler.toml)
//   Binding Durable Object:  REGISTRY  (clase Registry)
//   Binding KV (migración):  app
//   Secrets: ADMIN_USER, ADMIN_PASS, TOKEN_SECRET
// ============================================================

import { DurableObject } from "cloudflare:workers";

const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días
const LINK_PREFIX = "link:"; // solo para migrar desde KV
const USER_PREFIX = "user:"; // solo para migrar desde KV

// Si al iniciar sesión ves el error 1102 (CPU excedida), baja este valor
// ANTES de crear usuarios (ej. 50000). Cada cuenta guarda sus iteraciones.
const PBKDF2_ITER = 100000;

const MAX_URL = 2048;
const MAX_NOTES = 150;
const MAX_BULK_ROWS = 500;  // filas por petición de importación
const MAX_FAILS = 5;        // intentos fallidos permitidos por IP
const FAIL_TTL_MS = 15 * 60 * 1000;
const MIGRATE_OPS = 40;     // lecturas de KV por paso de migración

const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
const CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DUMMY_SALT = "0".repeat(32);

// ---------- Respuestas ----------
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*", // Si quieres, cambia * por el dominio de tu panel
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS_HEADERS }
  });
}
const fail = (error, status = 200) => json({ success: false, error }, status);

// ---------- Utilidades compartidas ----------
function randomCode(len = 6) {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return [...bytes].map(b => chars[b % chars.length]).join("");
}

// ============================================================
// DURABLE OBJECT: fuente única de verdad
// Cada método público es atómico respecto a los demás: el objeto
// ejecuta una operación a la vez y las escrituras SQL síncronas
// no pueden intercalarse con otras peticiones.
// ============================================================
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS links (
     code TEXT PRIMARY KEY,
     target_url TEXT NOT NULL,
     notes TEXT NOT NULL DEFAULT '',
     clicks INTEGER NOT NULL DEFAULT 0,
     active INTEGER NOT NULL DEFAULT 1,
     owner TEXT,
     created_at INTEGER NOT NULL,
     claimed_at INTEGER
   )`,
  `CREATE INDEX IF NOT EXISTS idx_links_owner ON links(owner)`,
  `CREATE TABLE IF NOT EXISTS users (
     username TEXT PRIMARY KEY,
     salt TEXT NOT NULL,
     iter INTEGER NOT NULL,
     hash TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     pwd_version INTEGER NOT NULL DEFAULT 0,
     must_change INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS fails (
     ip TEXT PRIMARY KEY,
     n INTEGER NOT NULL,
     expires INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`
];

export class Registry extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.migrated = false;
    this.migrating = null;
    ctx.blockConcurrencyWhile(async () => {
      for (const stmt of SCHEMA) this.sql.exec(stmt);
      // Bases creadas antes de esta versión: agrega la columna sin perder datos
      const cols = this.sql.exec("PRAGMA table_info(users)").toArray();
      if (!cols.some(c => c.name === "must_change")) {
        this.sql.exec("ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0");
      }
      // Sin binding KV no hay nada que migrar
      this.migrated = this.#meta("mig_phase") === "done" || !env.app;
    });
  }

  // ---------- helpers privados ----------
  #meta(k) {
    const r = this.sql.exec("SELECT v FROM meta WHERE k = ?", k).toArray();
    return r.length ? r[0].v : null;
  }
  #setMeta(k, v) {
    this.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", k, v);
  }

  #link(code) {
    const r = this.sql.exec("SELECT * FROM links WHERE code = ?", code).toArray();
    return r.length ? this.#toLink(r[0]) : null;
  }
  #toLink(r) {
    return {
      id: r.code,
      shortCode: r.code,
      targetUrl: r.target_url,
      notes: r.notes,
      clicks: r.clicks,
      active: !!r.active,
      owner: r.owner || null,
      createdAt: r.created_at,
      claimedAt: r.claimed_at || 0
    };
  }
  #userRow(username) {
    const r = this.sql.exec("SELECT * FROM users WHERE username = ?", username).toArray();
    return r.length ? {
      username: r[0].username, salt: r[0].salt, iter: r[0].iter, hash: r[0].hash,
      createdAt: r[0].created_at, pwdVersion: r[0].pwd_version,
      mustChange: !!r[0].must_change
    } : null;
  }
  #codeExists(code) {
    return this.sql.exec("SELECT 1 FROM links WHERE code = ?", code).toArray().length > 0;
  }

  // ---------- migración desde KV (una sola vez, por lotes) ----------
  #importRaw(phase, raw) {
    let o;
    try { o = JSON.parse(raw); } catch { return 0; }
    if (!o || typeof o !== "object") return 0;

    if (phase === "users") {
      if (!USERNAME_RE.test(String(o.username || "")) || !o.salt || !o.hash) return 0;
      const r = this.sql.exec(
        `INSERT OR IGNORE INTO users (username, salt, iter, hash, created_at, pwd_version)
         VALUES (?, ?, ?, ?, ?, ?)`,
        o.username, o.salt, o.iter || PBKDF2_ITER, o.hash,
        o.createdAt || Date.now(), o.pwdChangedAt ? 1 : 0
      );
      return r.rowsWritten > 0 ? 1 : 0;
    }

    if (!o.shortCode || !o.targetUrl) return 0;
    const r = this.sql.exec(
      `INSERT OR IGNORE INTO links (code, target_url, notes, clicks, active, owner, created_at, claimed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      String(o.shortCode), String(o.targetUrl), String(o.notes || ""), Number(o.clicks) || 0,
      o.active === false ? 0 : 1, o.owner || null, Number(o.createdAt) || Date.now(), o.claimedAt || null
    );
    return r.rowsWritten > 0 ? 1 : 0;
  }

  // Importa un registro suelto desde KV (para no perder enlaces mientras dura la migración)
  async #pull(phase, key) {
    if (!this.env.app) return false;
    const raw = await this.env.app.get((phase === "users" ? USER_PREFIX : LINK_PREFIX) + key);
    return raw ? this.#importRaw(phase, raw) > 0 : false;
  }

  migrateStep() {
    if (this.migrated) return Promise.resolve({ done: true, imported: 0 });
    if (!this.migrating) {
      this.migrating = this.#doMigrateStep().finally(() => { this.migrating = null; });
    }
    return this.migrating;
  }

  async #doMigrateStep() {
    let ops = 0;
    let imported = 0;
    while (ops < MIGRATE_OPS && !this.migrated) {
      const phase = this.#meta("mig_phase") || "users";
      const cursor = this.#meta("mig_cursor") || undefined;
      const prefix = phase === "users" ? USER_PREFIX : LINK_PREFIX;

      const page = await this.env.app.list({ prefix, cursor, limit: 20 });
      const raws = await Promise.all(page.keys.map(k => this.env.app.get(k.name)));
      ops += 1 + page.keys.length;
      for (const raw of raws) if (raw) imported += this.#importRaw(phase, raw);

      if (!page.list_complete) {
        this.#setMeta("mig_cursor", page.cursor);
      } else if (phase === "users") {
        this.#setMeta("mig_phase", "links");
        this.#setMeta("mig_cursor", "");
      } else {
        this.#setMeta("mig_phase", "done");
        this.migrated = true;
      }
    }
    return { done: this.migrated, imported };
  }

  async #ready() {
    if (!this.migrated) await this.migrateStep();
  }

  // ---------- anti fuerza bruta ----------
  isBlocked(ip) {
    const r = this.sql.exec("SELECT n, expires FROM fails WHERE ip = ?", ip).toArray();
    return r.length > 0 && r[0].expires > Date.now() && r[0].n >= MAX_FAILS;
  }
  addFail(ip) {
    const now = Date.now();
    this.sql.exec("DELETE FROM fails WHERE expires < ?", now);
    const r = this.sql.exec("SELECT n FROM fails WHERE ip = ?", ip).toArray();
    const n = (r.length ? r[0].n : 0) + 1;
    this.sql.exec("INSERT OR REPLACE INTO fails (ip, n, expires) VALUES (?, ?, ?)", ip, n, now + FAIL_TTL_MS);
  }
  clearFails(ip) {
    this.sql.exec("DELETE FROM fails WHERE ip = ?", ip);
  }

  // ---------- redirección pública ----------
  async resolve(code) {
    await this.#ready();
    let link = this.#link(code);
    if (!link && !this.migrated && await this.#pull("links", code)) link = this.#link(code);
    if (!link) return { ok: false, status: 404, error: "El enlace acortado no existe." };
    if (!link.active) return { ok: false, status: 403, error: "Este enlace está desactivado." };
    this.sql.exec("UPDATE links SET clicks = clicks + 1 WHERE code = ?", code);
    return { ok: true, targetUrl: link.targetUrl };
  }

  // ---------- enlaces ----------
  async listLinks() {
    await this.#ready();
    return this.sql.exec("SELECT * FROM links ORDER BY created_at DESC, code ASC")
      .toArray().map(r => this.#toLink(r));
  }

  // rows: [{ targetUrl, shortCode?, notes }] ya validadas por el Worker.
  // Devuelve un resultado por fila. La comprobación de "ya existe" y la
  // inserción ocurren juntas, sin posibilidad de duplicados.
  async createLinks(rows) {
    await this.#ready();
    if (!this.migrated) {
      for (const r of rows) if (r.shortCode) await this.#pull("links", r.shortCode);
    }
    const out = [];
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      for (const r of rows) {
        let code = r.shortCode;
        if (code) {
          if (this.#codeExists(code)) { out.push({ ok: false, error: "Ese código ya existe" }); continue; }
        } else {
          do { code = randomCode(); } while (this.#codeExists(code));
        }
        this.sql.exec(
          "INSERT INTO links (code, target_url, notes, created_at) VALUES (?, ?, ?, ?)",
          code, r.targetUrl, r.notes || "", now
        );
        out.push({ ok: true, link: this.#link(code) });
      }
    });
    return out;
  }

  async updateLink(code, patch) {
    await this.#ready();
    const link = this.#link(code);
    if (!link) return null;
    if (patch.targetUrl !== undefined) this.sql.exec("UPDATE links SET target_url = ? WHERE code = ?", patch.targetUrl, code);
    if (patch.notes !== undefined) this.sql.exec("UPDATE links SET notes = ? WHERE code = ?", patch.notes, code);
    return this.#link(code);
  }

  async setActive(code, active) {
    await this.#ready();
    if (!this.#link(code)) return null;
    this.sql.exec("UPDATE links SET active = ? WHERE code = ?", active ? 1 : 0, code);
    return this.#link(code);
  }

  // owner vacío = liberar. Devuelve { ok, link } o { ok:false, error }
  async setOwner(code, owner) {
    await this.#ready();
    if (!this.#link(code)) return { ok: false, error: "Enlace no encontrado" };
    if (owner) {
      if (!this.#userRow(owner)) return { ok: false, error: "Ese usuario no existe" };
      this.sql.exec("UPDATE links SET owner = ?, claimed_at = ? WHERE code = ?", owner, Date.now(), code);
    } else {
      this.sql.exec("UPDATE links SET owner = NULL, claimed_at = NULL WHERE code = ?", code);
    }
    return { ok: true, link: this.#link(code) };
  }

  async deleteLink(code) {
    await this.#ready();
    this.sql.exec("DELETE FROM links WHERE code = ?", code);
    return true;
  }

  // ---------- usuario: reclamar y editar lo suyo ----------
  async myLinks(username) {
    await this.#ready();
    return this.sql.exec("SELECT * FROM links WHERE owner = ? ORDER BY claimed_at DESC, code ASC", username)
      .toArray().map(r => this.#toLink(r));
  }

  // Solo activos y sin dueño. No se expone la URL destino.
  async available() {
    await this.#ready();
    return this.sql.exec("SELECT code, notes FROM links WHERE active = 1 AND owner IS NULL ORDER BY code ASC")
      .toArray().map(r => ({ id: r.code, shortCode: r.code, notes: r.notes }));
  }

  // RECLAMO ATÓMICO: la lectura y la escritura ocurren sin que ninguna otra
  // petición pueda intercalarse, así que solo una persona puede ganar.
  async claim(code, username) {
    await this.#ready();
    let result = { ok: false, error: "Este enlace ya no está disponible" };
    this.ctx.storage.transactionSync(() => {
      const link = this.#link(code);
      if (!link || !link.active || link.owner) return;
      if (!this.#userRow(username)) return;
      this.sql.exec("UPDATE links SET owner = ?, claimed_at = ? WHERE code = ?", username, Date.now(), code);
      result = { ok: true, link: this.#link(code) };
    });
    return result;
  }

  async updateOwnUrl(code, username, targetUrl) {
    await this.#ready();
    const link = this.#link(code);
    if (!link || link.owner !== username) return null;
    this.sql.exec("UPDATE links SET target_url = ? WHERE code = ?", targetUrl, code);
    return this.#link(code);
  }

  // ---------- usuarios ----------
  async getUser(username) {
    await this.#ready();
    let u = this.#userRow(username);
    if (!u && !this.migrated && await this.#pull("users", username)) u = this.#userRow(username);
    return u;
  }

  async createUser(rec) {
    await this.#ready();
    if (!this.migrated) await this.#pull("users", rec.username);
    let result = { ok: false, error: "Ese usuario ya existe" };
    this.ctx.storage.transactionSync(() => {
      if (this.#userRow(rec.username)) return;
      this.sql.exec(
        "INSERT INTO users (username, salt, iter, hash, created_at, must_change) VALUES (?, ?, ?, ?, ?, 1)",
        rec.username, rec.salt, rec.iter, rec.hash, Date.now()
      );
      result = { ok: true };
    });
    return result;
  }

  // Cambia la contraseña e incrementa la versión (invalida sesiones anteriores).
  // mustChange = true cuando la define el administrador (contraseña temporal).
  async setPassword(username, rec, mustChange = false) {
    await this.#ready();
    if (!this.#userRow(username)) return null;
    this.sql.exec(
      `UPDATE users SET salt = ?, iter = ?, hash = ?, pwd_version = pwd_version + 1, must_change = ?
        WHERE username = ?`,
      rec.salt, rec.iter, rec.hash, mustChange ? 1 : 0, username
    );
    return this.#userRow(username).pwdVersion;
  }

  async listUsers() {
    await this.#ready();
    return this.sql.exec(
      `SELECT u.username, u.created_at,
              u.must_change,
              (SELECT COUNT(*) FROM links l WHERE l.owner = u.username) AS links
         FROM users u ORDER BY u.username ASC`
    ).toArray().map(r => ({
      username: r.username, createdAt: r.created_at, links: r.links, mustChange: !!r.must_change
    }));
  }

  // Elimina la cuenta y libera sus enlaces en una sola operación atómica
  async deleteUser(username) {
    await this.#ready();
    let result = { ok: false, error: "Usuario no encontrado" };
    this.ctx.storage.transactionSync(() => {
      if (!this.#userRow(username)) return;
      const released = this.sql.exec("SELECT COUNT(*) AS n FROM links WHERE owner = ?", username).one().n;
      this.sql.exec("UPDATE links SET owner = NULL, claimed_at = NULL WHERE owner = ?", username);
      this.sql.exec("DELETE FROM users WHERE username = ?", username);
      result = { ok: true, released };
    });
    return result;
  }
}

// ============================================================
// WORKER
// ============================================================
const enc = new TextEncoder();
const registry = env => env.REGISTRY.get(env.REGISTRY.idFromName("main"));

// ---------- Criptografía ----------
function toHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function randomHex(n) {
  return toHex(crypto.getRandomValues(new Uint8Array(n)));
}
function b64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}

// Comparación en tiempo constante
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hashPassword(password, saltHex, iterations) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations },
    key, 256
  );
  return toHex(new Uint8Array(bits));
}

async function makePasswordRecord(password) {
  const salt = randomHex(16);
  return { salt, iter: PBKDF2_ITER, hash: await hashPassword(password, salt, PBKDF2_ITER) };
}

// ---------- Tokens de sesión ----------
// pv = versión de contraseña: al cambiarla, las sesiones anteriores dejan de valer
async function makeToken(env, username, role, pv = 0) {
  const now = Date.now();
  const payload = b64url(JSON.stringify({ u: username, r: role, pv, iat: now, exp: now + TOKEN_TTL_MS }));
  return payload + "." + await hmacHex(env.TOKEN_SECRET, payload);
}

// Devuelve { username, role } o null. Para usuarios comprueba que la cuenta
// siga existiendo y que la contraseña no haya cambiado desde que se emitió.
async function authenticate(env, token) {
  if (typeof token !== "string") return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  if (!safeEqual(sig, await hmacHex(env.TOKEN_SECRET, payload))) return null;

  let data;
  try { data = JSON.parse(b64urlDecode(payload)); } catch { return null; }
  if (!data || !data.exp || data.exp < Date.now()) return null;

  if (data.r === "admin") {
    if (!safeEqual(String(data.u).toLowerCase(), String(env.ADMIN_USER).toLowerCase())) return null;
    return { username: String(env.ADMIN_USER), role: "admin" };
  }
  if (data.r === "user") {
    const rec = await registry(env).getUser(String(data.u || "").toLowerCase());
    if (!rec) return null;
    if (rec.pwdVersion !== (data.pv || 0)) return null;
    return { username: rec.username, role: "user", mustChange: rec.mustChange };
  }
  return null;
}

// ---------- Validaciones ----------
function parseUrl(input) {
  let s = String(input || "").trim();
  if (!s || s.length > MAX_URL) return null;
  if (!/^https?:\/\//i.test(s)) {
    // Rechaza otros esquemas (javascript:, data:, ftp://, etc.)
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^(javascript|data|vbscript|file|blob):/i.test(s)) return null;
    s = "https://" + s;
  }
  try {
    const u = new URL(s);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (!u.hostname) return null;
    return u.href;
  } catch {
    return null;
  }
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 128;
}

// Valida una fila de enlace. Devuelve { row } o { error }
function validateLinkRow(input) {
  const targetUrl = parseUrl(input.targetUrl);
  if (!targetUrl) return { error: "La URL destino no es válida (debe ser http o https)" };

  const notes = String(input.notes ?? "").trim();
  if (notes.length > MAX_NOTES) return { error: `Las notas no pueden superar ${MAX_NOTES} caracteres` };

  const shortCode = String(input.shortCode ?? "").trim();
  if (shortCode && !CODE_RE.test(shortCode)) {
    return { error: "El código solo puede tener letras, números, - y _ (máx. 64)" };
  }
  return { row: { targetUrl, notes, shortCode } };
}

// ============================================================
// PÚBLICO: redirección
// ============================================================
async function redirectLookup(env, code) {
  if (!code) return fail("Falta el parámetro ?r=codigo", 400);
  if (code.length > 64) return fail("El enlace acortado no existe.", 404);

  const r = await registry(env).resolve(code);
  return r.ok ? json({ success: true, targetUrl: r.targetUrl }) : fail(r.error, r.status);
}

// ============================================================
// LOGIN
// ============================================================
async function handleLogin(env, body, ip) {
  const reg = registry(env);
  if (await reg.isBlocked(ip)) {
    return fail("Demasiados intentos fallidos. Intenta de nuevo en 15 minutos.", 429);
  }

  const username = String(body.user || "").trim().toLowerCase();
  const pass = String(body.pass || "");
  let role = null;
  let name = username;
  let pv = 0;
  let mustChange = false;

  if (safeEqual(username, String(env.ADMIN_USER).toLowerCase())) {
    if (safeEqual(pass, env.ADMIN_PASS)) { role = "admin"; name = String(env.ADMIN_USER); }
  } else {
    const rec = USERNAME_RE.test(username) ? await reg.getUser(username) : null;
    // Se calcula el hash siempre para que el tiempo de respuesta no revele si la cuenta existe
    const h = await hashPassword(pass, rec ? rec.salt : DUMMY_SALT, rec ? rec.iter : PBKDF2_ITER);
    if (rec && safeEqual(h, rec.hash)) {
      role = "user"; name = rec.username; pv = rec.pwdVersion; mustChange = rec.mustChange;
    }
  }

  if (!role) {
    await reg.addFail(ip);
    return fail("Usuario o contraseña incorrectos", 401);
  }

  await reg.clearFails(ip);
  return json({ success: true, token: await makeToken(env, name, role, pv), role, username: name, mustChange });
}

// ============================================================
// ADMIN: enlaces
// ============================================================
async function adminMigrate(env) {
  const r = await registry(env).migrateStep();
  return json({ success: true, done: r.done, imported: r.imported });
}

async function adminList(env) {
  return json({ success: true, data: await registry(env).listLinks() });
}

async function adminCreate(env, body) {
  const v = validateLinkRow(body);
  if (v.error) return fail(v.error);
  const [res] = await registry(env).createLinks([v.row]);
  return res.ok ? json({ success: true, data: res.link }) : fail(res.error);
}

// Importación masiva (CSV): body.rows = [{ line, targetUrl, shortCode, notes }]
async function adminCreateBulk(env, body) {
  if (!Array.isArray(body.rows) || body.rows.length === 0) return fail("No hay filas para importar");
  if (body.rows.length > MAX_BULK_ROWS) return fail(`Máximo ${MAX_BULK_ROWS} filas por petición`);

  const failed = [];
  const valid = [];
  body.rows.forEach((raw, i) => {
    const line = Number.isFinite(raw && raw.line) ? raw.line : i + 1;
    const v = validateLinkRow(raw || {});
    if (v.error) failed.push({ line, error: v.error });
    else valid.push({ line, row: v.row });
  });

  let created = 0;
  if (valid.length) {
    const results = await registry(env).createLinks(valid.map(x => x.row));
    results.forEach((res, i) => {
      if (res.ok) created++;
      else failed.push({ line: valid[i].line, error: res.error });
    });
  }
  failed.sort((a, b) => a.line - b.line);
  return json({ success: true, created, failed });
}

async function adminUpdate(env, body) {
  const patch = {};
  if (body.targetUrl !== undefined && body.targetUrl !== null && String(body.targetUrl).trim() !== "") {
    const targetUrl = parseUrl(body.targetUrl);
    if (!targetUrl) return fail("La URL destino no es válida (debe ser http o https)");
    patch.targetUrl = targetUrl;
  }
  if (body.notes !== undefined && body.notes !== null) {
    const notes = String(body.notes).trim();
    if (notes.length > MAX_NOTES) return fail(`Las notas no pueden superar ${MAX_NOTES} caracteres`);
    patch.notes = notes;
  }
  const link = await registry(env).updateLink(String(body.id || ""), patch);
  return link ? json({ success: true, data: link }) : fail("Enlace no encontrado");
}

async function adminSetActive(env, body) {
  const link = await registry(env).setActive(String(body.id || ""), body.active === true);
  return link ? json({ success: true, data: link }) : fail("Enlace no encontrado");
}

// owner vacío = liberar el enlace (queda disponible para reclamar)
async function adminSetOwner(env, body) {
  const owner = String(body.owner || "").trim().toLowerCase();
  const r = await registry(env).setOwner(String(body.id || ""), owner);
  return r.ok ? json({ success: true, data: r.link }) : fail(r.error);
}

async function adminDelete(env, body) {
  const id = String(body.id || "");
  if (!id) return fail("Falta el id");
  await registry(env).deleteLink(id);
  return json({ success: true });
}

// ============================================================
// ADMIN: usuarios
// ============================================================
async function usersList(env) {
  return json({ success: true, data: await registry(env).listUsers() });
}

async function userCreate(env, body) {
  const username = String(body.username || "").trim().toLowerCase();
  if (!USERNAME_RE.test(username)) {
    return fail("Usuario inválido: 3 a 32 caracteres (letras minúsculas, números, . _ -)");
  }
  if (safeEqual(username, String(env.ADMIN_USER).toLowerCase())) return fail("Ese nombre de usuario está reservado");
  if (!validPassword(body.password)) return fail("La contraseña debe tener entre 8 y 128 caracteres");

  const r = await registry(env).createUser({ username, ...(await makePasswordRecord(body.password)) });
  return r.ok ? json({ success: true, username }) : fail(r.error);
}

async function userSetPassword(env, body) {
  if (!validPassword(body.password)) return fail("La contraseña debe tener entre 8 y 128 caracteres");
  const username = String(body.username || "").trim().toLowerCase();
  // Contraseña temporal: el usuario deberá cambiarla en su próximo inicio de sesión
  const v = await registry(env).setPassword(username, await makePasswordRecord(body.password), true);
  return v === null ? fail("Usuario no encontrado") : json({ success: true });
}

// Elimina la cuenta y libera sus enlaces (vuelven a estar disponibles)
async function userDelete(env, body) {
  const r = await registry(env).deleteUser(String(body.username || "").trim().toLowerCase());
  return r.ok ? json({ success: true, released: r.released }) : fail(r.error);
}

// ============================================================
// USUARIO: solo lo suyo
// ============================================================
async function myLinks(env, body, auth) {
  return json({ success: true, data: await registry(env).myLinks(auth.username) });
}

async function availableLinks(env) {
  return json({ success: true, data: await registry(env).available() });
}

async function claimLink(env, body, auth) {
  const r = await registry(env).claim(String(body.id || ""), auth.username);
  return r.ok ? json({ success: true, data: r.link }) : fail(r.error);
}

// Lo ÚNICO que un usuario puede modificar: el destino de sus propios enlaces
async function updateOwnUrl(env, body, auth) {
  const targetUrl = parseUrl(body.targetUrl);
  if (!targetUrl) return fail("La URL destino no es válida (debe ser http o https)");
  const link = await registry(env).updateOwnUrl(String(body.id || ""), auth.username, targetUrl);
  return link ? json({ success: true, data: link }) : fail("Enlace no encontrado");
}

async function changeOwnPassword(env, body, auth) {
  const reg = registry(env);
  const rec = await reg.getUser(auth.username);
  if (!rec) return fail("No autorizado", 401);
  if (!validPassword(body.password)) return fail("La nueva contraseña debe tener entre 8 y 128 caracteres");

  const h = await hashPassword(String(body.current || ""), rec.salt, rec.iter);
  if (!safeEqual(h, rec.hash)) return fail("La contraseña actual no es correcta");
  if (body.password === body.current) return fail("La nueva contraseña debe ser diferente a la actual");

  const pv = await reg.setPassword(auth.username, await makePasswordRecord(body.password), false);
  // Se entrega un token nuevo para que la sesión actual siga válida
  return json({ success: true, token: await makeToken(env, auth.username, "user", pv) });
}

// ============================================================
// Rutas y permisos
// ============================================================
const ROUTES = {
  // Administrador
  migrate:         { roles: ["admin"], fn: adminMigrate },
  list:            { roles: ["admin"], fn: adminList },
  create:          { roles: ["admin"], fn: adminCreate },
  create_bulk:     { roles: ["admin"], fn: adminCreateBulk },
  update:          { roles: ["admin"], fn: adminUpdate },
  set_active:      { roles: ["admin"], fn: adminSetActive },
  set_owner:       { roles: ["admin"], fn: adminSetOwner },
  delete:          { roles: ["admin"], fn: adminDelete },
  users_list:      { roles: ["admin"], fn: usersList },
  user_create:     { roles: ["admin"], fn: userCreate },
  user_password:   { roles: ["admin"], fn: userSetPassword },
  user_delete:     { roles: ["admin"], fn: userDelete },
  // Usuario
  my_links:        { roles: ["user"], fn: myLinks },
  available:       { roles: ["user"], fn: availableLinks },
  claim:           { roles: ["user"], fn: claimLink },
  update_url:      { roles: ["user"], fn: updateOwnUrl },
  change_password: { roles: ["user"], fn: changeOwnPassword }
};

// ---------- Entrada principal ----------
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (!env.REGISTRY) {
        return fail("Falta el binding del Durable Object REGISTRY. Despliega con wrangler (ver wrangler.toml).", 500);
      }
      if (!env.ADMIN_USER || !env.ADMIN_PASS || !env.TOKEN_SECRET) {
        return fail("Faltan secrets: ADMIN_USER, ADMIN_PASS y TOKEN_SECRET.", 500);
      }

      // GET público: redirección
      if (request.method === "GET") {
        const code = new URL(request.url).searchParams.get("r");
        return await redirectLookup(env, code);
      }

      if (request.method !== "POST") return fail("Método no permitido", 405);

      let body;
      try { body = await request.json(); }
      catch { return fail("JSON inválido", 400); }
      if (!body || typeof body !== "object") return fail("JSON inválido", 400);

      if (body.action === "login") {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        return await handleLogin(env, body, ip);
      }

      // Todo lo demás requiere sesión válida
      const auth = await authenticate(env, body.token);
      if (!auth) return json({ success: false, error: "No autorizado", unauthorized: true }, 401);

      // Contraseña temporal: hasta cambiarla, lo único permitido es cambiarla
      if (auth.role === "user" && auth.mustChange && body.action !== "change_password") {
        return json({
          success: false,
          error: "Debes cambiar tu contraseña temporal antes de continuar.",
          mustChange: true
        }, 403);
      }

      const route = Object.hasOwn(ROUTES, body.action) ? ROUTES[body.action] : null;
      if (!route) return fail("Acción desconocida", 400);
      if (!route.roles.includes(auth.role)) return fail("Acceso denegado", 403);

      return await route.fn(env, body, auth);
    } catch (err) {
      return fail("Error interno: " + err.message, 500);
    }
  }
};
