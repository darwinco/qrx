// ============================================================
// Cloudflare Worker - Gestor de enlaces y QR con roles
// Versión con DURABLE OBJECTS (consistencia fuerte)
//
// ARQUITECTURA
//   Worker (este archivo)  -> rutas, sesiones, validaciones, contraseñas, Resend.
//   Durable Object Registry -> ÚNICA fuente de verdad (SQLite): enlaces,
//        usuarios, tokens de recuperación e intentos de login.
//   KV (binding "app")     -> solo se lee una vez para migrar tus datos
//        anteriores al Durable Object. Luego ya no se usa.
//
// ROLES
//   admin -> crea (uno a uno o por CSV), edita, elimina, activa/desactiva
//            enlaces, asigna propietarios y gestiona usuarios/correos.
//   user  -> ve los enlaces suyos, ve/actualiza su correo y cambia el
//            destino (URL) de sus propios enlaces.
//
// REQUISITOS (ver wrangler.toml)
//   Binding Durable Object:  REGISTRY  (clase Registry)
//   Binding KV (migración):  app
//   Secrets: ADMIN_USER, ADMIN_PASS, TOKEN_SECRET, RESEND_API_KEY
//   Vars/Secrets opcionales: FROM_EMAIL (ej. "no-reply@tudominio.com")
// ============================================================

import { DurableObject } from "cloudflare:workers";

const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días
const RESET_TTL_MS = 30 * 60 * 1000;        // 30 minutos para recuperar contraseña
const LINK_PREFIX = "link:"; // solo para migrar desde KV
const USER_PREFIX = "user:"; // solo para migrar desde KV

// Si al iniciar sesión ves el error 1102 (CPU excedida), baja este valor
// ANTES de crear usuarios (ej. 50000). Cada cuenta guarda sus iteraciones.
const PBKDF2_ITER = 100000;

const MAX_URL = 2048;
const MAX_NOTES = 150;
const MAX_EMAIL = 160;
const MAX_BULK_ROWS = 500;  // filas por petición de importación
const MAX_FAILS = 5;        // intentos fallidos permitidos por IP
const FAIL_TTL_MS = 15 * 60 * 1000;
const MIGRATE_OPS = 40;     // lecturas de KV por paso de migración

const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
const CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
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

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]
  ));
}

// ============================================================
// DURABLE OBJECT: fuente única de verdad
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
     email TEXT NOT NULL DEFAULT '',
     salt TEXT NOT NULL,
     iter INTEGER NOT NULL,
     hash TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     pwd_version INTEGER NOT NULL DEFAULT 0,
     must_change INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS password_resets (
     token_hash TEXT PRIMARY KEY,
     username TEXT NOT NULL,
     expires_at INTEGER NOT NULL,
     used INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(username)`,
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
      // Bases creadas antes de esta versión: agrega columnas sin perder datos
      const cols = this.sql.exec("PRAGMA table_info(users)").toArray();
      if (!cols.some(c => c.name === "must_change")) {
        this.sql.exec("ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0");
      }
      if (!cols.some(c => c.name === "email")) {
        this.sql.exec("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''");
      }
      this.migrated = this.#meta("mig_phase") === "done" || !env.app;
    });
  }

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
      username: r[0].username,
      email: r[0].email || "",
      salt: r[0].salt,
      iter: r[0].iter,
      hash: r[0].hash,
      createdAt: r[0].created_at,
      pwdVersion: r[0].pwd_version,
      mustChange: !!r[0].must_change
    } : null;
  }
  #userByEmail(email) {
    const normalized = String(email || "").trim().toLowerCase();
    if (!normalized) return null;
    const r = this.sql.exec("SELECT * FROM users WHERE LOWER(email) = ?", normalized).toArray();
    return r.length ? this.#userRow(r[0].username) : null;
  }
  #codeExists(code) {
    return this.sql.exec("SELECT 1 FROM links WHERE code = ?", code).toArray().length > 0;
  }

  // ---------- migración desde KV ----------
  #importRaw(phase, raw) {
    let o;
    try { o = JSON.parse(raw); } catch { return 0; }
    if (!o || typeof o !== "object") return 0;

    if (phase === "users") {
      if (!USERNAME_RE.test(String(o.username || "")) || !o.salt || !o.hash) return 0;
      const r = this.sql.exec(
        `INSERT OR IGNORE INTO users (username, email, salt, iter, hash, created_at, pwd_version)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        o.username, String(o.email || "").trim().toLowerCase(), o.salt, o.iter || PBKDF2_ITER, o.hash,
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
        const activeVal = r.active === false ? 0 : 1;
        this.sql.exec(
          "INSERT INTO links (code, target_url, notes, active, created_at) VALUES (?, ?, ?, ?, ?)",
          code, r.targetUrl, r.notes || "", activeVal, now
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

  // ---------- usuario: enlaces y correo ----------
  async myLinks(username) {
    await this.#ready();
    return this.sql.exec("SELECT * FROM links WHERE owner = ? ORDER BY claimed_at DESC, code ASC", username)
      .toArray().map(r => this.#toLink(r));
  }

  async available() {
    await this.#ready();
    return this.sql.exec("SELECT code, notes FROM links WHERE active = 1 AND owner IS NULL ORDER BY code ASC")
      .toArray().map(r => ({ id: r.code, shortCode: r.code, notes: r.notes }));
  }

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

  async setUserEmail(username, email) {
    await this.#ready();
    if (!this.#userRow(username)) return null;
    const normalized = String(email || "").trim().toLowerCase();
    this.sql.exec("UPDATE users SET email = ? WHERE username = ?", normalized, username);
    return normalized;
  }

  // ---------- usuarios ----------
  async getUser(username) {
    await this.#ready();
    let u = this.#userRow(username);
    if (!u && !this.migrated && await this.#pull("users", username)) u = this.#userRow(username);
    return u;
  }

  async findUserForReset(identifier) {
    await this.#ready();
    const clean = String(identifier || "").trim().toLowerCase();
    if (!clean) return null;
    if (clean.includes("@")) {
      return this.#userByEmail(clean);
    }
    let u = this.#userRow(clean);
    if (!u && !this.migrated && USERNAME_RE.test(clean) && await this.#pull("users", clean)) {
      u = this.#userRow(clean);
    }
    return u;
  }

  async createUser(rec) {
    await this.#ready();
    if (!this.migrated) await this.#pull("users", rec.username);
    let result = { ok: false, error: "Ese usuario ya existe" };
    this.ctx.storage.transactionSync(() => {
      if (this.#userRow(rec.username)) return;
      this.sql.exec(
        "INSERT INTO users (username, email, salt, iter, hash, created_at, must_change) VALUES (?, ?, ?, ?, ?, ?, 1)",
        rec.username, rec.email || "", rec.salt, rec.iter, rec.hash, Date.now()
      );
      result = { ok: true };
    });
    return result;
  }

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
      `SELECT u.username, u.email, u.created_at,
              u.must_change,
              (SELECT COUNT(*) FROM links l WHERE l.owner = u.username) AS links
         FROM users u ORDER BY u.username ASC`
    ).toArray().map(r => ({
      username: r.username,
      email: r.email || "",
      createdAt: r.created_at,
      links: r.links,
      mustChange: !!r.must_change
    }));
  }

  async deleteUser(username) {
    await this.#ready();
    let result = { ok: false, error: "Usuario no encontrado" };
    this.ctx.storage.transactionSync(() => {
      if (!this.#userRow(username)) return;
      const released = this.sql.exec("SELECT COUNT(*) AS n FROM links WHERE owner = ?", username).one().n;
      this.sql.exec("UPDATE links SET owner = NULL, claimed_at = NULL WHERE owner = ?", username);
      this.sql.exec("DELETE FROM password_resets WHERE username = ?", username);
      this.sql.exec("DELETE FROM users WHERE username = ?", username);
      result = { ok: true, released };
    });
    return result;
  }

  // ---------- tokens de recuperación ----------
  async createResetToken(username, tokenHash, expiresAt) {
    await this.#ready();
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM password_resets WHERE expires_at < ? OR used = 1", now);
      this.sql.exec("UPDATE password_resets SET used = 1 WHERE username = ?", username);
      this.sql.exec(
        "INSERT INTO password_resets (token_hash, username, expires_at, used) VALUES (?, ?, ?, 0)",
        tokenHash, username, expiresAt
      );
    });
  }

  async consumeResetTokenAndSetPassword(tokenHash, rec) {
    await this.#ready();
    const now = Date.now();
    let result = { ok: false, error: "El enlace de recuperación no es válido o ha expirado." };
    this.ctx.storage.transactionSync(() => {
      const rows = this.sql.exec(
        "SELECT username, expires_at, used FROM password_resets WHERE token_hash = ?",
        tokenHash
      ).toArray();
      if (!rows.length) return;
      const row = rows[0];
      if (row.used || row.expires_at < now) return;
      if (!this.#userRow(row.username)) return;

      this.sql.exec("UPDATE password_resets SET used = 1 WHERE token_hash = ?", tokenHash);
      this.sql.exec(
        `UPDATE users SET salt = ?, iter = ?, hash = ?, pwd_version = pwd_version + 1, must_change = 0
          WHERE username = ?`,
        rec.salt, rec.iter, rec.hash, row.username
      );
      result = { ok: true, username: row.username };
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

async function sha256Hex(data) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(String(data)));
  return toHex(new Uint8Array(digest));
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}

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
async function makeToken(env, username, role, pv = 0) {
  const now = Date.now();
  const payload = b64url(JSON.stringify({ u: username, r: role, pv, iat: now, exp: now + TOKEN_TTL_MS }));
  return payload + "." + await hmacHex(env.TOKEN_SECRET, payload);
}

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

function parseEmailOptional(input) {
  const e = String(input || "").trim().toLowerCase();
  if (!e) return "";
  if (e.length > MAX_EMAIL || !EMAIL_RE.test(e)) return null;
  return e;
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 128;
}

function validateLinkRow(input) {
  const targetUrl = parseUrl(input.targetUrl);
  if (!targetUrl) return { error: "La URL destino no es válida (debe ser http o https)" };

  const notes = String(input.notes ?? "").trim();
  if (notes.length > MAX_NOTES) return { error: `Las notas no pueden superar ${MAX_NOTES} caracteres` };

  const shortCode = String(input.shortCode ?? "").trim();
  if (shortCode && !CODE_RE.test(shortCode)) {
    return { error: "El código solo puede tener letras, números, - y _ (máx. 64)" };
  }
  const active = input.active === false ? false : true;
  return { row: { targetUrl, notes, shortCode, active } };
}

// ---------- Envío de correo con Resend ----------
async function sendResetEmailResend(env, { to, username, resetUrl }) {
  if (!env.RESEND_API_KEY) {
    throw new Error("Falta el secret RESEND_API_KEY en el Worker.");
  }
  const from = String(env.FROM_EMAIL || env.RESEND_FROM || "").trim();
  if (!from) {
    throw new Error("Falta configurar FROM_EMAIL con un remitente verificado en Resend.");
  }

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject: "Recuperación de contraseña - Gestor de Enlaces y QR",
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #1f2937; max-width: 520px;">
          <h2 style="margin-bottom: 8px;">Recuperar contraseña</h2>
          <p>Hola <b>${escapeHtml(username)}</b>,</p>
          <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta. Haz clic en el siguiente botón para crear una nueva contraseña (este enlace vence en 30 minutos):</p>
          <p style="margin: 24px 0;">
            <a href="${escapeHtml(resetUrl)}" style="background:#2563eb;color:#ffffff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block;">
              Restablecer contraseña
            </a>
          </p>
          <p style="font-size: 12px; color: #6b7280;">Si no solicitaste este cambio, puedes ignorar este correo.</p>
        </div>
      `
    })
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Resend (${res.status}): ${errText}`);
  }
}

// ============================================================
// PÚBLICO: redirección y recuperación de contraseña
// ============================================================
async function redirectLookup(env, code) {
  if (!code) return fail("Falta el parámetro ?r=codigo", 400);
  if (code.length > 64) return fail("El enlace acortado no existe.", 404);

  const r = await registry(env).resolve(code);
  return r.ok ? json({ success: true, targetUrl: r.targetUrl }) : fail(r.error, r.status);
}

async function requestPasswordReset(env, body) {
  const identifier = String(body.identifier || "").trim();
  const neutralMsg = "Si el usuario o correo existe y tiene correo configurado, te enviaremos un enlace de recuperación.";
  if (!identifier) return fail("Ingresa tu usuario o correo electrónico.");

  const reg = registry(env);
  const user = await reg.findUserForReset(identifier);

  if (user && user.email && EMAIL_RE.test(user.email)) {
    const rawToken = randomHex(24);
    const tokenHash = await sha256Hex(rawToken + ":" + String(env.TOKEN_SECRET || ""));
    const expiresAt = Date.now() + RESET_TTL_MS;
    await reg.createResetToken(user.username, tokenHash, expiresAt);

    const parsedBase = parseUrl(body.resetBaseUrl) || "";
    const cleanBase = parsedBase ? parsedBase.split("?")[0] : "";
    const resetUrl = cleanBase
      ? `${cleanBase}?reset=${encodeURIComponent(rawToken)}`
      : `?reset=${encodeURIComponent(rawToken)}`;

    try {
      await sendResetEmailResend(env, {
        to: user.email,
        username: user.username,
        resetUrl
      });
    } catch (err) {
      console.error("Error enviando correo con Resend:", err);
      return fail("No se pudo enviar el correo de recuperación en este momento.");
    }
  }

  return json({ success: true, message: neutralMsg });
}

async function resetPassword(env, body) {
  const rawToken = String(body.token || "").trim();
  const password = String(body.password || "");
  if (!rawToken) return fail("Falta el token de recuperación.");
  if (!validPassword(password)) return fail("La contraseña debe tener entre 8 y 128 caracteres.");

  const tokenHash = await sha256Hex(rawToken + ":" + String(env.TOKEN_SECRET || ""));
  const rec = await makePasswordRecord(password);
  const res = await registry(env).consumeResetTokenAndSetPassword(tokenHash, rec);
  return res.ok ? json({ success: true, username: res.username }) : fail(res.error);
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

  const email = parseEmailOptional(body.email);
  if (email === null) return fail("El correo electrónico no es válido");

  const r = await registry(env).createUser({
    username,
    email,
    ...(await makePasswordRecord(body.password))
  });
  return r.ok ? json({ success: true, username, email }) : fail(r.error);
}

async function userUpdateEmail(env, body) {
  const username = String(body.username || "").trim().toLowerCase();
  const email = parseEmailOptional(body.email);
  if (email === null) return fail("El correo electrónico no es válido");

  const saved = await registry(env).setUserEmail(username, email);
  return saved === null ? fail("Usuario no encontrado") : json({ success: true, username, email: saved });
}

async function userSetPassword(env, body) {
  if (!validPassword(body.password)) return fail("La contraseña debe tener entre 8 y 128 caracteres");
  const username = String(body.username || "").trim().toLowerCase();
  const v = await registry(env).setPassword(username, await makePasswordRecord(body.password), true);
  return v === null ? fail("Usuario no encontrado") : json({ success: true });
}

async function userDelete(env, body) {
  const r = await registry(env).deleteUser(String(body.username || "").trim().toLowerCase());
  return r.ok ? json({ success: true, released: r.released }) : fail(r.error);
}

// ============================================================
// USUARIO: solo lo suyo
// ============================================================
async function myLinks(env, body, auth) {
  const reg = registry(env);
  const [data, userRec] = await Promise.all([reg.myLinks(auth.username), reg.getUser(auth.username)]);
  return json({ success: true, data, email: userRec ? userRec.email : "" });
}

async function updateOwnEmail(env, body, auth) {
  const email = parseEmailOptional(body.email);
  if (email === null || !email) return fail("Ingresa un correo electrónico válido");
  const saved = await registry(env).setUserEmail(auth.username, email);
  return saved === null ? fail("No autorizado", 401) : json({ success: true, email: saved });
}

async function availableLinks(env) {
  return json({ success: true, data: await registry(env).available() });
}

async function claimLink(env, body, auth) {
  const r = await registry(env).claim(String(body.id || ""), auth.username);
  return r.ok ? json({ success: true, data: r.link }) : fail(r.error);
}

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
  return json({ success: true, token: await makeToken(env, auth.username, "user", pv) });
}

// ============================================================
// Rutas y permisos
// ============================================================
const ROUTES = {
  // Administrador
  migrate:          { roles: ["admin"], fn: adminMigrate },
  list:             { roles: ["admin"], fn: adminList },
  create:           { roles: ["admin"], fn: adminCreate },
  create_bulk:      { roles: ["admin"], fn: adminCreateBulk },
  update:           { roles: ["admin"], fn: adminUpdate },
  set_active:       { roles: ["admin"], fn: adminSetActive },
  set_owner:        { roles: ["admin"], fn: adminSetOwner },
  delete:           { roles: ["admin"], fn: adminDelete },
  users_list:       { roles: ["admin"], fn: usersList },
  user_create:      { roles: ["admin"], fn: userCreate },
  user_update_email:{ roles: ["admin"], fn: userUpdateEmail },
  user_password:    { roles: ["admin"], fn: userSetPassword },
  user_delete:      { roles: ["admin"], fn: userDelete },
  // Usuario
  my_links:         { roles: ["user"], fn: myLinks },
  update_email:     { roles: ["user"], fn: updateOwnEmail },
  available:        { roles: ["user"], fn: availableLinks },
  claim:            { roles: ["user"], fn: claimLink },
  update_url:       { roles: ["user"], fn: updateOwnUrl },
  change_password:  { roles: ["user"], fn: changeOwnPassword }
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
      if (body.action === "request_password_reset") {
        return await requestPasswordReset(env, body);
      }
      if (body.action === "reset_password") {
        return await resetPassword(env, body);
      }

      const auth = await authenticate(env, body.token);
      if (!auth) return json({ success: false, error: "No autorizado", unauthorized: true }, 401);

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
