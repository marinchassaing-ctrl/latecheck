'use strict';
/*
 * LateCheck — serveur (Node 22+, aucune dépendance npm)
 * - Base SQLite (node:sqlite)
 * - Stripe Connect Express : onboarding des hôtes, paiements par Stripe Checkout
 *   en "destination charge" avec commission LateCheck prélevée en application fee
 * - Webhooks Stripe signés : seul un webhook confirme un paiement
 */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

/* ------------------------------------------------------------------ Config */
(function loadEnv() {
  const f = path.join(__dirname, '.env');
  if (!fs.existsSync(f)) return;
  for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();
const env = process.env;
const PORT = Number(env.PORT) || 3000;
const APP_URL = (env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const STRIPE_KEY = env.STRIPE_SECRET_KEY || '';
const STRIPE_API = (env.STRIPE_API_BASE || 'https://api.stripe.com').replace(/\/$/, '');
const WH_SECRETS = [env.STRIPE_WEBHOOK_SECRET, env.STRIPE_CONNECT_WEBHOOK_SECRET].filter(Boolean);
const ADMIN_EMAIL = (env.ADMIN_EMAIL || '').trim().toLowerCase();
const DB_PATH = env.DB_PATH || path.join(__dirname, 'latecheck.db');
const COMMISSION_RATE = 0.10;
const SECURE_COOKIE = APP_URL.startsWith('https://');

if (!STRIPE_KEY) { console.error('❌ STRIPE_SECRET_KEY manquant (voir .env.example).'); process.exit(1); }
const STRIPE_MODE = STRIPE_KEY.startsWith('sk_live_') ? 'live' : 'test';
if (STRIPE_MODE === 'live') console.warn('⚠️  Clé Stripe LIVE : les paiements sont réels.');
if (!WH_SECRETS.length) console.warn('⚠️  STRIPE_WEBHOOK_SECRET manquant : aucun paiement ne pourra être confirmé.');
if (!ADMIN_EMAIL) console.warn('⚠️  ADMIN_EMAIL manquant : le compte administrateur ne peut pas être créé.');

/* ------------------------------------------------------------------ Base de données */
const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('host','admin')), name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE, pw TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
  stripe_account TEXT UNIQUE, payouts_ready INTEGER NOT NULL DEFAULT 0, details_submitted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS listings(
  id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, address TEXT NOT NULL,
  photo TEXT, checkout TEXT NOT NULL, prices TEXT NOT NULL, paused INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0, slug TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS requests(
  id TEXT PRIMARY KEY, listing_id TEXT NOT NULL REFERENCES listings(id), host_id TEXT NOT NULL REFERENCES users(id),
  guest_name TEXT NOT NULL, guest_email TEXT NOT NULL, guest_token TEXT NOT NULL, date TEXT NOT NULL,
  hours INTEGER NOT NULL, price INTEGER NOT NULL, old_time TEXT NOT NULL, new_time TEXT NOT NULL, message TEXT,
  status TEXT NOT NULL, expired_reason TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  decided_at INTEGER, pay_token TEXT UNIQUE, pay_token_used TEXT, pay_expires_at INTEGER,
  checkout_session TEXT, paid_at INTEGER);
CREATE INDEX IF NOT EXISTS req_host ON requests(host_id);
CREATE TABLE IF NOT EXISTS payments(
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES requests(id), host_id TEXT NOT NULL, listing_id TEXT NOT NULL,
  amount INTEGER NOT NULL, commission INTEGER NOT NULL DEFAULT 0, stripe_fee INTEGER NOT NULL DEFAULT 0,
  stripe_fee_actual INTEGER, net INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, method TEXT, last4 TEXT,
  stripe_payment_intent TEXT, stripe_charge TEXT, created_at INTEGER NOT NULL, refunded_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS pay_one_success ON payments(request_id) WHERE status IN ('succeeded','refunded');
CREATE TABLE IF NOT EXISTS emails(id TEXT PRIMARY KEY, to_addr TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stripe_events(id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
const q = (sql) => db.prepare(sql);
for (const sql of ['ALTER TABLE payments ADD COLUMN invoice_id TEXT', 'ALTER TABLE users ADD COLUMN billing TEXT', 'ALTER TABLE requests ADD COLUMN payment_intent TEXT', 'ALTER TABLE users ADD COLUMN stripe_mode TEXT', 'ALTER TABLE users ADD COLUMN terms_accepted_at INTEGER', 'ALTER TABLE requests ADD COLUMN cgv_accepted_at INTEGER']) {
  try { db.exec(sql); } catch (e) { /* colonne déjà présente */ }
}
db.exec(`CREATE TABLE IF NOT EXISTS invoices(
  id TEXT PRIMARY KEY, number TEXT NOT NULL UNIQUE, type TEXT NOT NULL, host_id TEXT NOT NULL, month TEXT NOT NULL,
  issued_at INTEGER NOT NULL, sales INTEGER NOT NULL, commission INTEGER NOT NULL, fees INTEGER NOT NULL,
  ttc INTEGER NOT NULL, ht INTEGER NOT NULL, vat INTEGER NOT NULL, vat_rate REAL NOT NULL, count INTEGER NOT NULL,
  ref TEXT, payment_id TEXT, customer TEXT NOT NULL, seller TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS inv_one_month ON invoices(host_id, month) WHERE type='facture';
CREATE UNIQUE INDEX IF NOT EXISTS inv_one_credit ON invoices(payment_id) WHERE type='avoir';`);
db.exec(`CREATE TABLE IF NOT EXISTS push_tokens(token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, platform TEXT NOT NULL, created_at INTEGER NOT NULL)`);

/* Passage du mode test au mode réel : les comptes Stripe de test n'existent pas en réel.
   On réinitialise les connexions Stripe et on efface les demandes et paiements fictifs.
   Les comptes hôtes et les logements (donc les QR codes déjà imprimés) sont conservés. */
(function switchStripeMode() {
  const row = q("SELECT value FROM settings WHERE key='stripe_mode_seen'").get();
  const seen = row ? JSON.parse(row.value) : (q('SELECT 1 FROM payments LIMIT 1').get() || q("SELECT 1 FROM users WHERE stripe_account IS NOT NULL").get() ? 'test' : STRIPE_MODE);
  if (seen === 'test' && STRIPE_MODE === 'live') {
    db.exec(`DELETE FROM invoices; DELETE FROM settings WHERE key LIKE 'invoice_seq_%'; DELETE FROM payments; DELETE FROM requests; DELETE FROM emails; DELETE FROM stripe_events;
             UPDATE users SET stripe_account=NULL, payouts_ready=0, details_submitted=0, stripe_mode=NULL;`);
    console.log('🔁 Passage en mode réel : données de test effacées, les hôtes doivent reconnecter Stripe.');
  }
  q("UPDATE users SET stripe_account=NULL, payouts_ready=0, details_submitted=0 WHERE stripe_account IS NOT NULL AND COALESCE(stripe_mode,'test') <> ?").run(STRIPE_MODE);
  q("INSERT INTO settings(key,value) VALUES('stripe_mode_seen',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(JSON.stringify(STRIPE_MODE));
})();

/* ------------------------------------------------------------------ Utilitaires */
const now = () => Date.now();
const newId = (p) => p + crypto.randomBytes(9).toString('hex');
const newToken = () => crypto.randomBytes(24).toString('base64url');
const isEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const eur = (c) => (c / 100).toLocaleString('fr-FR', { style: 'currency', currency: 'EUR' });
const hoursLabel = (h) => '+' + h + (h > 1 ? ' heures' : ' heure');
const hFmt = (t) => { const [a, b] = t.split(':'); return Number(a) + ' h' + (b === '00' ? '' : ' ' + b); };
const addHours = (hhmm, h) => { const [a, b] = hhmm.split(':').map(Number); const m = (a * 60 + b + h * 60) % 1440; return String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0'); };
const dayFr = (d) => new Date(d + 'T12:00:00').toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
const timeFr = (t) => new Date(t).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Paris' });
const todayParis = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'Europe/Paris' });
function fail(status, message, code) { const e = new Error(message); e.status = status; if (code) e.code = code; throw e; }

function hashPw(pw) { const salt = crypto.randomBytes(16).toString('hex'); return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex'); }
function checkPw(pw, stored) {
  const [salt, h] = String(stored).split(':'); if (!salt || !h) return false;
  const a = crypto.scryptSync(pw, salt, 64), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const LEGAL = {
  company: env.LEGAL_COMPANY || '[Raison sociale à compléter]', form: env.LEGAL_FORM || '[forme juridique]',
  siren: env.LEGAL_SIREN || '[SIREN à compléter]', address: env.LEGAL_ADDRESS || '[adresse du siège à compléter]',
  email: env.LEGAL_EMAIL || env.ADMIN_EMAIL || '[e-mail de contact]', director: env.LEGAL_DIRECTOR || '[directeur de la publication]',
  vat: env.LEGAL_VAT || '', capital: env.LEGAL_CAPITAL || '', rcs: env.LEGAL_RCS || '',
  vatRate: Math.max(0, Number(env.LEGAL_VAT_RATE || 0)), mediator: env.LEGAL_MEDIATOR || '[médiateur de la consommation à désigner]',
};
const DEFAULT_SETTINGS = { requestTtlMin: 120, payTtlMin: 60, stripePct: 0.015, stripeFixed: 25 };
function getSettings() {
  const s = { ...DEFAULT_SETTINGS };
  for (const r of q('SELECT key, value FROM settings').all()) s[r.key] = JSON.parse(r.value);
  s.commissionRate = COMMISSION_RATE;
  return s;
}
/* Commission : 10 % du prix. Frais Stripe à la charge de l'hôte : estimés puis inclus dans l'application fee. */
function computeSplit(amount, s = getSettings()) {
  const commission = Math.round(amount * COMMISSION_RATE);
  const stripeFee = Math.round(amount * s.stripePct) + s.stripeFixed;
  return { commission, stripeFee, applicationFee: commission + stripeFee, net: amount - commission - stripeFee };
}

/* E-mails : enregistrés en base, envoyés via Resend si configuré */
function sendEmail(to, subject, body) {
  q('INSERT INTO emails(id,to_addr,subject,body,at) VALUES(?,?,?,?,?)').run(newId('em_'), to, subject, body, now());
  if (!env.RESEND_API_KEY) return;
  fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.EMAIL_FROM || 'LateCheck <onboarding@resend.dev>', to: [to], subject, text: body }),
  }).then((r) => { if (!r.ok) r.text().then((t) => console.error('Resend', r.status, t)); }).catch((e) => console.error('Resend', e.message));
}

/* ------------------------------------------------------------------ Notifications push iOS (APNs) */
const http2 = require('node:http2');
// La clé .p8 est acceptée sous toutes ses formes : fichier collé tel quel (avec ou sans les lignes BEGIN/END),
// ou converti en base64. On reconstruit toujours une clé PEM valide.
function parseApnsKey(raw) {
  raw = String(raw || '').trim();
  if (!raw) return '';
  if (raw.includes('PRIVATE KEY')) return raw.replace(/\\n/g, '\n');
  const compact = raw.replace(/\s+/g, '');
  try { const dec = Buffer.from(compact, 'base64').toString('utf8'); if (dec.includes('PRIVATE KEY')) return dec; } catch (_) {}
  if (/^MIG[A-Za-z0-9+/=]+$/.test(compact)) return `-----BEGIN PRIVATE KEY-----\n${compact.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
  return '';
}
const APNS = {
  keyId: String(env.APNS_KEY_ID || '').trim(), teamId: String(env.APNS_TEAM_ID || '').trim(), bundleId: String(env.APNS_BUNDLE_ID || 'fr.latecheck.app').trim(),
  key: parseApnsKey(env.APNS_KEY_BASE64 || env.APNS_KEY), keyError: '',
};
if (APNS.key) { try { crypto.createPrivateKey(APNS.key); } catch (e) { APNS.keyError = e.message; APNS.key = ''; } }
APNS.enabled = !!(APNS.keyId && APNS.teamId && APNS.key);
if (!APNS.enabled) console.warn('ℹ️  Notifications push désactivées (APNS_KEY_ID, APNS_TEAM_ID, APNS_KEY_BASE64).');
let apnsJwt = null;
function apnsToken() {
  if (apnsJwt && now() - apnsJwt.at < 40 * 60000) return apnsJwt.token;
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const data = enc({ alg: 'ES256', kid: APNS.keyId }) + '.' + enc({ iss: APNS.teamId, iat: Math.floor(Date.now() / 1000) });
  const sig = crypto.sign('sha256', Buffer.from(data), { key: APNS.key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  apnsJwt = { token: data + '.' + sig, at: now() };
  return apnsJwt.token;
}
function apnsSend(host, deviceToken, payload) {
  return new Promise((resolve) => {
    let client, jwt;
    try { jwt = apnsToken(); } catch (e) { return resolve({ status: -1, reason: 'Clé APNs illisible : ' + e.message }); }
    try { client = http2.connect(host); } catch (e) { return resolve({ status: 0, reason: e.message }); }
    client.on('error', (e) => resolve({ status: 0, reason: e.message }));
    const req = client.request({ ':method': 'POST', ':path': `/3/device/${deviceToken}`, authorization: `bearer ${jwt}`,
      'apns-topic': APNS.bundleId, 'apns-push-type': 'alert', 'apns-priority': '10', 'content-type': 'application/json' });
    let status = 0, body = '';
    req.on('response', (h) => { status = h[':status']; });
    req.on('data', (c) => { body += c; });
    req.on('end', () => { client.close(); let reason = ''; try { reason = JSON.parse(body).reason || ''; } catch (_) {} resolve({ status, reason }); });
    req.on('error', (e) => { client.close(); resolve({ status: 0, reason: e.message }); });
    req.setTimeout(10000, () => { req.close(); });
    req.end(JSON.stringify(payload));
  });
}
// Une même app peut parler aux deux serveurs d'Apple : production (TestFlight, App Store) et sandbox (builds Xcode).
// Selon la clé .p8 (réglée « Sandbox », « Production » ou les deux), un serveur peut refuser : on essaie l'autre,
// et on retient celui qui a marché pour chaque iPhone.
const APNS_HOSTS = { production: 'https://api.push.apple.com', sandbox: 'https://api.sandbox.push.apple.com' };
const tokenEnv = new Map();
const isTokenError = (r) => r.status === 410 || /^(Unregistered|BadDeviceToken)$/.test(r.reason);
async function apnsDeliver(token, payload) {
  const first = tokenEnv.get(token) || 'production', order = [first, first === 'production' ? 'sandbox' : 'production'];
  const tries = {};
  for (const env of order) {
    const r = await apnsSend(APNS_HOSTS[env], token, payload); tries[env] = r;
    if (r.status === 200) { tokenEnv.set(token, env); return { ok: true, env, tries }; }
  }
  return { ok: false, tries };
}
async function sendPush(userId, title, body, url) {
  if (!APNS.enabled) return;
  const payload = { aps: { alert: { title, body }, sound: 'default' }, url: url || '#/h' };
  const tokens = q('SELECT * FROM push_tokens WHERE user_id=?').all(userId);
  if (!tokens.length) console.warn('APNs : aucun iPhone enregistré pour cet hôte (ouvrez l’app et activez les notifications)');
  for (const t of tokens) {
    const d = await apnsDeliver(t.token, payload);
    if (d.ok) { console.log('APNs envoyé', t.token.slice(0, 8), d.env); continue; }
    const all = Object.values(d.tries);
    if (all.every(isTokenError)) { q('DELETE FROM push_tokens WHERE token=?').run(t.token); console.warn('APNs : iPhone désinscrit, jeton supprimé', t.token.slice(0, 8)); }
    else console.error('APNs échec', t.token.slice(0, 8), Object.entries(d.tries).map(([e, r]) => `${e} ${r.status} ${r.reason}`).join(' | '));
  }
}

/* ------------------------------------------------------------------ Factures de commission (mensuelles) et avoirs */
const parisMonth = (t) => new Date(t).toLocaleDateString('sv-SE', { timeZone: 'Europe/Paris' }).slice(0, 7);
const parisDate = (t) => new Date(t).toLocaleDateString('fr-FR', { timeZone: 'Europe/Paris' });
const monthFr = (m) => { const [y, mo] = m.split('-'); return new Date(Date.UTC(+y, +mo - 1, 15)).toLocaleDateString('fr-FR', { month: 'long', year: 'numeric', timeZone: 'UTC' }); };
function nextInvoiceNumber() {
  const y = new Date().toLocaleDateString('sv-SE', { timeZone: 'Europe/Paris' }).slice(0, 4), k = 'invoice_seq_' + y;
  const r = q('SELECT value FROM settings WHERE key=?').get(k), n = (r ? JSON.parse(r.value) : 0) + 1;
  q('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, JSON.stringify(n));
  return `LC-${y}-${String(n).padStart(6, '0')}`;
}
function customerSnapshot(u) {
  let b = {}; try { b = JSON.parse(u.billing || '{}') || {}; } catch (e) {}
  return JSON.stringify({ name: u.name, email: u.email, company: b.company || '', address: b.address || '', siren: b.siren || '', vat: b.vat || '' });
}
const sellerSnapshot = () => JSON.stringify(LEGAL);
function splitVat(ttc) { const ht = Math.round(ttc / (1 + LEGAL.vatRate / 100)); return { ht, vat: ttc - ht }; }
/* Émet les factures des mois clos (appelé régulièrement). Numérotation continue par année. */
function issueInvoices() {
  const cur = parisMonth(now()), groups = {};
  for (const p of q("SELECT * FROM payments WHERE status='succeeded' AND invoice_id IS NULL").all()) {
    const m = parisMonth(p.created_at); if (m >= cur) continue;
    (groups[p.host_id + '|' + m] = groups[p.host_id + '|' + m] || []).push(p);
  }
  for (const [k, ps] of Object.entries(groups)) {
    const [hostId, m] = k.split('|');
    const host = q('SELECT * FROM users WHERE id=?').get(hostId);
    if (!host || q("SELECT 1 FROM invoices WHERE host_id=? AND month=? AND type='facture'").get(hostId, m)) continue;
    const commission = ps.reduce((a, p) => a + p.commission, 0), fees = ps.reduce((a, p) => a + p.stripe_fee, 0);
    const ttc = commission + fees, { ht, vat } = splitVat(ttc), id = newId('inv_');
    db.exec('BEGIN IMMEDIATE');
    try {
      q(`INSERT INTO invoices(id,number,type,host_id,month,issued_at,sales,commission,fees,ttc,ht,vat,vat_rate,count,customer,seller)
         VALUES(?,?,'facture',?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, nextInvoiceNumber(), hostId, m, now(), ps.reduce((a, p) => a + p.amount, 0),
        commission, fees, ttc, ht, vat, LEGAL.vatRate, ps.length, customerSnapshot(host), sellerSnapshot());
      for (const p of ps) q('UPDATE payments SET invoice_id=? WHERE id=?').run(id, p.id);
      db.exec('COMMIT');
      if (host.status === 'active') sendEmail(host.email, `Votre facture LateCheck de ${monthFr(m)}`, `Bonjour ${host.name},\n\nVotre facture de commission LateCheck pour ${monthFr(m)} est disponible dans l'application, rubrique Revenus → Factures et relevés.\nVentes : ${eur(ps.reduce((a, p) => a + p.amount, 0))} · commission et frais : ${eur(ttc)}.`);
    } catch (e) { db.exec('ROLLBACK'); console.error('facture', e.message); }
  }
}
/* Remboursement d'une vente déjà facturée : avoir immédiat */
function issueCreditNote(p) {
  if (!p.invoice_id || q("SELECT 1 FROM invoices WHERE payment_id=? AND type='avoir'").get(p.id)) return;
  const inv = q('SELECT * FROM invoices WHERE id=?').get(p.invoice_id), host = q('SELECT * FROM users WHERE id=?').get(p.host_id);
  if (!inv || !host) return;
  const ttc = -(p.commission + p.stripe_fee), { ht, vat } = splitVat(ttc);
  db.exec('BEGIN IMMEDIATE');
  try {
    q(`INSERT INTO invoices(id,number,type,host_id,month,issued_at,sales,commission,fees,ttc,ht,vat,vat_rate,count,ref,payment_id,customer,seller)
       VALUES(?,?,'avoir',?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)`).run(newId('inv_'), nextInvoiceNumber(), p.host_id, parisMonth(now()), now(),
      -p.amount, -p.commission, -p.stripe_fee, ttc, ht, vat, inv.vat_rate, inv.number, p.id, customerSnapshot(host), sellerSnapshot());
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); console.error('avoir', e.message); }
}
setInterval(() => { try { issueInvoices(); } catch (e) { console.error('factures', e); } }, 10 * 60000).unref();
setTimeout(() => { try { issueInvoices(); } catch (e) { console.error('factures', e); } }, 5000).unref();

/* Mini-générateur PDF (Helvetica, A4), sans dépendance */
const PDF_W = { ' ': 278, ',': 278, '.': 278, '-': 333, '%': 889, '€': 556, '(': 333, ')': 333, '/': 278, ':': 278, '·': 278 };
function textW(s, size, bold) { let w = 0; for (const ch of String(s)) w += /[0-9]/.test(ch) ? 556 : (PDF_W[ch] || (/[A-Z]/.test(ch) ? 667 : /[il.,'!|]/.test(ch) ? 240 : bold ? 590 : 540)); return w / 1000 * size; }
function pdfStr(s) {
  const map = { '€': '\x80', '’': '\x92', '‘': '\x91', '“': '\x93', '”': '\x94', '–': '\x96', '—': '\x97', '…': '\x85', 'œ': '\x9c', 'Œ': '\x8c', '\u202f': ' ', '\u00a0': ' ' };
  let o = ''; for (const ch of String(s ?? '')) { if (map[ch] !== undefined) o += map[ch]; else o += ch.charCodeAt(0) < 256 ? ch : '?'; }
  return o.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}
function pdfDoc() {
  const pages = []; let c = '';
  const INK = '0.09 0.15 0.11', MUTED = '0.40 0.46 0.42', GREEN = '0.18 0.36 0.26';
  const d = {
    INK, MUTED, GREEN,
    text(x, y, s, { size = 9.5, bold = false, color = INK, align = 'left', max = 0 } = {}) {
      s = String(s ?? ''); if (max) while (s.length > 3 && textW(s, size, bold) > max) s = s.slice(0, -2).trimEnd() + '…';
      const xx = align === 'right' ? x - textW(s, size, bold) : align === 'center' ? x - textW(s, size, bold) / 2 : x;
      c += `BT /${bold ? 'F2' : 'F1'} ${size} Tf ${color} rg ${xx.toFixed(2)} ${y.toFixed(2)} Td (${pdfStr(s)}) Tj ET\n`;
    },
    wrap(x, y, s, width, opts = {}) { const size = opts.size || 9.5, words = String(s).split(' '); let line = '', yy = y;
      for (const w of words) { const t = line ? line + ' ' + w : w; if (textW(t, size, opts.bold) > width && line) { d.text(x, yy, line, opts); yy -= size * 1.35; line = w; } else line = t; }
      if (line) { d.text(x, yy, line, opts); yy -= size * 1.35; } return yy; },
    line(x1, y1, x2, y2, w = 0.6, color = '0.86 0.89 0.86') { c += `${color} RG ${w} w ${x1} ${y1} m ${x2} ${y2} l S\n`; },
    rect(x, y, w, h, color = '0.93 0.95 0.93') { c += `${color} rg ${x} ${y} ${w} ${h} re f\n`; },
    page() { if (c) pages.push(c); c = ''; },
    end() {
      if (c) pages.push(c);
      const objs = [null, null];
      const add = (o) => { objs.push(o); return objs.length; };
      const f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
      const f2 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
      const kids = pages.map((pc) => { const cs = add(`<< /Length ${Buffer.byteLength(pc, 'latin1')} >>\nstream\n${pc}\nendstream`);
        return add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${cs} 0 R >>`); });
      objs[0] = '<< /Type /Catalog /Pages 2 0 R >>';
      objs[1] = `<< /Type /Pages /Kids [${kids.map((k) => k + ' 0 R').join(' ')}] /Count ${kids.length} >>`;
      let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'; const offs = [];
      objs.forEach((o, i) => { offs.push(Buffer.byteLength(out, 'latin1')); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
      const xref = Buffer.byteLength(out, 'latin1');
      out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => String(o).padStart(10, '0') + ' 00000 n \n').join('') +
        `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
      return Buffer.from(out, 'latin1');
    },
  };
  return d;
}
const eurPdf = (c) => (c / 100).toLocaleString('fr-FR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' €';
function invoiceTransactions(inv) {
  const sql = `SELECT p.*, r.guest_name, r.hours, r.date, l.name AS lname FROM payments p JOIN requests r ON r.id=p.request_id JOIN listings l ON l.id=p.listing_id`;
  return inv.type === 'avoir' ? q(sql + ' WHERE p.id=?').all(inv.payment_id) : q(sql + ' WHERE p.invoice_id=? ORDER BY p.created_at').all(inv.id);
}
function invoicePdf(inv) {
  const S = JSON.parse(inv.seller), C = JSON.parse(inv.customer), d = pdfDoc(), M = 50, R = 545, avoir = inv.type === 'avoir';
  const footer = (n) => { d.line(M, 52, R, 52); d.text(M, 38, `${S.company} · ${S.form} · SIREN ${S.siren} · ${S.address}`, { size: 7.5, color: d.MUTED, max: 430 }); d.text(R, 38, `Page ${n}`, { size: 7.5, color: d.MUTED, align: 'right' }); };
  // En-tête
  d.text(M, 790, 'LateCheck', { size: 22, bold: true, color: d.GREEN });
  d.text(R, 792, avoir ? 'AVOIR' : 'FACTURE', { size: 18, bold: true, align: 'right' });
  d.text(R, 774, `N° ${inv.number}`, { size: 10, align: 'right', bold: true });
  d.text(R, 760, `Date d'émission : ${parisDate(inv.issued_at)}`, { size: 9, align: 'right', color: d.MUTED });
  if (avoir) d.text(R, 747, `Avoir sur la facture N° ${inv.ref}`, { size: 9, align: 'right', color: d.MUTED });
  // Émetteur
  let y = 730;
  d.text(M, y, 'Émetteur', { size: 8, color: d.MUTED }); y -= 14;
  d.text(M, y, S.company, { bold: true }); y -= 13;
  d.text(M, y, `${S.form}${S.capital ? ' au capital de ' + S.capital : ''}`, { size: 9 }); y -= 12;
  y = d.wrap(M, y, S.address, 230, { size: 9 });
  d.text(M, y, `SIREN ${S.siren}${S.rcs ? ' · RCS ' + S.rcs : ''}`, { size: 9 }); y -= 12;
  if (S.vat) { d.text(M, y, `TVA intracommunautaire : ${S.vat}`, { size: 9 }); y -= 12; }
  d.text(M, y, S.email, { size: 9 });
  // Client
  d.rect(315, 640, 230, 104);
  let yc = 730;
  d.text(327, yc, 'Facturé à', { size: 8, color: d.MUTED }); yc -= 14;
  d.text(327, yc, C.company || C.name, { bold: true, max: 205 }); yc -= 13;
  if (C.company) { d.text(327, yc, C.name, { size: 9, max: 205 }); yc -= 12; }
  if (C.address) yc = d.wrap(327, yc, C.address, 205, { size: 9 });
  if (C.siren) { d.text(327, yc, `SIREN ${C.siren}`, { size: 9 }); yc -= 12; }
  if (C.vat) { d.text(327, yc, `TVA ${C.vat}`, { size: 9 }); yc -= 12; }
  d.text(327, yc, C.email, { size: 9, max: 205 });
  // Période
  y = 610;
  d.text(M, y, avoir ? `Remboursement du ${parisDate(inv.issued_at)}` : `Période facturée : ${monthFr(inv.month)} (du 1er au dernier jour du mois)`, { size: 10, bold: true });
  // Tableau
  y = 582; d.rect(M, y - 6, R - M, 20, '0.93 0.95 0.93');
  const cols = [M + 8, 330, 390, 455, R - 8];
  d.text(cols[0], y, 'Désignation', { size: 8.5, bold: true }); d.text(cols[1], y, 'Qté', { size: 8.5, bold: true, align: 'right' });
  d.text(cols[2] + 20, y, 'PU HT', { size: 8.5, bold: true, align: 'right' }); d.text(cols[3], y, 'TVA', { size: 8.5, bold: true, align: 'right' });
  d.text(cols[4], y, 'Total HT', { size: 8.5, bold: true, align: 'right' });
  const lines = [
    [avoir ? `Annulation de la commission LateCheck (10 %) sur une vente remboursée de ${eurPdf(-inv.sales)}` : `Commission de service LateCheck : 10 % des ventes encaissées (${eurPdf(inv.sales)}, ${inv.count} vente${inv.count > 1 ? 's' : ''})`, inv.commission],
    [avoir ? 'Annulation des frais de traitement des paiements' : 'Frais de traitement des paiements par carte', inv.fees],
  ];
  y -= 26;
  for (const [label, ttc] of lines) {
    const ht = Math.round(ttc / (1 + inv.vat_rate / 100));
    const yy = d.wrap(cols[0], y, label, 250, { size: 9 });
    d.text(cols[1], y, '1', { size: 9, align: 'right' }); d.text(cols[2] + 20, y, eurPdf(ht), { size: 9, align: 'right' });
    d.text(cols[3], y, `${inv.vat_rate} %`, { size: 9, align: 'right' }); d.text(cols[4], y, eurPdf(ht), { size: 9, align: 'right' });
    y = Math.min(yy, y - 14) - 6; d.line(M, y + 8, R, y + 8);
  }
  // Totaux
  y -= 8;
  const tot = (label, val, bold) => { d.text(430, y, label, { size: bold ? 10.5 : 9.5, bold, align: 'right' }); d.text(R - 8, y, eurPdf(val), { size: bold ? 10.5 : 9.5, bold, align: 'right' }); y -= bold ? 18 : 15; };
  tot('Total HT', inv.ht); tot(`TVA (${inv.vat_rate} %)`, inv.vat); d.line(330, y + 10, R, y + 10); tot(avoir ? 'Total TTC à déduire' : 'Total TTC', inv.ttc, true);
  // Mentions
  y -= 6;
  const mentions = [];
  if (!inv.vat_rate) mentions.push('TVA non applicable, article 293 B du Code général des impôts.');
  mentions.push(avoir ? 'Montant recrédité : la commission et les frais ont été restitués lors du remboursement du voyageur.'
    : `Facture acquittée : montant prélevé automatiquement sur vos encaissements, au moment de chaque vente, via Stripe. Montant net versé sur votre compte : ${eurPdf(inv.sales - inv.ttc)}.`);
  mentions.push("Pénalités de retard : trois fois le taux d'intérêt légal. Indemnité forfaitaire pour frais de recouvrement : 40 € (clients professionnels). Pas d'escompte pour paiement anticipé.");
  for (const m of mentions) y = d.wrap(M, y, m, R - M, { size: 8.5, color: d.MUTED }) - 4;
  // Récapitulatif
  if (!avoir) {
    y -= 10; d.rect(M, y - 52, R - M, 62);
    d.text(M + 12, y - 8, `Récapitulatif de ${monthFr(inv.month)}`, { size: 10, bold: true });
    const box = [['Ventes encaissées', inv.sales], ['Commission et frais LateCheck', inv.ttc], ['Net versé', inv.sales - inv.ttc]];
    box.forEach(([l, v], i) => { const x = M + 12 + i * 165; d.text(x, y - 26, l, { size: 8, color: d.MUTED }); d.text(x, y - 42, eurPdf(v), { size: 12, bold: true, color: i === 2 ? d.GREEN : d.INK }); });
  }
  footer(1);
  // Annexe : détail des transactions
  const tx = invoiceTransactions(inv);
  let page = 1, rowY = 0;
  const head = () => { d.page(); page++; d.text(M, 790, `Détail des transactions · ${avoir ? 'avoir ' : 'facture '}${inv.number}`, { size: 13, bold: true });
    d.text(M, 774, avoir ? 'Vente remboursée' : `Ventes encaissées en ${monthFr(inv.month)}`, { size: 9, color: d.MUTED });
    rowY = 746; d.rect(M, rowY - 6, R - M, 20, '0.93 0.95 0.93');
    [['Date', M + 6, 'left'], ['Voyageur', 108, 'left'], ['Logement', 180, 'left'], ['Départ', 310, 'left'], ['Payé', 418, 'right'], ['LateCheck', 482, 'right'], ['Net', R - 6, 'right']]
      .forEach(([t, x, a]) => d.text(x, rowY, t, { size: 8.5, bold: true, align: a })); rowY -= 22; };
  head();
  for (const t of tx) {
    if (rowY < 80) { footer(page); head(); }
    const fee = t.commission + t.stripe_fee;
    d.text(M + 6, rowY, parisDate(t.created_at), { size: 8.5 }); d.text(108, rowY, t.guest_name, { size: 8.5, max: 66 });
    d.text(180, rowY, t.lname, { size: 8.5, max: 122 }); d.text(310, rowY, `${t.date.slice(8, 10)}/${t.date.slice(5, 7)} · +${t.hours} h`, { size: 8.5 });
    d.text(418, rowY, eurPdf(t.amount), { size: 8.5, align: 'right' }); d.text(482, rowY, eurPdf(fee), { size: 8.5, align: 'right' });
    d.text(R - 6, rowY, eurPdf(t.amount - fee), { size: 8.5, align: 'right' }); rowY -= 6; d.line(M, rowY, R, rowY); rowY -= 12;
  }
  rowY -= 6; d.text(418, rowY, eurPdf(tx.reduce((a, t) => a + t.amount, 0)), { size: 9, bold: true, align: 'right' });
  d.text(482, rowY, eurPdf(tx.reduce((a, t) => a + t.commission + t.stripe_fee, 0)), { size: 9, bold: true, align: 'right' });
  d.text(R - 6, rowY, eurPdf(tx.reduce((a, t) => a + t.amount - t.commission - t.stripe_fee, 0)), { size: 9, bold: true, align: 'right' });
  footer(page);
  return d.end();
}
function monthCsv(hostId, month) {
  const c = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"', n = (x) => ((x || 0) / 100).toFixed(2).replace('.', ',');
  const rows = [['Date', 'Voyageur', 'Logement', 'Date du départ', 'Durée (h)', 'Montant payé (€)', 'Commission LateCheck (€)', 'Frais de paiement (€)', 'Net versé (€)', 'Statut', 'Facture']];
  const all = q(`SELECT p.*, r.guest_name, r.hours, r.date, l.name AS lname, i.number AS inv FROM payments p JOIN requests r ON r.id=p.request_id
    JOIN listings l ON l.id=p.listing_id LEFT JOIN invoices i ON i.id=p.invoice_id WHERE p.host_id=? AND p.status IN ('succeeded','refunded') ORDER BY p.created_at`).all(hostId);
  for (const p of all.filter((p) => parisMonth(p.created_at) === month)) {
    const ok = p.status === 'succeeded';
    rows.push([new Date(p.created_at).toLocaleString('fr-FR', { timeZone: 'Europe/Paris' }), p.guest_name, p.lname, p.date, p.hours, n(p.amount),
      ok ? n(p.commission) : '0,00', ok ? n(p.stripe_fee) : '0,00', ok ? n(p.net) : '0,00', ok ? 'Encaissé' : 'Remboursé', p.inv || '']);
  }
  return '\uFEFF' + rows.map((r) => r.map(c).join(';')).join('\r\n');
}
/* Liens de téléchargement signés (valables 15 min) : ouvrables hors session, ex. dans Safari depuis l'app */
const DOC_SECRET = env.DOC_SECRET || crypto.createHash('sha256').update('latecheck-docs:' + STRIPE_KEY).digest('hex');
function signDoc(payload) { const b = Buffer.from(JSON.stringify({ ...payload, exp: now() + 15 * 60000 })).toString('base64url'); return b + '.' + crypto.createHmac('sha256', DOC_SECRET).update(b).digest('base64url'); }
function readDoc(t) {
  const [b, sig] = String(t).split('.'); if (!b || !sig) return null;
  const exp = crypto.createHmac('sha256', DOC_SECRET).update(b).digest('base64url');
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null;
  const p = JSON.parse(Buffer.from(b, 'base64url').toString('utf8')); return p.exp > now() ? p : null;
}

/* ------------------------------------------------------------------ Client Stripe (API REST) */
function formEncode(obj, prefix, out = []) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (Array.isArray(v)) v.forEach((x, i) => (x !== null && typeof x === 'object') ? formEncode(x, `${key}[${i}]`, out) : out.push(encodeURIComponent(key + '[]') + '=' + encodeURIComponent(x)));
    else if (typeof v === 'object') formEncode(v, key, out);
    else out.push(encodeURIComponent(key) + '=' + encodeURIComponent(v));
  }
  return out;
}
async function stripe(method, p, params = {}, { account, idem } = {}) {
  const body = formEncode(params).join('&');
  const url = STRIPE_API + '/v1' + p + (method === 'GET' && body ? '?' + body : '');
  const headers = { Authorization: 'Bearer ' + STRIPE_KEY, 'Stripe-Version': '2024-06-20' };
  if (method !== 'GET') headers['Content-Type'] = 'application/x-www-form-urlencoded';
  if (account) headers['Stripe-Account'] = account;
  if (idem) headers['Idempotency-Key'] = idem;
  const r = await fetch(url, { method, headers, body: method === 'GET' ? undefined : body });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = (data.error && data.error.message) || 'Stripe ' + r.status;
    console.error('Stripe', method, p, r.status, msg);
    const e = new Error(msg); e.stripe = true; throw e;
  }
  return data;
}
/* API Stripe v2 (Accounts v2, imposée pour les nouvelles plateformes Connect) */
const STRIPE_V2_VERSION = env.STRIPE_V2_VERSION || '2026-09-30.endive';
async function stripeV2(method, p, body, { idem } = {}) {
  const call = async (version) => {
    const headers = { Authorization: 'Bearer ' + STRIPE_KEY, 'Stripe-Version': version };
    if (method !== 'GET') headers['Content-Type'] = 'application/json';
    if (idem) headers['Idempotency-Key'] = idem;
    const r = await fetch(STRIPE_API + p, { method, headers, body: method === 'GET' ? undefined : JSON.stringify(body || {}) });
    return { r, data: await r.json().catch(() => ({})) };
  };
  let { r, data } = await call(STRIPE_V2_VERSION);
  if (!r.ok && /version/i.test(JSON.stringify(data.error || '')) && STRIPE_V2_VERSION !== '2026-09-30.preview') ({ r, data } = await call('2026-09-30.preview'));
  if (!r.ok) {
    const msg = (data.error && data.error.message) || 'Stripe ' + r.status;
    console.error('Stripe v2', method, p, r.status, msg);
    const e = new Error(msg); e.stripe = true; throw e;
  }
  return data;
}
function verifyStripeSignature(raw, header) {
  if (!header || !WH_SECRETS.length) return false;
  let t = null; const sigs = [];
  for (const part of header.split(',')) { const i = part.indexOf('='); const k = part.slice(0, i), v = part.slice(i + 1); if (k === 't') t = v; if (k === 'v1') sigs.push(v); }
  if (!t || !sigs.length || Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
  for (const secret of WH_SECRETS) {
    const expected = crypto.createHmac('sha256', secret).update(t + '.' + raw.toString('utf8')).digest('hex');
    for (const s of sigs) if (s.length === expected.length && crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))) return true;
  }
  return false;
}

/* ------------------------------------------------------------------ Sérialisation (ce que le navigateur reçoit) */
const parseJson = (s) => { try { return JSON.parse(s || '{}') || {}; } catch (e) { return {}; } };
const outUser = (u) => ({ billing: parseJson(u.billing), id: u.id, role: u.role, name: u.name, email: u.email, status: u.status, stripeAccount: u.stripe_account, payoutsReady: !!u.payouts_ready, detailsSubmitted: !!u.details_submitted, createdAt: u.created_at });
const outListing = (l) => ({ id: l.id, hostId: l.host_id, name: l.name, address: l.address, photo: l.photo, checkout: l.checkout, prices: JSON.parse(l.prices), paused: !!l.paused, deleted: !!l.deleted, slug: l.slug, createdAt: l.created_at });
const outRequest = (r, asGuest = false) => ({
  id: r.id, listingId: r.listing_id, hostId: r.host_id, guestName: r.guest_name, guestEmail: r.guest_email,
  guestToken: asGuest ? r.guest_token : undefined, payToken: asGuest ? r.pay_token : undefined,
  date: r.date, hours: r.hours, price: r.price, oldTime: r.old_time, newTime: r.new_time, message: r.message,
  status: r.status, expiredReason: r.expired_reason, createdAt: r.created_at, expiresAt: r.expires_at,
  decidedAt: r.decided_at, payExpiresAt: r.pay_expires_at, paidAt: r.paid_at });
const outPayment = (p) => ({ id: p.id, requestId: p.request_id, hostId: p.host_id, listingId: p.listing_id, amount: p.amount, commission: p.commission, stripeFee: p.stripe_fee, stripeFeeActual: p.stripe_fee_actual, net: p.net, status: p.status, method: p.method, last4: p.last4, stripeIntent: p.stripe_payment_intent, createdAt: p.created_at, refundedAt: p.refunded_at });
const outEmail = (e) => ({ id: e.id, to: e.to_addr, subject: e.subject, body: e.body, at: e.at });

/* ------------------------------------------------------------------ Sessions */
function cookies(req) {
  const o = {};
  for (const p of (req.headers.cookie || '').split(';')) { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); }
  return o;
}
function currentUser(req) {
  const t = cookies(req).lc_sid; if (!t) return null;
  return q('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').get(t) || null;
}
function openSession(res, userId) {
  const t = newToken();
  q('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)').run(t, userId, now());
  res.setHeader('Set-Cookie', `lc_sid=${t}; HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000${SECURE_COOKIE ? '; Secure' : ''}`);
}
function need(req, role) {
  const u = currentUser(req);
  if (!u) fail(401, 'Connectez-vous pour continuer.');
  if (u.status !== 'active') fail(403, 'Ce compte est suspendu.');
  if (role && u.role !== role) fail(403, 'Accès refusé.');
  return u;
}

/* ------------------------------------------------------------------ Expirations */
function sweep() {
  const t = now();
  // Paiement jamais finalisé par le voyageur : la demande disparaît sans bruit
  q("UPDATE requests SET status='abandoned' WHERE status='awaiting_payment' AND expires_at < ?").run(t);
  for (const r of q("SELECT * FROM requests WHERE status='pending' AND expires_at < ?").all(t)) {
    if (q("UPDATE requests SET status='expired', expired_reason='host' WHERE id=? AND status='pending'").run(r.id).changes) {
      if (r.payment_intent) releaseHold(r.payment_intent);
      sendEmail(r.guest_email, 'Votre demande de départ tardif a expiré', `Bonjour ${r.guest_name},\n\nVotre hôte n'a pas répondu à temps. Le montant réservé sur votre carte est libéré : rien n'a été prélevé. Merci de libérer le logement à ${r.old_time}.`);
    }
  }
  for (const r of q("SELECT * FROM requests WHERE status='accepted' AND pay_expires_at < ?").all(t)) {
    if (q("UPDATE requests SET status='expired', expired_reason='payment', pay_token=NULL WHERE id=? AND status='accepted'").run(r.id).changes) {
      if (r.checkout_session) stripe('POST', `/checkout/sessions/${r.checkout_session}/expire`).catch(() => {});
      sendEmail(r.guest_email, 'Votre lien de paiement a expiré', `Bonjour ${r.guest_name},\n\nLe lien de paiement a expiré : votre départ tardif n'est pas confirmé. Merci de libérer le logement à ${r.old_time}.`);
    }
  }
}
setInterval(() => { try { sweep(); } catch (e) { console.error('sweep', e); } }, 60000).unref();

/* ------------------------------------------------------------------ Stripe Connect : comptes hôtes */
async function syncAccount(user) {
  if (!user.stripe_account) return user;
  const a = await stripeV2('GET', `/v2/core/accounts/${user.stripe_account}?include=configuration.recipient`);
  const t = a.configuration && a.configuration.recipient && a.configuration.recipient.capabilities
    && a.configuration.recipient.capabilities.stripe_balance && a.configuration.recipient.capabilities.stripe_balance.stripe_transfers;
  const ready = !!(t && t.status === 'active');
  q('UPDATE users SET payouts_ready=?, details_submitted=? WHERE id=?').run(ready ? 1 : 0, ready ? 1 : 0, user.id);
  return q('SELECT * FROM users WHERE id=?').get(user.id);
}

/* ------------------------------------------------------------------ Empreinte bancaire (autorisation puis capture) */
function releaseHold(piId) {
  return stripe('POST', `/payment_intents/${piId}/cancel`, {}, { idem: 'cancel_' + piId }).catch((e) => console.error('Libération empreinte', piId, e.message));
}
const PI_EXPAND = { expand: ['latest_charge.balance_transaction', 'payment_method'] };
function recordCapturedPayment(r, pi) {
  const charge = pi.latest_charge && typeof pi.latest_charge === 'object' ? pi.latest_charge : null;
  const bt = charge && charge.balance_transaction && typeof charge.balance_transaction === 'object' ? charge.balance_transaction : null;
  const feeActual = bt ? (bt.fee_details || []).filter((f) => f.type === 'stripe_fee').reduce((a, f) => a + f.amount, 0) : null;
  const pm = pi.payment_method && typeof pi.payment_method === 'object' ? pi.payment_method : {};
  const wallet = pm.card && pm.card.wallet && pm.card.wallet.type;
  const method = wallet === 'apple_pay' ? 'apple_pay' : wallet === 'google_pay' ? 'google_pay' : (pm.type || 'card');
  const amount = pi.amount_received || pi.amount;
  const commission = Math.round(amount * COMMISSION_RATE), appFee = pi.application_fee_amount || 0;
  try {
    q(`INSERT INTO payments(id,request_id,host_id,listing_id,amount,commission,stripe_fee,stripe_fee_actual,net,status,method,last4,stripe_payment_intent,stripe_charge,created_at)
       VALUES(?,?,?,?,?,?,?,?,?,'succeeded',?,?,?,?,?)`)
      .run(newId('pay_'), r.id, r.host_id, r.listing_id, amount, commission, appFee - commission, feeActual, amount - appFee, method, (pm.card && pm.card.last4) || null, pi.id, charge ? charge.id : null, now());
  } catch (e) { if (/UNIQUE/i.test(e.message)) return false; throw e; }
  q("UPDATE requests SET status='paid', paid_at=?, decided_at=COALESCE(decided_at, ?) WHERE id=?").run(now(), now(), r.id);
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  const host = q('SELECT * FROM users WHERE id=?').get(r.host_id);
  sendEmail(r.guest_email, 'Votre départ tardif est confirmé', `Bonjour ${r.guest_name},\n\nVotre hôte a accepté : vous pouvez rester jusqu'à ${hFmt(r.new_time)} le ${dayFr(r.date)} à « ${l.name} ».\n${eur(amount)} ont été prélevés sur votre carte.`);
  sendEmail(host.email, 'Départ tardif vendu', `${r.guest_name} part à ${r.new_time} le ${dayFr(r.date)} (« ${l.name} »). Paiement de ${eur(amount)} encaissé.\nCommission LateCheck : ${eur(commission)} · frais de paiement : ${eur(appFee - commission)} · net pour vous : ${eur(amount - appFee)}.`);
  return true;
}
async function openCheckout(r) {
  if (r.checkout_session) {
    const ex = await stripe('GET', `/checkout/sessions/${r.checkout_session}`);
    if (ex.status === 'open') return ex.url; // double clic : même session
    if (ex.status === 'complete') return null;
  }
  const host = q('SELECT * FROM users WHERE id=?').get(r.host_id);
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  const split = computeSplit(r.price);
  const expiresAt = now() + 31 * 60000; // minimum imposé par Stripe : 30 min
  const s = await stripe('POST', '/checkout/sessions', {
    mode: 'payment', locale: 'fr', customer_email: r.guest_email,
    line_items: [{ quantity: 1, price_data: { currency: 'eur', unit_amount: r.price, product_data: {
      name: `Départ tardif ${hoursLabel(r.hours)} — ${l.name}`,
      description: `Départ à ${r.new_time} au lieu de ${r.old_time}, le ${dayFr(r.date)}. Montant réservé, prélevé seulement si l'hôte accepte.` } } }],
    payment_intent_data: {
      capture_method: 'manual',
      application_fee_amount: split.applicationFee,
      transfer_data: { destination: host.stripe_account },
      description: `LateCheck ${r.id}`, metadata: { request_id: r.id, listing_id: l.id, host_id: host.id },
    },
    metadata: { request_id: r.id },
    success_url: `${APP_URL}/#/r/${r.id}/${r.guest_token}?paid=1`,
    cancel_url: `${APP_URL}/#/r/${r.id}/${r.guest_token}`,
    expires_at: Math.floor(expiresAt / 1000),
  }, { idem: `cs_${r.id}_${r.checkout_session || 'first'}` });
  q("UPDATE requests SET checkout_session=?, expires_at=? WHERE id=? AND status='awaiting_payment'").run(s.id, expiresAt + 5 * 60000, r.id);
  return s.url;
}
async function onCheckoutAuthorized(s) {
  const rid = s.metadata && s.metadata.request_id;
  const r = rid && q('SELECT * FROM requests WHERE id=?').get(rid);
  if (!r) return;
  const pi = await stripe('GET', `/payment_intents/${s.payment_intent}`, PI_EXPAND);
  if (pi.status === 'succeeded') { recordCapturedPayment(r, pi); return; }
  if (pi.status !== 'requires_capture') return;
  const exp = now() + getSettings().requestTtlMin * 60000;
  if (!q("UPDATE requests SET status='pending', payment_intent=?, created_at=?, expires_at=? WHERE id=? AND status IN ('awaiting_payment','abandoned')").run(pi.id, now(), exp, r.id).changes) {
    if (['refused', 'cancelled', 'expired'].includes(q('SELECT status FROM requests WHERE id=?').get(r.id).status)) releaseHold(pi.id);
    return;
  }
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  const host = q('SELECT * FROM users WHERE id=?').get(r.host_id);
  sendPush(host.id, 'Nouvelle demande de départ tardif', `${r.guest_name} · ${hoursLabel(r.hours)} (jusqu'à ${r.new_time}) · ${eur(r.price)} · ${l.name}`, `#/h/requests/${r.id}`).catch((e) => console.error('push', e.message));
  sendEmail(host.email, 'Nouvelle demande de départ tardif', `${r.guest_name} demande ${hoursLabel(r.hours)} (départ à ${r.new_time}) le ${dayFr(r.date)} pour « ${l.name} ».\nLe paiement de ${eur(r.price)} est déjà réservé : acceptez pour l'encaisser.\nRépondez avant ${timeFr(exp)} : ${APP_URL}/#/h/requests/${r.id}`);
  sendEmail(r.guest_email, 'Votre demande a bien été envoyée', `Bonjour ${r.guest_name},\n\nVotre demande de départ à ${r.new_time} a été transmise à votre hôte.\n${eur(r.price)} sont réservés sur votre carte : ils ne seront prélevés que si votre hôte accepte.\nSuivre la demande : ${APP_URL}/#/r/${r.id}/${r.guest_token}`);
}

/* ------------------------------------------------------------------ Rattrapage sans webhook
   Si le webhook Stripe n'arrive pas (URL ou secret erronés, panne), on interroge Stripe nous-mêmes :
   au retour du voyageur sur la page de confirmation, puis chaque minute pour les paiements récents. */
async function reconcileCheckout(r) {
  if (!r || !r.checkout_session || !['awaiting_payment', 'abandoned', 'accepted'].includes(r.status)) return false;
  const s = await stripe('GET', `/checkout/sessions/${r.checkout_session}`);
  if (s.status !== 'complete') return false;
  const fresh = q('SELECT status FROM requests WHERE id=?').get(r.id);
  if (!fresh || fresh.status !== r.status) return false; // déjà traité entre-temps (webhook arrivé)
  console.warn(`Rattrapage : paiement ${r.id} confirmé directement auprès de Stripe (le webhook n'est pas arrivé)`);
  if (s.payment_status === 'paid') await onCheckoutCompleted(s); else await onCheckoutAuthorized(s);
  return true;
}
let reconciling = false;
setInterval(async () => {
  if (reconciling) return; reconciling = true;
  try {
    const recent = q("SELECT * FROM requests WHERE checkout_session IS NOT NULL AND status IN ('awaiting_payment','abandoned') AND expires_at > ? ORDER BY expires_at DESC LIMIT 25").all(now() - 2 * 3600000);
    for (const r of recent) { try { await reconcileCheckout(r); } catch (e) { console.error('rattrapage', r.id, e.message); } }
  } finally { reconciling = false; }
}, 60000).unref();

/* ------------------------------------------------------------------ Paiements confirmés par webhook */
function markRefunded(paymentId) {
  const p = q('SELECT * FROM payments WHERE id=?').get(paymentId);
  if (!p || !q("UPDATE payments SET status='refunded', refunded_at=? WHERE id=? AND status='succeeded'").run(now(), p.id).changes) return false;
  const r = q('SELECT * FROM requests WHERE id=?').get(p.request_id);
  q("UPDATE requests SET status='refunded' WHERE id=?").run(p.request_id);
  issueCreditNote(p);
  const host = q('SELECT * FROM users WHERE id=?').get(p.host_id);
  if (r) sendEmail(r.guest_email, 'Remboursement de votre départ tardif', `Bonjour ${r.guest_name},\n\n${eur(p.amount)} vous ont été remboursés. Le départ tardif est annulé : merci de libérer le logement à ${r.old_time}.`);
  if (host) sendEmail(host.email, 'Paiement remboursé', `Le paiement de ${eur(p.amount)} de ${r ? r.guest_name : 'votre voyageur'} a été remboursé.`);
  return true;
}
async function onCheckoutCompleted(s) {
  if (s.payment_status !== 'paid') return;
  const rid = s.metadata && s.metadata.request_id;
  const r = rid && q('SELECT * FROM requests WHERE id=?').get(rid);
  if (!r) { console.warn('checkout.session.completed sans demande connue', s.id); return; }
  if (q("SELECT 1 FROM payments WHERE request_id=? AND status IN ('succeeded','refunded')").get(r.id)) return; // déjà traité

  const pi = await stripe('GET', `/payment_intents/${s.payment_intent}`, { expand: ['latest_charge.balance_transaction', 'payment_method'] });
  const charge = pi.latest_charge && typeof pi.latest_charge === 'object' ? pi.latest_charge : null;
  const bt = charge && charge.balance_transaction && typeof charge.balance_transaction === 'object' ? charge.balance_transaction : null;
  const feeActual = bt ? (bt.fee_details || []).filter((f) => f.type === 'stripe_fee').reduce((a, f) => a + f.amount, 0) : null;
  const pm = pi.payment_method && typeof pi.payment_method === 'object' ? pi.payment_method : {};
  const method = pm.card && pm.card.wallet && pm.card.wallet.type === 'apple_pay' ? 'apple_pay' : pm.card && pm.card.wallet && pm.card.wallet.type === 'google_pay' ? 'google_pay' : (pm.type || 'card');
  const commission = Math.round(pi.amount * COMMISSION_RATE);
  const appFee = pi.application_fee_amount || 0;

  try {
    q(`INSERT INTO payments(id,request_id,host_id,listing_id,amount,commission,stripe_fee,stripe_fee_actual,net,status,method,last4,stripe_payment_intent,stripe_charge,created_at)
       VALUES(?,?,?,?,?,?,?,?,?,'succeeded',?,?,?,?,?)`)
      .run(newId('pay_'), r.id, r.host_id, r.listing_id, pi.amount, commission, appFee - commission, feeActual, pi.amount - appFee, method, (pm.card && pm.card.last4) || null, pi.id, charge ? charge.id : null, now());
  } catch (e) { if (/UNIQUE/i.test(e.message)) return; throw e; } // webhook en double

  const fresh = q('SELECT * FROM requests WHERE id=?').get(r.id);
  if (['refused', 'cancelled'].includes(fresh.status)) {
    // Ne devrait pas arriver : paiement reçu pour une demande annulée → remboursement automatique
    const p = q("SELECT * FROM payments WHERE request_id=? AND status='succeeded'").get(r.id);
    await stripe('POST', '/refunds', { payment_intent: pi.id, reverse_transfer: true, refund_application_fee: true }, { idem: 're_' + p.id });
    markRefunded(p.id);
    return;
  }
  q("UPDATE requests SET status='paid', paid_at=?, pay_token_used=pay_token, pay_token=NULL WHERE id=?").run(now(), r.id);
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  const host = q('SELECT * FROM users WHERE id=?').get(r.host_id);
  sendEmail(r.guest_email, 'Votre départ tardif est confirmé', `Bonjour ${r.guest_name},\n\nPaiement de ${eur(pi.amount)} reçu. Votre départ tardif est confirmé : vous pouvez rester jusqu'à ${hFmt(r.new_time)} le ${dayFr(r.date)} à « ${l.name} ».`);
  sendEmail(host.email, 'Départ tardif payé', `${r.guest_name} a payé ${eur(pi.amount)} pour partir à ${r.new_time} le ${dayFr(r.date)} (« ${l.name} »).\nCommission LateCheck : ${eur(commission)} · frais de paiement : ${eur(appFee - commission)} · net pour vous : ${eur(pi.amount - appFee)}.`);
}
async function handleStripeEvent(ev) {
  const o = ev.data.object;
  switch (ev.type) {
    case 'checkout.session.completed':
    case 'checkout.session.async_payment_succeeded':
      if (o.payment_status === 'paid') return onCheckoutCompleted(o); // ancien parcours (paiement après acceptation)
      return onCheckoutAuthorized(o);                                  // empreinte bancaire
    case 'payment_intent.succeeded': {
      const rid = o.metadata && o.metadata.request_id;
      const r = rid && q('SELECT * FROM requests WHERE id=?').get(rid);
      if (!r || o.capture_method !== 'manual' || q("SELECT 1 FROM payments WHERE request_id=? AND status IN ('succeeded','refunded')").get(r.id)) return;
      return recordCapturedPayment(r, await stripe('GET', `/payment_intents/${o.id}`, PI_EXPAND));
    }
    case 'payment_intent.canceled': {
      const r = q("SELECT * FROM requests WHERE payment_intent=? AND status='pending'").get(o.id);
      if (r && q("UPDATE requests SET status='expired', expired_reason='host' WHERE id=? AND status='pending'").run(r.id).changes)
        sendEmail(r.guest_email, 'Votre demande de départ tardif a expiré', `Bonjour ${r.guest_name},\n\nLe montant réservé sur votre carte est libéré : rien n'a été prélevé.`);
      return;
    }
    case 'checkout.session.expired': {
      q("UPDATE requests SET status='abandoned' WHERE checkout_session=? AND status='awaiting_payment'").run(o.id);
      const r = q("SELECT * FROM requests WHERE checkout_session=? AND status='accepted'").get(o.id);
      if (r && now() > r.pay_expires_at) sweep();
      else if (r) q('UPDATE requests SET checkout_session=NULL WHERE id=?').run(r.id); // le voyageur pourra relancer un paiement
      return;
    }
    case 'payment_intent.payment_failed': {
      const rid = o.metadata && o.metadata.request_id;
      const r = rid && q('SELECT * FROM requests WHERE id=?').get(rid);
      if (!r) return;
      const err = o.last_payment_error || {};
      const last4 = err.payment_method && err.payment_method.card ? err.payment_method.card.last4 : null;
      q(`INSERT INTO payments(id,request_id,host_id,listing_id,amount,status,method,last4,stripe_payment_intent,created_at) VALUES(?,?,?,?,?,'failed','card',?,?,?)`)
        .run(newId('pay_'), r.id, r.host_id, r.listing_id, o.amount, last4, o.id, now());
      return;
    }
    case 'charge.refunded': {
      if (!o.refunded) return; // remboursement partiel : non géré en V1
      const p = q("SELECT * FROM payments WHERE stripe_payment_intent=? AND status='succeeded'").get(o.payment_intent);
      if (p) markRefunded(p.id);
      return;
    }
    case 'account.updated': {
      const ready = !!(o.details_submitted && o.capabilities && o.capabilities.transfers === 'active');
      q('UPDATE users SET payouts_ready=?, details_submitted=? WHERE stripe_account=?').run(ready ? 1 : 0, o.details_submitted ? 1 : 0, o.id);
      return;
    }
    default: return;
  }
}

/* ------------------------------------------------------------------ Routeur */
const routes = [];
const route = (method, pattern, fn, opts = {}) => routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '([^/]+)') + '$'), fn, opts });

/* État : chaque rôle ne reçoit que ses propres données */
route('GET', '/api/state', (req) => {
  sweep();
  const u = currentUser(req);
  const out = { me: null, hasAdmin: !!q("SELECT 1 FROM users WHERE role='admin'").get(), adminConfigured: !!ADMIN_EMAIL,
    stripeMode: STRIPE_MODE, pushEnabled: APNS.enabled, legal: LEGAL, users: [], listings: [], requests: [], payments: [], emails: [], settings: getSettings(), guest: null };
  if (u && u.status === 'active') {
    out.me = outUser(u);
    if (u.role === 'admin') {
      out.users = q('SELECT * FROM users ORDER BY created_at DESC').all().map(outUser);
      out.listings = q('SELECT * FROM listings').all().map(outListing);
      out.requests = q('SELECT * FROM requests ORDER BY created_at DESC').all().map((r) => outRequest(r));
      out.payments = q('SELECT * FROM payments ORDER BY created_at DESC').all().map(outPayment);
      out.emails = q('SELECT * FROM emails ORDER BY at DESC LIMIT 100').all().map(outEmail);
    } else {
      out.users = [out.me];
      out.listings = q('SELECT * FROM listings WHERE host_id=?').all(u.id).map(outListing);
      out.requests = q("SELECT * FROM requests WHERE host_id=? AND status NOT IN ('awaiting_payment','abandoned') ORDER BY created_at DESC").all(u.id).map((r) => outRequest(r));
      out.payments = q('SELECT * FROM payments WHERE host_id=? ORDER BY created_at DESC').all(u.id).map(outPayment);
      out.emails = q('SELECT * FROM emails WHERE to_addr=? ORDER BY at DESC LIMIT 20').all(u.email).map(outEmail);
    }
  }
  const addListing = (l) => { if (l && !out.listings.some((x) => x.id === l.id)) out.listings.push(outListing(l)); };
  const addRequest = (r) => { if (!r) return; out.requests = out.requests.filter((x) => x.id !== r.id); out.requests.push(outRequest(r, true)); addListing(q('SELECT * FROM listings WHERE id=?').get(r.listing_id)); };
  const { slug, rid, rt, pay, mine } = req.query;
  if (slug) {
    const l = q('SELECT * FROM listings WHERE slug=?').get(slug);
    if (l && !l.deleted) {
      const host = q('SELECT status, payouts_ready FROM users WHERE id=?').get(l.host_id);
      out.guest = { listingId: l.id, available: !l.paused && host.status === 'active' && !!host.payouts_ready };
      addListing(l);
    }
  }
  if (rid && rt) addRequest(q('SELECT * FROM requests WHERE id=? AND guest_token=?').get(rid, rt));
  if (pay) addRequest(q('SELECT * FROM requests WHERE pay_token=? OR pay_token_used=?').get(pay, pay));
  if (mine) for (const pair of String(mine).split(',').slice(0, 20)) { const [i, t] = pair.split(':'); if (i && t) addRequest(q('SELECT * FROM requests WHERE id=? AND guest_token=?').get(i, t)); }
  return out;
});

/* Authentification */
route('POST', '/api/auth/signup', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80), email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!name || !isEmail(email)) fail(400, 'Renseignez un nom et un e-mail valide.');
  if (pw.length < 8) fail(400, 'Le mot de passe doit contenir au moins 8 caractères.');
  if (email === ADMIN_EMAIL) fail(400, 'Cet e-mail est réservé au compte administrateur.');
  if (!req.body.acceptTerms) fail(400, "Acceptez les conditions générales d'utilisation pour créer votre compte.");
  if (q('SELECT 1 FROM users WHERE email=?').get(email)) fail(409, 'Un compte existe déjà avec cet e-mail.');
  const id = newId('usr_');
  q("INSERT INTO users(id,role,name,email,pw,created_at,terms_accepted_at) VALUES(?,'host',?,?,?,?,?)").run(id, name, email, hashPw(pw), now(), now());
  sendEmail(email, 'Bienvenue sur LateCheck', `Bonjour ${name},\n\nVotre compte hôte est prêt. Connectez Stripe pour recevoir vos paiements, puis ajoutez votre premier logement.`);
  openSession(res, id);
});
route('POST', '/api/auth/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !checkPw(String(req.body.password || ''), u.pw)) fail(401, 'E-mail ou mot de passe incorrect.');
  if (u.status !== 'active') fail(403, 'Ce compte est suspendu.');
  openSession(res, u.id);
  return { role: u.role };
});
route('POST', '/api/auth/logout', (req, res) => {
  const t = cookies(req).lc_sid; if (t) q('DELETE FROM sessions WHERE token=?').run(t);
  res.setHeader('Set-Cookie', 'lc_sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
});
route('POST', '/api/auth/setup-admin', (req, res) => {
  if (!ADMIN_EMAIL) fail(400, 'Définissez ADMIN_EMAIL dans le fichier .env du serveur.');
  if (q("SELECT 1 FROM users WHERE role='admin'").get()) fail(409, 'Le compte administrateur existe déjà.');
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (email !== ADMIN_EMAIL) fail(403, "Cet e-mail ne correspond pas à l'ADMIN_EMAIL du serveur.");
  if (pw.length < 10) fail(400, 'Le mot de passe administrateur doit contenir au moins 10 caractères.');
  const id = newId('usr_');
  q("INSERT INTO users(id,role,name,email,pw,created_at) VALUES(?,'admin',?,?,?,?)").run(id, String(req.body.name || 'Administrateur').slice(0, 80), email, hashPw(pw), now());
  openSession(res, id);
});

/* Stripe Connect : hôte */
route('POST', '/api/stripe/connect', async (req) => {
  let u = need(req, 'host');
  if (!APP_URL.startsWith('https://') && !env.STRIPE_API_BASE) fail(500, "APP_URL doit être une adresse https:// (réglage du serveur).");
  if (!u.stripe_account) {
    const a = await stripeV2('POST', '/v2/core/accounts', {
      contact_email: u.email, display_name: u.name, dashboard: 'express',
      identity: { country: 'fr' },
      defaults: { responsibilities: { fees_collector: 'application', losses_collector: 'application' } },
      configuration: { recipient: { capabilities: { stripe_balance: { stripe_transfers: { requested: true } } } } },
      metadata: { latecheck_user: u.id },
    }, { idem: 'acctv2_' + u.id });
    q('UPDATE users SET stripe_account=?, stripe_mode=? WHERE id=?').run(a.id, STRIPE_MODE, u.id);
    u = q('SELECT * FROM users WHERE id=?').get(u.id);
  }
  const makeLink = () => stripeV2('POST', '/v2/core/account_links', {
    account: u.stripe_account,
    use_case: { type: 'account_onboarding', account_onboarding: {
      refresh_url: `${APP_URL}/#/h/account?stripe=refresh`,
      return_url: `${APP_URL}/#/h/account?stripe=return`,
    } },
  });
  let link;
  try { link = await makeLink(); }
  catch (e) {
    if (!/no such|not found|does not exist|resource_missing|invalid account/i.test(e.message)) throw e;
    q('UPDATE users SET stripe_account=NULL, payouts_ready=0, details_submitted=0 WHERE id=?').run(u.id); // compte d'un autre mode : on recommence
    fail(409, 'Votre ancienne connexion Stripe n\'est plus valable. Cliquez à nouveau sur « Connecter mon compte Stripe ».');
  }
  return { url: link.url };
});
route('POST', '/api/stripe/refresh', async (req) => { const u = need(req, 'host'); const x = await syncAccount(u); return { payoutsReady: !!x.payouts_ready }; });
route('POST', '/api/stripe/dashboard', async (req) => {
  const u = need(req, 'host'); if (!u.stripe_account) fail(400, "Connectez d'abord votre compte Stripe.");
  const l = await stripe('POST', `/accounts/${u.stripe_account}/login_links`);
  return { url: l.url };
});

/* Factures et relevés */
route('GET', '/api/invoices', (req) => {
  const u = need(req, 'host'); issueInvoices();
  const cur = parisMonth(now()), curPays = q("SELECT * FROM payments WHERE host_id=? AND status='succeeded' AND invoice_id IS NULL").all(u.id).filter((p) => parisMonth(p.created_at) === cur);
  return {
    invoices: q('SELECT id, number, type, month, issued_at, sales, ttc, count, ref FROM invoices WHERE host_id=? ORDER BY issued_at DESC').all(u.id),
    current: { month: cur, sales: curPays.reduce((a, p) => a + p.amount, 0), fees: curPays.reduce((a, p) => a + p.commission + p.stripe_fee, 0), count: curPays.length },
  };
});
route('PUT', '/api/account/billing', (req) => {
  const u = need(req, 'host'), b = req.body || {}, clean = (v, n) => String(v || '').trim().slice(0, n);
  const billing = { company: clean(b.company, 100), address: clean(b.address, 200), siren: clean(b.siren, 20).replace(/\s/g, ''), vat: clean(b.vat, 20).replace(/\s/g, '').toUpperCase() };
  if (billing.siren && !/^\d{9}$/.test(billing.siren)) fail(400, 'Le SIREN doit contenir 9 chiffres.');
  q('UPDATE users SET billing=? WHERE id=?').run(JSON.stringify(billing), u.id);
});
route('POST', '/api/docs/link', (req) => {
  const u = need(req, 'host'), b = req.body || {};
  if (b.kind === 'invoice') {
    const inv = q('SELECT * FROM invoices WHERE id=? AND host_id=?').get(String(b.id || ''), u.id); if (!inv) fail(404, 'Facture introuvable.');
    return { url: `${APP_URL}/api/docs/${signDoc({ k: 'invoice', id: inv.id, u: u.id })}` };
  }
  if (b.kind === 'csv') {
    if (!/^\d{4}-\d{2}$/.test(String(b.month || ''))) fail(400, 'Mois invalide.');
    return { url: `${APP_URL}/api/docs/${signDoc({ k: 'csv', m: b.month, u: u.id })}` };
  }
  fail(400, 'Document inconnu.');
});
route('GET', '/api/docs/:t', (req, res, t) => {
  const p = readDoc(t);
  if (!p) { res.writeHead(410, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Lien expiré. Retournez dans LateCheck et touchez à nouveau le document.'); return; }
  if (p.k === 'invoice') {
    const inv = q('SELECT * FROM invoices WHERE id=? AND host_id=?').get(p.id, p.u); if (!inv) fail(404, 'Facture introuvable.');
    const pdf = invoicePdf(inv);
    res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Length': pdf.length, 'Content-Disposition': `inline; filename="${inv.number}.pdf"`, 'Cache-Control': 'private, no-store' });
    res.end(pdf); return;
  }
  if (p.k === 'csv') {
    res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="latecheck-releve-${p.m}.csv"`, 'Cache-Control': 'private, no-store' });
    res.end(monthCsv(p.u, p.m)); return;
  }
  fail(404, 'Document inconnu.');
});

/* Notifications push : enregistrement de l'appareil */
route('POST', '/api/push/register', (req) => {
  const u = need(req, 'host');
  const token = String(req.body.token || '');
  if (!/^[0-9a-fA-F]{32,200}$/.test(token)) fail(400, 'Jeton de notification invalide.');
  q("INSERT INTO push_tokens(token,user_id,platform,created_at) VALUES(?,?,'ios',?) ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id").run(token, u.id, now());
  return { enabled: APNS.enabled };
});

/* Notifications push : diagnostic complet depuis l'app (Mon compte → Tester les notifications) */
route('POST', '/api/push/test', async (req) => {
  const u = need(req, 'host');
  const tokens = q('SELECT * FROM push_tokens WHERE user_id=? ORDER BY created_at DESC').all(u.id);
  const out = { enabled: APNS.enabled, keyIdLen: (APNS.keyId || '').length, teamIdLen: (APNS.teamId || '').length,
    keyFound: !!APNS.key, keyError: APNS.keyError, keyId: APNS.keyId, bundleId: APNS.bundleId, tokens: tokens.length, results: [] };
  if (!APNS.enabled) return out;
  const payload = { aps: { alert: { title: 'Test LateCheck', body: 'Les notifications fonctionnent 🎉' }, sound: 'default' }, url: '#/h/account' };
  for (const t of tokens.slice(0, 3)) {
    const prod = await apnsSend('https://api.push.apple.com', t.token, payload);
    const sand = prod.status === 200 ? null : await apnsSend('https://api.sandbox.push.apple.com', t.token, payload);
    console.log('APNs test', t.token.slice(0, 8), 'production', prod.status, prod.reason, sand ? `| sandbox ${sand.status} ${sand.reason}` : '');
    out.results.push({ prod, sand });
  }
  return out;
});

/* Suppression du compte hôte (exigée par Apple, droit à l'effacement RGPD).
   Les paiements passés sont conservés, anonymisés, pour les obligations comptables. */
route('POST', '/api/account/delete', async (req, res) => {
  const u = need(req, 'host');
  if (!checkPw(String(req.body.password || ''), u.pw)) fail(403, 'Mot de passe incorrect.');
  for (const r of q("SELECT * FROM requests WHERE host_id=? AND status IN ('pending','capturing','accepted','awaiting_payment')").all(u.id)) {
    q("UPDATE requests SET status='cancelled', pay_token=NULL WHERE id=?").run(r.id);
    if (r.payment_intent) await releaseHold(r.payment_intent);
    if (r.status !== 'awaiting_payment') sendEmail(r.guest_email, 'Demande annulée', `Bonjour ${r.guest_name},\n\nCe logement n'accepte plus de demandes. Le montant réservé est libéré : rien n'a été prélevé.`);
  }
  q("UPDATE requests SET guest_name='Voyageur', guest_email='anonyme@latecheck.invalid', message=NULL WHERE host_id=?").run(u.id);
  q('UPDATE listings SET deleted=1, paused=1, photo=NULL, name=?, address=? WHERE host_id=?').run('Logement supprimé', '', u.id);
  q('DELETE FROM push_tokens WHERE user_id=?').run(u.id);
  q('DELETE FROM sessions WHERE user_id=?').run(u.id);
  q('DELETE FROM emails WHERE to_addr=?').run(u.email);
  q("UPDATE users SET status='deleted', name='Compte supprimé', email=?, pw=?, stripe_account=NULL, payouts_ready=0 WHERE id=?")
    .run(`supprime+${u.id}@latecheck.invalid`, hashPw(newToken()), u.id);
  res.setHeader('Set-Cookie', 'lc_sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
});

/* Logements */
function readListingBody(b) {
  const name = String(b.name || '').trim().slice(0, 60), address = String(b.address || '').trim().slice(0, 120), checkout = String(b.checkout || '');
  if (!name || !address || !/^([01]\d|2[0-3]):[0-5]\d$/.test(checkout)) fail(400, "Renseignez le nom, l'adresse et l'heure de départ.");
  const photo = b.photo ? String(b.photo) : null;
  if (photo && (!/^data:image\/(jpeg|png|webp);base64,/.test(photo) || photo.length > 2500000)) fail(400, 'Photo invalide ou trop lourde (2 Mo maximum).');
  return { name, address, checkout, photo };
}
const ownListing = (u, id) => { const l = q('SELECT * FROM listings WHERE id=? AND host_id=? AND deleted=0').get(id, u.id); if (!l) fail(404, 'Logement introuvable.'); return l; };
route('POST', '/api/listings', (req) => {
  const u = need(req, 'host'); const b = readListingBody(req.body); const id = newId('lst_');
  q('INSERT INTO listings(id,host_id,name,address,photo,checkout,prices,slug,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, u.id, b.name, b.address, b.photo, b.checkout, JSON.stringify({ 1: 500, 2: 1000, 3: 1500, 4: 2000 }), crypto.randomBytes(6).toString('base64url'), now());
  return { id };
});
route('PUT', '/api/listings/:id', (req, _res, id) => {
  const u = need(req, 'host'); ownListing(u, id); const b = readListingBody(req.body);
  q('UPDATE listings SET name=?, address=?, photo=?, checkout=? WHERE id=?').run(b.name, b.address, b.photo, b.checkout, id);
});
route('PUT', '/api/listings/:id/prices', (req, _res, id) => {
  const u = need(req, 'host'); ownListing(u, id); const p = req.body.prices || {}; const prices = {};
  for (const h of [1, 2, 3, 4]) { const v = Math.round(Number(p[h])); if (!Number.isFinite(v) || v < 100 || v > 50000) fail(400, 'Chaque tarif doit être compris entre 1 € et 500 €.'); prices[h] = v; }
  q('UPDATE listings SET prices=? WHERE id=?').run(JSON.stringify(prices), id);
});
route('PUT', '/api/listings/:id/pause', (req, _res, id) => {
  const u = need(req, 'host'); ownListing(u, id);
  q('UPDATE listings SET paused=? WHERE id=?').run(req.body.paused ? 1 : 0, id);
});
route('DELETE', '/api/listings/:id', (req, _res, id) => {
  const u = need(req, 'host'); ownListing(u, id);
  q('UPDATE listings SET deleted=1, paused=1 WHERE id=?').run(id);
  q("UPDATE requests SET status='abandoned' WHERE listing_id=? AND status='awaiting_payment'").run(id);
  for (const r of q("SELECT * FROM requests WHERE listing_id=? AND status IN ('pending','accepted')").all(id)) {
    q("UPDATE requests SET status='cancelled', pay_token=NULL WHERE id=?").run(r.id);
    if (r.payment_intent) releaseHold(r.payment_intent);
    if (r.checkout_session) stripe('POST', `/checkout/sessions/${r.checkout_session}/expire`).catch(() => {});
    sendEmail(r.guest_email, 'Demande annulée', `Bonjour ${r.guest_name},\n\nCe logement n'accepte plus de demandes de départ tardif. Aucun paiement n'a été effectué.`);
  }
});

/* Demandes : décisions de l'hôte */
route('POST', '/api/requests/:id/accept', async (req, _res, id) => {
  const u = need(req, 'host');
  let r = q('SELECT * FROM requests WHERE id=? AND host_id=?').get(id, u.id);
  if (!r) fail(404, 'Demande introuvable.');
  sweep();
  r = q('SELECT * FROM requests WHERE id=?').get(id);
  if (r.status !== 'pending' || !r.payment_intent) fail(409, 'Cette demande a déjà été traitée ou a expiré.');
  if (!q("UPDATE requests SET status='capturing', decided_at=? WHERE id=? AND status='pending'").run(now(), id).changes) fail(409, 'Cette demande est déjà en cours de traitement.');
  let pi;
  try { pi = await stripe('POST', `/payment_intents/${r.payment_intent}/capture`, PI_EXPAND, { idem: 'capture_' + r.id }); }
  catch (e) {
    let st = null; try { st = (await stripe('GET', `/payment_intents/${r.payment_intent}`)).status; } catch (_) {}
    if (st === 'succeeded') pi = await stripe('GET', `/payment_intents/${r.payment_intent}`, PI_EXPAND);
    else if (st === 'requires_capture') { q("UPDATE requests SET status='pending' WHERE id=?").run(id); throw e; }
    else {
      q("UPDATE requests SET status='expired', expired_reason='payment' WHERE id=?").run(id);
      sendEmail(r.guest_email, 'Votre demande de départ tardif', `Bonjour ${r.guest_name},\n\nLe paiement réservé n'a pas pu être encaissé : votre départ tardif n'est pas confirmé. Merci de libérer le logement à ${r.old_time}.`);
      fail(409, "La réservation du paiement a expiré : rien n'a pu être encaissé. Le voyageur est prévenu.");
    }
  }
  recordCapturedPayment(r, pi);
});
route('POST', '/api/requests/:id/refuse', async (req, _res, id) => {
  const u = need(req, 'host');
  const r = q('SELECT * FROM requests WHERE id=? AND host_id=?').get(id, u.id);
  if (!r) fail(404, 'Demande introuvable.');
  if (!q("UPDATE requests SET status='refused', decided_at=?, pay_token=NULL WHERE id=? AND status='pending'").run(now(), id).changes) fail(409, 'Cette demande a déjà été traitée.');
  if (r.payment_intent) await releaseHold(r.payment_intent);
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  sendEmail(r.guest_email, 'Votre demande de départ tardif', `Bonjour ${r.guest_name},\n\nVotre hôte ne peut pas accepter votre demande pour « ${l.name} ». Le montant réservé sur votre carte est libéré : rien n'a été prélevé. Merci de libérer le logement à ${r.old_time}.`);
});

/* Remboursement (hôte propriétaire du paiement ou administrateur) */
route('POST', '/api/payments/:id/refund', async (req, _res, id) => {
  const u = need(req);
  const p = q('SELECT * FROM payments WHERE id=?').get(id);
  if (!p || (u.role !== 'admin' && p.host_id !== u.id)) fail(404, 'Paiement introuvable.');
  if (p.status !== 'succeeded') fail(409, 'Ce paiement ne peut pas être remboursé.');
  await stripe('POST', '/refunds', { payment_intent: p.stripe_payment_intent, reverse_transfer: true, refund_application_fee: true }, { idem: 're_' + p.id });
  markRefunded(p.id);
});

/* Voyageur (sans compte) */
route('POST', '/api/public/requests', async (req) => {
  sweep();
  const b = req.body;
  const l = q('SELECT * FROM listings WHERE slug=? AND deleted=0').get(String(b.slug || ''));
  if (!l) fail(404, 'Logement introuvable.');
  const host = q('SELECT * FROM users WHERE id=?').get(l.host_id);
  if (l.paused || host.status !== 'active' || !host.payouts_ready) fail(409, "Ce logement n'accepte pas de demandes pour le moment.");
  const hours = Number(b.hours), name = String(b.name || '').trim().slice(0, 40), email = String(b.email || '').trim().toLowerCase(), date = String(b.date || ''), message = String(b.message || '').trim().slice(0, 300);
  if (![1, 2, 3, 4].includes(hours)) fail(400, 'Durée invalide.');
  if (!b.acceptCgv) fail(400, 'Acceptez les conditions générales de vente pour continuer.');
  if (!name || !isEmail(email)) fail(400, 'Renseignez votre prénom et un e-mail valide.');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || date < todayParis()) fail(400, 'Choisissez une date de départ à venir.');
  const dup = q("SELECT * FROM requests WHERE listing_id=? AND guest_email=? AND date=? AND status IN ('pending','accepted','paid','capturing')").get(l.id, email, date);
  if (dup) return { id: dup.id, guestToken: dup.guest_token, duplicate: true, url: null };
  const prices = JSON.parse(l.prices);
  let r = q("SELECT * FROM requests WHERE listing_id=? AND guest_email=? AND date=? AND hours=? AND status='awaiting_payment'").get(l.id, email, date, hours);
  if (!r) {
    const id = newId('req_');
    q(`INSERT INTO requests(id,listing_id,host_id,guest_name,guest_email,guest_token,date,hours,price,old_time,new_time,message,status,created_at,expires_at,cgv_accepted_at)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'awaiting_payment',?,?,?)`)
      .run(id, l.id, l.host_id, name, email, newToken(), date, hours, prices[hours], l.checkout, addHours(l.checkout, hours), message || null, now(), now() + 40 * 60000, now());
    r = q('SELECT * FROM requests WHERE id=?').get(id);
  }
  try { return { id: r.id, guestToken: r.guest_token, url: await openCheckout(r) }; }
  catch (e) { q("UPDATE requests SET status='abandoned' WHERE id=? AND status='awaiting_payment'").run(r.id); throw e; }
});
route('POST', '/api/public/requests/:id/sync', async (req, _res, id) => {
  const r = q('SELECT * FROM requests WHERE id=? AND guest_token=?').get(id, String(req.body.t || ''));
  if (!r) fail(404, 'Demande introuvable.');
  await reconcileCheckout(r);
  return { status: q('SELECT status FROM requests WHERE id=?').get(id).status };
}, { rate: 'public' });

route('POST', '/api/public/requests/:id/checkout', async (req, _res, id) => {
  sweep();
  const r = q('SELECT * FROM requests WHERE id=? AND guest_token=?').get(id, String(req.body.t || ''));
  if (!r) fail(404, 'Demande introuvable.');
  if (r.status !== 'awaiting_payment') fail(409, 'Ce paiement ne peut plus être repris. Refaites une demande depuis la page du logement.');
  return { url: await openCheckout(r) };
});
route('POST', '/api/public/pay/:token/checkout', async (req, _res, token) => {
  sweep();
  const r = q('SELECT * FROM requests WHERE pay_token=?').get(token);
  if (!r || r.status !== 'accepted') fail(410, 'Ce lien de paiement a expiré ou a déjà été utilisé.');
  if (r.checkout_session) {
    const ex = await stripe('GET', `/checkout/sessions/${r.checkout_session}`);
    if (ex.status === 'open') return { url: ex.url };            // double clic : même session
    if (ex.status === 'complete') return { url: null, done: true };
  }
  const host = q('SELECT * FROM users WHERE id=?').get(r.host_id);
  if (host.status !== 'active' || !host.payouts_ready || !host.stripe_account) fail(409, 'Votre hôte ne peut pas encaisser de paiement pour le moment.');
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  const split = computeSplit(r.price);
  const expiresAt = Math.max(r.pay_expires_at, now() + 31 * 60000); // Stripe exige au moins 30 min
  const s = await stripe('POST', '/checkout/sessions', {
    mode: 'payment', locale: 'fr', customer_email: r.guest_email,
    line_items: [{ quantity: 1, price_data: { currency: 'eur', unit_amount: r.price, product_data: {
      name: `Départ tardif ${hoursLabel(r.hours)} — ${l.name}`, description: `Départ à ${r.new_time} au lieu de ${r.old_time}, le ${dayFr(r.date)}` } } }],
    payment_intent_data: {
      application_fee_amount: split.applicationFee,
      transfer_data: { destination: host.stripe_account },
      description: `LateCheck ${r.id}`, metadata: { request_id: r.id, listing_id: l.id, host_id: host.id },
    },
    metadata: { request_id: r.id },
    success_url: `${APP_URL}/#/r/${r.id}/${r.guest_token}?paid=1`,
    cancel_url: `${APP_URL}/#/pay/${token}`,
    expires_at: Math.floor(expiresAt / 1000),
  }, { idem: `cs_${r.id}_${r.checkout_session || 'first'}` });
  q("UPDATE requests SET checkout_session=?, pay_expires_at=? WHERE id=? AND status='accepted'").run(s.id, expiresAt, r.id);
  return { url: s.url };
});

/* Administration */
route('POST', '/api/admin/hosts/:id/toggle', (req, _res, id) => {
  need(req, 'admin');
  const h = q("SELECT * FROM users WHERE id=? AND role='host' AND status IN ('active','suspended')").get(id); if (!h) fail(404, 'Hôte introuvable ou compte supprimé.');
  q('UPDATE users SET status=? WHERE id=?').run(h.status === 'active' ? 'suspended' : 'active', id);
  if (h.status === 'active') q('DELETE FROM sessions WHERE user_id=?').run(id);
});
route('PUT', '/api/admin/settings', (req) => {
  need(req, 'admin'); const b = req.body;
  const v = { requestTtlMin: Math.round(Number(b.requestTtlMin)), payTtlMin: Math.round(Number(b.payTtlMin)), stripePct: Number(b.stripePct), stripeFixed: Math.round(Number(b.stripeFixed)) };
  if (!(v.requestTtlMin >= 5 && v.requestTtlMin <= 1440)) fail(400, "L'expiration des demandes doit être comprise entre 5 et 1440 minutes.");
  if (!(v.payTtlMin >= 31 && v.payTtlMin <= 1440)) fail(400, "Le lien de paiement doit rester valable entre 31 et 1440 minutes (minimum imposé par Stripe).");
  if (!(v.stripePct >= 0 && v.stripePct <= 0.1) || !(v.stripeFixed >= 0 && v.stripeFixed <= 500)) fail(400, 'Frais Stripe invalides.');
  for (const [k, val] of Object.entries(v)) q('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, JSON.stringify(val));
});
route('GET', '/api/admin/stripe', async (req) => {
  need(req, 'admin');
  const [bal, payouts] = await Promise.all([stripe('GET', '/balance'), stripe('GET', '/payouts', { limit: 12 })]);
  const pick = (arr) => (arr || []).filter((x) => x.currency === 'eur').reduce((a, x) => a + x.amount, 0);
  return { available: pick(bal.available), pending: pick(bal.pending),
    payouts: (payouts.data || []).map((p) => ({ id: p.id, amount: p.amount, currency: p.currency, status: p.status, arrival: p.arrival_date * 1000, created: p.created * 1000 })) };
});
route('POST', '/api/admin/payout', async (req) => {
  need(req, 'admin');
  const bal = await stripe('GET', '/balance');
  const available = (bal.available || []).filter((x) => x.currency === 'eur').reduce((a, x) => a + x.amount, 0);
  if (available < 100) fail(409, 'Solde disponible insuffisant (1 € minimum).');
  const p = await stripe('POST', '/payouts', { amount: available, currency: 'eur', description: 'Commissions LateCheck' }, { idem: `po_${todayParis()}_${available}` });
  return { amount: p.amount, arrival: p.arrival_date * 1000 };
});
route('GET', '/api/admin/export.csv', (req, res) => {
  need(req, 'admin');
  const c = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const n = (x) => ((x || 0) / 100).toFixed(2).replace('.', ',');
  const rows = [['Date', 'Propriétaire', 'E-mail propriétaire', 'Logement', 'Voyageur', 'Durée (h)', 'Montant payé (€)', 'Commission LateCheck (€)', 'Frais facturés à l\'hôte (€)', 'Frais Stripe réels (€)', 'Reversé au propriétaire (€)', 'Statut', 'PaymentIntent']];
  for (const p of q(`SELECT p.*, u.name hn, u.email he, l.name ln, r.guest_name gn, r.hours h FROM payments p
      JOIN users u ON u.id=p.host_id JOIN listings l ON l.id=p.listing_id JOIN requests r ON r.id=p.request_id ORDER BY p.created_at`).all()) {
    const ok = p.status === 'succeeded';
    rows.push([new Date(p.created_at).toLocaleString('fr-FR', { timeZone: 'Europe/Paris' }), p.hn, p.he, p.ln, p.gn, p.h, n(p.amount), ok ? n(p.commission) : '0,00', ok ? n(p.stripe_fee) : '0,00', p.stripe_fee_actual == null ? '' : n(p.stripe_fee_actual), ok ? n(p.net) : '0,00', { succeeded: 'Réussi', failed: 'Échoué', refunded: 'Remboursé' }[p.status], p.stripe_payment_intent]);
  }
  res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="latecheck-transactions-${todayParis()}.csv"` });
  res.end('\uFEFF' + rows.map((r) => r.map(c).join(';')).join('\r\n'));
});

/* Webhooks Stripe */
route('POST', '/api/stripe/webhook', async (req, res) => {
  if (!verifyStripeSignature(req.raw, req.headers['stripe-signature'])) { console.warn('Webhook Stripe REFUSÉ : signature invalide → vérifiez STRIPE_WEBHOOK_SECRET sur Render (whsec_… de cet endpoint)'); res.writeHead(400); res.end('Signature invalide'); return; }
  const ev = JSON.parse(req.raw.toString('utf8'));
  console.log('Webhook Stripe reçu :', ev.type);
  if (q('SELECT 1 FROM stripe_events WHERE id=?').get(ev.id)) return { received: true, duplicate: true };
  await handleStripeEvent(ev); // en cas d'erreur : 500, Stripe renverra l'événement
  q('INSERT OR IGNORE INTO stripe_events(id,type,received_at) VALUES(?,?,?)').run(ev.id, ev.type, now());
  return { received: true };
}, { raw: true });

/* ------------------------------------------------------------------ Serveur HTTP */
const PUBLIC = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8' };
function serveStatic(pathname, res) {
  let f = path.normalize(path.join(PUBLIC, pathname === '/' ? 'index.html' : decodeURIComponent(pathname)));
  if (!f.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
  if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(PUBLIC, 'index.html');
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY' });
  fs.createReadStream(f).pipe(res);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(Object.assign(new Error('Requête trop volumineuse.'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks))); req.on('error', reject);
  });
}
function sendJson(res, status, data) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (!url.pathname.startsWith('/api/')) return serveStatic(url.pathname, res);
    const rt = routes.find((r) => r.method === req.method && r.re.test(url.pathname));
    if (!rt) return sendJson(res, 404, { error: 'Introuvable.' });
    // Protection CSRF : toute écriture depuis le navigateur porte l'en-tête X-LC
    if (req.method !== 'GET' && !rt.opts.raw && req.headers['x-lc'] !== '1') return sendJson(res, 403, { error: 'Requête refusée.' });
    const raw = await readBody(req, rt.opts.raw ? 1e6 : 4e6);
    req.raw = raw; req.query = Object.fromEntries(url.searchParams); req.body = {};
    if (!rt.opts.raw && raw.length) { try { req.body = JSON.parse(raw.toString('utf8')) || {}; } catch { return sendJson(res, 400, { error: 'Requête invalide.' }); } }
    const params = url.pathname.match(rt.re).slice(1).map(decodeURIComponent);
    const out = await rt.fn(req, res, ...params);
    if (!res.headersSent) sendJson(res, 200, out || { ok: true });
  } catch (e) {
    if (res.headersSent) return;
    if (e.status) return sendJson(res, e.status, { error: e.message, code: e.code });
    if (e.stripe) return sendJson(res, 502, { error: 'Stripe : ' + e.message });
    console.error(e);
    sendJson(res, 500, { error: 'Erreur serveur. Réessayez dans un instant.' });
  }
});
server.listen(PORT, () => console.log(`✅ LateCheck sur ${APP_URL} (Stripe ${STRIPE_MODE})`));
module.exports = server;
