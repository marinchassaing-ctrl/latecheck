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
const outUser = (u) => ({ id: u.id, role: u.role, name: u.name, email: u.email, status: u.status, stripeAccount: u.stripe_account, payoutsReady: !!u.payouts_ready, detailsSubmitted: !!u.details_submitted, createdAt: u.created_at });
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
  for (const r of q("SELECT * FROM requests WHERE status='pending' AND expires_at < ?").all(t)) {
    if (q("UPDATE requests SET status='expired', expired_reason='host' WHERE id=? AND status='pending'").run(r.id).changes)
      sendEmail(r.guest_email, 'Votre demande de départ tardif a expiré', `Bonjour ${r.guest_name},\n\nVotre hôte n'a pas répondu à temps. Aucun paiement n'a été effectué. Merci de libérer le logement à ${r.old_time}.`);
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

/* ------------------------------------------------------------------ Paiements confirmés par webhook */
function markRefunded(paymentId) {
  const p = q('SELECT * FROM payments WHERE id=?').get(paymentId);
  if (!p || !q("UPDATE payments SET status='refunded', refunded_at=? WHERE id=? AND status='succeeded'").run(now(), p.id).changes) return false;
  const r = q('SELECT * FROM requests WHERE id=?').get(p.request_id);
  q("UPDATE requests SET status='refunded' WHERE id=?").run(p.request_id);
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
      return onCheckoutCompleted(o);
    case 'checkout.session.expired': {
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
    stripeMode: STRIPE_MODE, users: [], listings: [], requests: [], payments: [], emails: [], settings: getSettings(), guest: null };
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
      out.requests = q('SELECT * FROM requests WHERE host_id=? ORDER BY created_at DESC').all(u.id).map((r) => outRequest(r));
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
  if (q('SELECT 1 FROM users WHERE email=?').get(email)) fail(409, 'Un compte existe déjà avec cet e-mail.');
  const id = newId('usr_');
  q("INSERT INTO users(id,role,name,email,pw,created_at) VALUES(?,'host',?,?,?,?)").run(id, name, email, hashPw(pw), now());
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
    q('UPDATE users SET stripe_account=? WHERE id=?').run(a.id, u.id);
    u = q('SELECT * FROM users WHERE id=?').get(u.id);
  }
  const link = await stripeV2('POST', '/v2/core/account_links', {
    account: u.stripe_account,
    use_case: { type: 'account_onboarding', account_onboarding: {
      configurations: ['recipient'],
      refresh_url: `${APP_URL}/#/h/account?stripe=refresh`,
      return_url: `${APP_URL}/#/h/account?stripe=return`,
    } },
  });
  return { url: link.url };
});
route('POST', '/api/stripe/refresh', async (req) => { const u = need(req, 'host'); const x = await syncAccount(u); return { payoutsReady: !!x.payouts_ready }; });
route('POST', '/api/stripe/dashboard', async (req) => {
  const u = need(req, 'host'); if (!u.stripe_account) fail(400, "Connectez d'abord votre compte Stripe.");
  const l = await stripe('POST', `/accounts/${u.stripe_account}/login_links`);
  return { url: l.url };
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
  for (const r of q("SELECT * FROM requests WHERE listing_id=? AND status IN ('pending','accepted')").all(id)) {
    q("UPDATE requests SET status='cancelled', pay_token=NULL WHERE id=?").run(r.id);
    if (r.checkout_session) stripe('POST', `/checkout/sessions/${r.checkout_session}/expire`).catch(() => {});
    sendEmail(r.guest_email, 'Demande annulée', `Bonjour ${r.guest_name},\n\nCe logement n'accepte plus de demandes de départ tardif. Aucun paiement n'a été effectué.`);
  }
});

/* Demandes : décisions de l'hôte */
route('POST', '/api/requests/:id/accept', async (req, _res, id) => {
  let u = need(req, 'host');
  const r = q('SELECT * FROM requests WHERE id=? AND host_id=?').get(id, u.id);
  if (!r) fail(404, 'Demande introuvable.');
  sweep();
  if (q('SELECT status FROM requests WHERE id=?').get(id).status !== 'pending') fail(409, 'Cette demande a déjà été traitée ou a expiré.');
  if (!u.payouts_ready && u.stripe_account) u = await syncAccount(u);
  if (!u.payouts_ready) fail(409, 'Terminez la connexion de votre compte Stripe pour accepter des demandes.', 'STRIPE');
  const payToken = newToken(), payExp = now() + getSettings().payTtlMin * 60000;
  if (!q("UPDATE requests SET status='accepted', decided_at=?, pay_token=?, pay_expires_at=? WHERE id=? AND status='pending'").run(now(), payToken, payExp, id).changes)
    fail(409, 'Cette demande a déjà été traitée.');
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  sendEmail(r.guest_email, 'Votre demande de départ tardif est acceptée', `Bonjour ${r.guest_name},\n\nVotre hôte accepte votre départ à ${r.new_time} le ${dayFr(r.date)} à « ${l.name} ».\nRéglez ${eur(r.price)} avant ${timeFr(payExp)} pour le confirmer :\n${APP_URL}/#/pay/${payToken}\n\nVotre départ tardif ne sera confirmé qu'après le paiement.`);
});
route('POST', '/api/requests/:id/refuse', (req, _res, id) => {
  const u = need(req, 'host');
  const r = q('SELECT * FROM requests WHERE id=? AND host_id=?').get(id, u.id);
  if (!r) fail(404, 'Demande introuvable.');
  if (!q("UPDATE requests SET status='refused', decided_at=?, pay_token=NULL WHERE id=? AND status='pending'").run(now(), id).changes) fail(409, 'Cette demande a déjà été traitée.');
  const l = q('SELECT * FROM listings WHERE id=?').get(r.listing_id);
  sendEmail(r.guest_email, 'Votre demande de départ tardif', `Bonjour ${r.guest_name},\n\nVotre hôte ne peut pas accepter votre demande pour « ${l.name} ». Merci de libérer le logement à ${r.old_time}. Aucun paiement n'a été effectué.`);
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
route('POST', '/api/public/requests', (req) => {
  sweep();
  const b = req.body;
  const l = q('SELECT * FROM listings WHERE slug=? AND deleted=0').get(String(b.slug || ''));
  if (!l) fail(404, 'Logement introuvable.');
  const host = q('SELECT * FROM users WHERE id=?').get(l.host_id);
  if (l.paused || host.status !== 'active' || !host.payouts_ready) fail(409, "Ce logement n'accepte pas de demandes pour le moment.");
  const hours = Number(b.hours), name = String(b.name || '').trim().slice(0, 40), email = String(b.email || '').trim().toLowerCase(), date = String(b.date || ''), message = String(b.message || '').trim().slice(0, 300);
  if (![1, 2, 3, 4].includes(hours)) fail(400, 'Durée invalide.');
  if (!name || !isEmail(email)) fail(400, 'Renseignez votre prénom et un e-mail valide.');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || date < todayParis()) fail(400, 'Choisissez une date de départ à venir.');
  const dup = q("SELECT * FROM requests WHERE listing_id=? AND guest_email=? AND date=? AND status IN ('pending','accepted','paid')").get(l.id, email, date);
  if (dup) return { id: dup.id, guestToken: dup.guest_token, duplicate: true };
  const prices = JSON.parse(l.prices), s = getSettings();
  const r = { id: newId('req_'), guestToken: newToken(), price: prices[hours], newTime: addHours(l.checkout, hours), expiresAt: now() + s.requestTtlMin * 60000 };
  q(`INSERT INTO requests(id,listing_id,host_id,guest_name,guest_email,guest_token,date,hours,price,old_time,new_time,message,status,created_at,expires_at)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`)
    .run(r.id, l.id, l.host_id, name, email, r.guestToken, date, hours, r.price, l.checkout, r.newTime, message || null, now(), r.expiresAt);
  sendEmail(host.email, 'Nouvelle demande de départ tardif', `${name} demande ${hoursLabel(hours)} (départ à ${r.newTime}) le ${dayFr(date)} pour « ${l.name} », soit ${eur(r.price)}.\nRépondez avant ${timeFr(r.expiresAt)} : ${APP_URL}/#/h/requests/${r.id}`);
  sendEmail(email, 'Votre demande a bien été envoyée', `Bonjour ${name},\n\nVotre demande de départ à ${r.newTime} a été transmise à votre hôte. Aucun paiement n'a été effectué.\nSuivre la demande : ${APP_URL}/#/r/${r.id}/${r.guestToken}`);
  return { id: r.id, guestToken: r.guestToken };
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
  const h = q("SELECT * FROM users WHERE id=? AND role='host'").get(id); if (!h) fail(404, 'Hôte introuvable.');
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
  if (!verifyStripeSignature(req.raw, req.headers['stripe-signature'])) { res.writeHead(400); res.end('Signature invalide'); return; }
  const ev = JSON.parse(req.raw.toString('utf8'));
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
