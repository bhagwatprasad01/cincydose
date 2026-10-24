/*
 * CincyDose server — cincydose.org
 * Passwordless sign-in: users enter their email address and confirm with a one-time code or link sent to it.
 * New accounts need administrator approval. No passwords are created or stored.
 * Zero npm dependencies: Node.js >= 22.13 (built-in node:sqlite, node:crypto, fetch).
 * Calculations run in each user's browser; analysis data and patient values are never sent to this server.
 */
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const tls = require('node:tls');
const { DatabaseSync } = require('node:sqlite');

/* ---------------------------------------------------------------- sites */
const BRANDS = {
  cincydose: {
    name: 'CincyDose', domain: 'cincydose.org', tagline: 'Model-informed precision dosing', cookie: 'cdose',
    lede: 'CincyDose individualizes doses of narrow-therapeutic-index drugs (vancomycin, aminoglycosides, tacrolimus, busulfan, antiepileptics, digoxin, theophylline) for neonates, children and adults. It combines published population models with measured levels by Bayesian estimation and ranks regimens by the chance of reaching the target.',
    feats: [['Patient values stay on your device', 'Covariates, doses and levels are processed in your browser and never uploaded to this server.'], ['Built for the bedside', 'A drug library with source-checked and textbook models, prediction intervals, and a copy-ready summary for the chart.']],
    roles: ['Pharmacist', 'Physician', 'Nurse practitioner / PA', 'Pharmacy resident or fellow', 'Medical resident or fellow', 'Researcher / faculty', 'Student', 'Other'],
    purposeHint: 'Service or unit, drugs, research project',
    agree: 'I understand CincyDose is clinical decision support: I will confirm every dose with clinical judgment and local protocols, and I will not enter identifiable patient information into account fields.',
    approvedNote: 'CincyDose runs its calculations in your browser; patient values are not uploaded to the server. Always confirm doses with clinical judgment and local protocols.',
    light: '--bg:#f2f5f6;--surface:#fff;--sunk:#e9eff1;--ink:#13212a;--muted:#566873;--line:#d4dde2;--accent:#0d676c;--accent-ink:#fff;--accent-soft:#dbeeee',
    dark: '--bg:#0e1518;--surface:#152025;--sunk:#1b2a30;--ink:#e2ebee;--muted:#93a5ae;--line:#29393f;--accent:#53b8b8;--accent-ink:#04181a;--accent-soft:#163a3c',
    hex: '#0d676c', ink: '#13212a',
    mark: '<svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true"><path d="M2 17 C5 4, 7 4, 9 9 S 14 17, 20 6" fill="none" stroke="var(--accent-ink)" stroke-width="2.2" stroke-linecap="round"/><circle cx="9" cy="9" r="2" fill="var(--accent-ink)"/></svg>',
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="104" fill="#0d676c"/><path d="M70 392 C140 90, 186 90, 232 210 S 330 392, 448 136" fill="none" stroke="#fff" stroke-width="44" stroke-linecap="round"/><circle cx="232" cy="210" r="40" fill="#fff"/></svg>'
  }
};

/* ---------------------------------------------------------------- config */
const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? process.env[k] : d);
const SITE = 'cincydose';
const B = BRANDS[SITE];
const CFG = {
  port: +env('PORT', 8080),
  baseUrl: env('BASE_URL', 'http://localhost:8080').replace(/\/$/, ''),
  dbPath: env('DB_PATH', path.join(__dirname, 'data', 'cincydose.db')),
  appFile: env('APP_FILE', path.join(__dirname, 'app', 'index.html')),
  adminEmails: env('ADMIN_EMAILS', '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
  autoApproveDomains: env('AUTO_APPROVE_DOMAINS', '').split(',').map(s => s.trim().toLowerCase().replace(/^@/, '')).filter(Boolean),
  initialAdminEmail: env('INITIAL_ADMIN_EMAIL', '').toLowerCase(),
  initialAdminName: env('INITIAL_ADMIN_NAME', 'Administrator'),
  trustProxy: env('TRUST_PROXY', '0') === '1',
  email: {
    provider: env('EMAIL_PROVIDER', 'console'), // console | resend | sendgrid | postmark | smtp
    from: env('EMAIL_FROM', `${B.name} <no-reply@${B.domain}>`),
    apiKey: env('EMAIL_API_KEY', ''),
    smtpHost: env('SMTP_HOST', ''), smtpPort: +env('SMTP_PORT', 587), smtpUser: env('SMTP_USER', ''), smtpPass: env('SMTP_PASS', ''), smtpSecure: env('SMTP_SECURE', '0') === '1'
  },
  codeMinutes: +env('CODE_MINUTES', 15),
  sessionIdleMin: +env('SESSION_IDLE_MINUTES', 30),
  sessionMaxHours: +env('SESSION_MAX_HOURS', 12),
  rememberDays: +env('REMEMBER_DAYS', 30),
  orgName: env('ORG_NAME', "Division of Translational and Clinical Pharmacology, Cincinnati Children's Hospital Medical Center"),
  mailLog: env('MAIL_LOG', path.join(__dirname, 'data', 'mail.log'))
};
const SECURE_COOKIE = CFG.baseUrl.startsWith('https://');

/* ---------------------------------------------------------------- database */
fs.mkdirSync(path.dirname(CFG.dbPath), { recursive: true });
fs.mkdirSync(path.dirname(CFG.mailLog), { recursive: true });
const db = new DatabaseSync(CFG.dbPath);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  institution TEXT, title TEXT, purpose TEXT,
  status TEXT NOT NULL,            -- unverified | pending | active | denied | disabled
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, verified_at TEXT, decided_at TEXT, decided_by TEXT, last_login TEXT
);
CREATE TABLE IF NOT EXISTS codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL, link_hash TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL,           -- verify | login
  remember INTEGER NOT NULL DEFAULT 0, next TEXT,
  expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
  hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL, remember INTEGER NOT NULL DEFAULT 0, ip TEXT, agent TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, target TEXT, detail TEXT, ip TEXT
);
`);
const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (email,name,institution,title,purpose,status,is_admin,created_at) VALUES (?,?,?,?,?,?,?,?)'),
  adminCount: db.prepare("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND status = 'active'"),
  admins: db.prepare("SELECT email,name FROM users WHERE is_admin = 1 AND status = 'active'"),
  allUsers: db.prepare("SELECT id,email,name,institution,title,purpose,status,is_admin,created_at,verified_at,decided_at,decided_by,last_login FROM users ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'unverified' THEN 1 WHEN 'active' THEN 2 ELSE 3 END, created_at DESC"),
  codeInsert: db.prepare('INSERT INTO codes (user_id,code_hash,link_hash,purpose,remember,next,expires) VALUES (?,?,?,?,?,?,?)'),
  codeClear: db.prepare('DELETE FROM codes WHERE user_id = ?'),
  codeLatest: db.prepare('SELECT * FROM codes WHERE user_id = ? AND used = 0 ORDER BY id DESC LIMIT 1'),
  codeByLink: db.prepare('SELECT * FROM codes WHERE link_hash = ?'),
  codeAttempt: db.prepare('UPDATE codes SET attempts = attempts + 1 WHERE id = ?'),
  codeUse: db.prepare('UPDATE codes SET used = 1 WHERE id = ?'),
  insertToken: db.prepare('INSERT INTO tokens (hash,user_id,kind,expires) VALUES (?,?,?,?)'),
  tokenGet: db.prepare('SELECT * FROM tokens WHERE hash = ? AND kind = ?'),
  tokenUse: db.prepare('UPDATE tokens SET used = 1 WHERE hash = ?'),
  tokensClear: db.prepare('DELETE FROM tokens WHERE user_id = ? AND kind = ?'),
  sessInsert: db.prepare('INSERT INTO sessions (hash,user_id,created,last_seen,remember,ip,agent) VALUES (?,?,?,?,?,?,?)'),
  sessGet: db.prepare('SELECT * FROM sessions WHERE hash = ?'),
  sessTouch: db.prepare('UPDATE sessions SET last_seen = ? WHERE hash = ?'),
  sessDel: db.prepare('DELETE FROM sessions WHERE hash = ?'),
  sessDelUser: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  audit: db.prepare('INSERT INTO audit (ts,actor,action,target,detail,ip) VALUES (?,?,?,?,?,?)'),
  auditList: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 300')
};
const nowIso = () => new Date().toISOString();
const log = (actor, action, target, detail, ip) => q.audit.run(nowIso(), actor || null, action, target || null, detail || null, ip || null);

/* ---------------------------------------------------------------- crypto helpers */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');
const newCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
const codeHash = (userId, code) => sha(`${SITE}:${userId}:${code}`);
function issueToken(userId, kind, hours) { const t = token(); q.tokensClear.run(userId, kind); q.insertToken.run(sha(t), userId, kind, Date.now() + hours * 3600e3); return t; }
function readToken(t, kind) { if (!t || typeof t !== 'string') return null; const r = q.tokenGet.get(sha(t), kind); if (!r || r.used || r.expires < Date.now()) return null; return r; }

/* ---------------------------------------------------------------- email */
function smtpSend({ to, subject, text, html }) {
  return new Promise((resolve, reject) => {
    const E = CFG.email, fromAddr = (E.from.match(/<([^>]+)>/) || [, E.from])[1];
    const boundary = 'b' + crypto.randomBytes(8).toString('hex');
    const msg = [`From: ${E.from}`, `To: ${to.join(', ')}`, `Subject: =?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`, `Date: ${new Date().toUTCString()}`, `Message-ID: <${crypto.randomBytes(12).toString('hex')}@${fromAddr.split('@')[1] || B.domain}>`, 'MIME-Version: 1.0', `Content-Type: multipart/alternative; boundary="${boundary}"`, '', `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', Buffer.from(text).toString('base64').replace(/.{76}/g, '$&\r\n'), `--${boundary}`, 'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '', Buffer.from(html).toString('base64').replace(/.{76}/g, '$&\r\n'), `--${boundary}--`, ''].join('\r\n');
    let sock = E.smtpSecure ? tls.connect(E.smtpPort, E.smtpHost, { servername: E.smtpHost }) : net.connect(E.smtpPort, E.smtpHost);
    let buf = '', step = 0, upgraded = E.smtpSecure;
    const send = l => sock.write(l + '\r\n');
    let phase = 'greet';
    const onLine = line => {
      const code = line.slice(0, 3), more = line[3] === '-';
      if (more) return;
      if (/^[45]/.test(code)) { sock.destroy(); return reject(new Error('SMTP ' + line)); }
      if (phase === 'greet') { phase = 'ehlo'; return send('EHLO ' + B.domain); }
      if (phase === 'ehlo') {
        if (!upgraded) { phase = 'starttls'; return send('STARTTLS'); }
        phase = 'auth';
        if (E.smtpUser) return send('AUTH LOGIN');
        phase = 'mail'; return send(`MAIL FROM:<${fromAddr}>`);
      }
      if (phase === 'starttls') {
        sock.removeAllListeners('data');
        sock = tls.connect({ socket: sock, servername: E.smtpHost }, () => { upgraded = true; phase = 'ehlo'; send('EHLO ' + B.domain); });
        sock.on('data', onData); sock.on('error', reject); return;
      }
      if (phase === 'auth') { phase = 'user'; return send(Buffer.from(E.smtpUser).toString('base64')); }
      if (phase === 'user') { phase = 'pass'; return send(Buffer.from(E.smtpPass).toString('base64')); }
      if (phase === 'pass') { phase = 'mail'; return send(`MAIL FROM:<${fromAddr}>`); }
      if (phase === 'mail') { phase = 'rcpt'; rcpt = 0; return send(`RCPT TO:<${to[rcpt++]}>`); }
      if (phase === 'rcpt') { if (rcpt < to.length) return send(`RCPT TO:<${to[rcpt++]}>`); phase = 'data'; return send('DATA'); }
      if (phase === 'data') { phase = 'sent'; return send(msg.replace(/^\./gm, '..') + '\r\n.'); }
      if (phase === 'sent') { phase = 'quit'; send('QUIT'); return resolve(); }
    };
    let rcpt = 0;
    const onData = d => { buf += d.toString(); let i; while ((i = buf.indexOf('\r\n')) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 2); onLine(line); } };
    sock.on('data', onData); sock.on('error', reject);
    sock.setTimeout(20000, () => { sock.destroy(); reject(new Error('SMTP timeout')); });
  });
}
async function sendMail(to, subject, text, html) {
  to = (Array.isArray(to) ? to : [to]).filter(Boolean);
  if (!to.length) return;
  html = html || `<pre style="font:14px/1.5 system-ui,sans-serif;white-space:pre-wrap">${esc(text)}</pre>`;
  const E = CFG.email;
  try {
    if (E.provider === 'resend') {
      const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${E.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: E.from, to, subject, text, html }) });
      if (!r.ok) throw new Error('Resend ' + r.status + ' ' + await r.text());
    } else if (E.provider === 'sendgrid') {
      const m = E.from.match(/^(.*)<([^>]+)>$/); const from = m ? { name: m[1].trim(), email: m[2] } : { email: E.from };
      const r = await fetch('https://api.sendgrid.com/v3/mail/send', { method: 'POST', headers: { Authorization: `Bearer ${E.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ personalizations: [{ to: to.map(e => ({ email: e })) }], from, subject, content: [{ type: 'text/plain', value: text }, { type: 'text/html', value: html }] }) });
      if (!r.ok) throw new Error('SendGrid ' + r.status + ' ' + await r.text());
    } else if (E.provider === 'postmark') {
      const r = await fetch('https://api.postmarkapp.com/email', { method: 'POST', headers: { 'X-Postmark-Server-Token': E.apiKey, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ From: E.from, To: to.join(','), Subject: subject, TextBody: text, HtmlBody: html, MessageStream: 'outbound' }) });
      if (!r.ok) throw new Error('Postmark ' + r.status + ' ' + await r.text());
    } else if (E.provider === 'smtp') {
      await smtpSend({ to, subject, text, html });
    } else {
      fs.appendFileSync(CFG.mailLog, `\n===== ${nowIso()}\nTo: ${to.join(', ')}\nSubject: ${subject}\n\n${text}\n`);
      console.log(`[mail:console] to=${to.join(',')} subject="${subject}"`);
    }
  } catch (e) { console.error('[mail] failed:', e.message); log('system', 'email_failed', to.join(','), String(e.message).slice(0, 300)); }
}
function adminRecipients() { const set = new Set(CFG.adminEmails); q.admins.all().forEach(a => set.add(a.email)); return [...set]; }


/* ---------------------------------------------------------------- http helpers */
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' blob:; worker-src 'self' blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'";
function secHeaders(res) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (SECURE_COOKIE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function send(res, code, body, type = 'text/html; charset=utf-8', extra = {}) { secHeaders(res); res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extra }); res.end(body); }
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);
const redirect = (res, to) => { secHeaders(res); res.writeHead(303, { Location: to, 'Cache-Control': 'no-store' }); res.end(); };
function clientIp(req) { if (CFG.trustProxy && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim(); return req.socket.remoteAddress; }
function parseCookies(req) { const out = {}; String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); }); return out; }
const COOKIE = SECURE_COOKIE ? '__Host-' + B.cookie : B.cookie;
const setCookie = (v, maxAge) => `${COOKIE}=${v}; Path=/; HttpOnly; SameSite=Lax${SECURE_COOKIE ? '; Secure' : ''}${v ? (maxAge ? `; Max-Age=${maxAge}` : '') : '; Max-Age=0'}`;
function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { const s = Buffer.concat(chunks).toString('utf8'); resolve(s ? JSON.parse(s) : {}); } catch (e) { reject(Object.assign(new Error('bad json'), { status: 400 })); } });
    req.on('error', reject);
  });
}
function sameOrigin(req) {
  const o = req.headers.origin || req.headers.referer || '';
  if (!o) return false;
  try { const u = new URL(o); return u.host === req.headers.host; } catch (e) { return false; }
}
// simple in-memory rate limiter
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(); let b = buckets.get(key);
  if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.n++; return b.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k); }, 60000).unref();


/* ---------------------------------------------------------------- sessions */
function currentUser(req) {
  const c = parseCookies(req)[COOKIE]; if (!c) return null;
  const s = q.sessGet.get(sha(c)); if (!s) return null;
  const now = Date.now();
  const idle = s.remember ? CFG.rememberDays * 864e5 : CFG.sessionIdleMin * 60e3;
  const max = s.remember ? CFG.rememberDays * 864e5 : CFG.sessionMaxHours * 3600e3;
  if (now - s.last_seen > idle || now - s.created > max) { q.sessDel.run(s.hash); return null; }
  const u = q.userById.get(s.user_id); if (!u || u.status !== 'active') { q.sessDel.run(s.hash); return null; }
  if (now - s.last_seen > 30e3) q.sessTouch.run(now, s.hash);
  return { ...u, _sess: s.hash, _remember: !!s.remember };
}
function startSession(req, u, remember) {
  const t = token(), now = Date.now();
  q.sessInsert.run(sha(t), u.id, now, now, remember ? 1 : 0, clientIp(req), String(req.headers['user-agent'] || '').slice(0, 200));
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(nowIso(), u.id);
  return setCookie(t, remember ? CFG.rememberDays * 86400 : 0);
}
const safeNext = n => { n = String(n || '/app'); return /^\/[A-Za-z0-9/_-]*$/.test(n) && !n.startsWith('//') ? n : '/app'; };

/* ---------------------------------------------------------------- one-time codes */
async function sendCode(u, purpose, remember, next, ip) {
  q.codeClear.run(u.id);
  const code = newCode(), link = token();
  q.codeInsert.run(u.id, codeHash(u.id, code), sha(link), purpose, remember ? 1 : 0, safeNext(next), Date.now() + CFG.codeMinutes * 60e3);
  const url = `${CFG.baseUrl}/c?t=${encodeURIComponent(link)}`;
  const verify = purpose === 'verify';
  const subject = verify ? `${code} is your ${B.name} confirmation code` : `${code} is your ${B.name} sign-in code`;
  const lead = verify ? `Confirm your email address for ${B.name}.` : `Sign in to ${B.name}.`;
  const text = `Hello ${u.name},\n\n${lead}\n\nYour code: ${code}\n\nOr open this link: ${url}\n\nThe code and link work once and expire in ${CFG.codeMinutes} minutes.${verify ? '\nAfter you confirm, an administrator reviews your request.' : ''}\n\nIf you did not ask for this, ignore this email.`;
  const html = `<div style="font:15px/1.55 system-ui,sans-serif;color:${B.ink};max-width:520px">
    <p style="margin:0 0 6px;font-weight:700;font-size:17px">${esc(B.name)}</p><p>Hello ${esc(u.name)},</p><p>${esc(lead)} Your code:</p>
    <p style="font:700 32px/1.2 ui-monospace,Menlo,Consolas,monospace;letter-spacing:6px;margin:14px 0">${code}</p>
    <p style="margin:18px 0"><a href="${esc(url)}" style="background:${B.hex};color:#fff;text-decoration:none;padding:11px 20px;border-radius:8px;font-weight:600;display:inline-block">${verify ? 'Confirm my email' : 'Sign me in'}</a></p>
    <p style="color:#5a6178;font-size:13px">The code and button work once and expire in ${CFG.codeMinutes} minutes.${verify ? ' After you confirm, an administrator reviews your request.' : ''} If you did not ask for this, ignore this email.</p></div>`;
  await sendMail(u.email, subject, text, html);
  log(u.email, verify ? 'code_sent_verify' : 'code_sent_login', u.email, '', ip);
}
function checkCode(u, code) {
  const r = q.codeLatest.get(u.id);
  if (!r || r.expires < Date.now()) return { error: 'This code has expired. Send a new one.' };
  if (r.attempts >= 5) return { error: 'Too many incorrect codes. Send a new one.' };
  const given = codeHash(u.id, String(code || '').replace(/\D/g, ''));
  if (!crypto.timingSafeEqual(Buffer.from(given), Buffer.from(r.code_hash))) { q.codeAttempt.run(r.id); return { error: 'That code is not correct. Check the latest email and try again.' }; }
  q.codeUse.run(r.id);
  return { row: r };
}
async function completeCode(req, u, row, ip) {
  if (row.purpose === 'verify' && u.status === 'unverified') {
    const domain = u.email.split('@')[1], auto = CFG.autoApproveDomains.includes(domain);
    db.prepare('UPDATE users SET status = ?, verified_at = ?, decided_at = ?, decided_by = ? WHERE id = ?').run(auto ? 'active' : 'pending', nowIso(), auto ? nowIso() : null, auto ? 'auto (' + domain + ')' : null, u.id);
    log(u.email, 'email_verified', u.email, auto ? 'auto-approved by domain' : 'awaiting approval', ip);
    u = q.userById.get(u.id);
    if (!auto) { notifyAdminsOfRequest(u); return { status: 'pending' }; }
    sendMail(adminRecipients(), `${B.name}: new account (auto-approved) — ${u.name}`, `${u.name} <${u.email}> (${u.institution}, ${u.title}) created a ${B.name} account. It was approved automatically because ${domain} is an auto-approved domain.\n\nManage accounts: ${CFG.baseUrl}/admin`);
  }
  if (u.status !== 'active') return { status: u.status, error: STATUS_TEXT[u.status] };
  log(u.email, 'login', u.email, row.remember ? 'remember device' : '', ip);
  return { status: 'signed_in', cookie: startSession(req, u, !!row.remember), next: safeNext(row.next) };
}
const STATUS_TEXT = {
  unverified: 'Please confirm your email address first.',
  pending: 'Your account is waiting for administrator approval. You will get an email when it is approved.',
  denied: 'Your account request was not approved. Contact the administrators if you think this is a mistake.',
  disabled: 'This account has been disabled. Contact the administrators.'
};

/* ---------------------------------------------------------------- page shell */
const FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Public+Sans:wght@400;500;600;700&display=swap">';
const CSS_BASE = `:root{${B.light};--good:#1d7a3e;--good-soft:#e0f1e5;--warn:#9a5b00;--warn-soft:#fbefd8;--bad:#b3261b;--bad-soft:#fce4e1;--f-ui:'Public Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;--f-num:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{${B.dark};--good:#62c788;--good-soft:#14301f;--warn:#e4ad52;--warn-soft:#33280f;--bad:#f27d70;--bad-soft:#3a1c19;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--f-ui)}
.wrap{min-height:100vh;display:grid;place-items:center;padding:28px max(16px,env(safe-area-inset-left))}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:28px;width:100%;max-width:440px;display:grid;gap:14px;box-shadow:0 10px 40px rgba(20,24,50,.06)}
.card.wide{max-width:1100px}.card.mid{max-width:620px}
.brand{display:flex;align-items:center;gap:12px;text-decoration:none;color:inherit}.mark{width:38px;height:38px;border-radius:9px;background:var(--accent);display:grid;place-items:center;flex:none}
.brand h1{margin:0;font-size:20px}.brand p{margin:0;color:var(--muted);font-size:12.5px}
h2{margin:4px 0 0;font-size:19px}h3{margin:10px 0 4px;font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
p{margin:0}.hint{color:var(--muted);font-size:13px}
label{display:flex;flex-direction:column;gap:5px;font-size:12.5px;font-weight:500;color:var(--muted)}
input,select,textarea{font:inherit;font-size:14.5px;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:8px 10px;width:100%}
textarea{min-height:76px}
input:focus-visible,select:focus-visible,textarea:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.check{flex-direction:row;align-items:flex-start;gap:9px;font-weight:400;color:var(--ink);font-size:13.5px}.check input{width:auto;margin-top:3px}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.btn{font:600 14px var(--f-ui);border-radius:8px;padding:9px 16px;border:1px solid var(--line);background:var(--surface);color:var(--ink);cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}.btn.small{padding:4px 10px;font-size:12.5px}.btn.danger{color:var(--bad)}
.btn:disabled{opacity:.55;cursor:default}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
a{color:var(--accent)}
.msg{font-size:13.5px;min-height:1.2em;margin:0}.msg.bad{color:var(--bad)}.msg.good{color:var(--good)}
.note{border-radius:9px;padding:12px 14px;font-size:14px}.note.good{background:var(--good-soft)}.note.warn{background:var(--warn-soft)}.note.info{background:var(--accent-soft)}.note.bad{background:var(--bad-soft)}
table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{padding:8px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{font-size:11.5px;color:var(--muted);font-weight:600;letter-spacing:.03em}
.tbl{overflow-x:auto}
.pill{display:inline-flex;font:600 11.5px var(--f-ui);border-radius:999px;padding:2px 9px;white-space:nowrap}.pill.pending{background:var(--warn-soft);color:var(--warn)}.pill.active{background:var(--good-soft);color:var(--good)}.pill.denied,.pill.disabled{background:var(--bad-soft);color:var(--bad)}.pill.unverified{background:var(--sunk);color:var(--muted)}
.tabs{display:flex;gap:6px;flex-wrap:wrap}.tabs button{font:600 13px var(--f-ui);border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:999px;padding:5px 12px;cursor:pointer}.tabs button.on{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.mono{font-family:var(--f-num);font-size:12.5px;white-space:nowrap}
.hero{max-width:760px}.hero .lede{font-size:17px;color:var(--ink)}.feats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:6px}.feats div{background:var(--sunk);border-radius:9px;padding:12px 14px;font-size:14px}.feats b{display:block;margin-bottom:2px}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
@media (max-width:620px){.grid2,.feats{grid-template-columns:minmax(0,1fr)}.card{padding:20px}}`;
const CSS = CSS_BASE + `
[hidden]{display:none!important}
.code{font:600 26px/1.2 var(--f-num);letter-spacing:8px;text-align:center;padding:10px}
.link{background:none;border:0;padding:0;color:var(--accent);font:600 13px var(--f-ui);cursor:pointer;text-decoration:underline;text-underline-offset:2px}
.steps{display:flex;gap:8px;flex-wrap:wrap;font-size:12.5px;color:var(--muted)}.steps span{background:var(--sunk);border-radius:999px;padding:3px 10px}.steps span.on{background:var(--accent-soft);color:var(--accent);font-weight:600}`;
const BRAND = `<a class="brand" href="/"><div class="mark">${B.mark}</div><div><h1>${B.name}</h1><p>${esc(B.tagline)}</p></div></a>`;
const API_JS = `async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(b||{})});let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(j.error||('Request failed ('+r.status+')'));return j}
function formData(f){const o={};new FormData(f).forEach((v,k)=>o[k]=v);f.querySelectorAll('input[type=checkbox]').forEach(c=>o[c.name]=c.checked);return o}
function bind(id,path,done){const f=document.getElementById(id),m=f.querySelector('.msg'),b=f.querySelector('button[type=submit]');f.addEventListener('submit',async e=>{e.preventDefault();m.className='msg';m.textContent='';b.disabled=true;try{const j=await api(path,formData(f));await done(j,f,m)}catch(err){m.className='msg bad';m.textContent=err.message}finally{b.disabled=false}})}
function el(id){return document.getElementById(id)}
function finish(j){if(j.status==='signed_in'){location.href=j.next||'/app';return}const c=el('codeForm');c.innerHTML=document.querySelector('.brand').outerHTML+'<h2>Email confirmed</h2><div class="note good">Thank you. Your request has gone to the administrators. You will get an email as soon as your account is approved; then sign in here with just your email.</div><a class="btn" href="/">Back to home</a>'}
function codeStep(st){el('codeEmail').textContent=st.email;el('codeForm').hidden=false;st.from.hidden=true;const ci=el('codeForm').querySelector('[name=code]');ci.value='';ci.focus();
 el('resend').onclick=async()=>{const m=el('codeForm').querySelector('.msg');try{await api('/api/login/start',{email:st.email,remember:st.remember,next:st.next});m.className='msg good';m.textContent='A new code is on its way.'}catch(err){m.className='msg bad';m.textContent=err.message}};
 el('back').onclick=()=>{el('codeForm').hidden=true;st.from.hidden=false};window.__st=st}`;
const CODE_FORM = `<form class="card" id="codeForm" hidden>${BRAND}<h2>Check your email</h2>
  <p>We sent a 6-digit code to <b id="codeEmail"></b>. Enter it below, or click the button in the email.</p>
  <label>Code<input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required placeholder="••••••"></label>
  <p class="msg" role="alert"></p><button class="btn primary" type="submit">Continue</button>
  <div class="row hint"><button class="link" type="button" id="resend">Send a new code</button><span>·</span><button class="link" type="button" id="back">Use a different email</button></div>
  <p class="hint">The code expires in ${CFG.codeMinutes} minutes. Not in your inbox? Check spam or junk.</p></form>`;
const CODE_JS = `;(()=>{const g=el('codeForm');g.addEventListener('submit',async e=>{e.preventDefault();const mm=g.querySelector('.msg'),bb=g.querySelector('button[type=submit]');mm.className='msg';mm.textContent='';bb.disabled=true;try{const st=window.__st;const j=await api('/api/login/verify',{email:st.email,code:g.querySelector('[name=code]').value,remember:st.remember,next:st.next});finish(j)}catch(err){mm.className='msg bad';mm.textContent=err.message}finally{bb.disabled=false}})})();`;
function page(title, body, opts = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · ${B.name}</title><link rel="icon" href="/icon.svg" type="image/svg+xml">${FONTS}<style>${CSS}</style></head>
<body><div class="wrap"><div>${body}<footer>${esc(CFG.orgName)}</footer></div></div>${opts.script ? `<script>${API_JS}\n${opts.script}</script>` : ''}</body></html>`;
}

/* ---------------------------------------------------------------- pages */
const P = {
  home: u => page(B.tagline, `<div class="card hero">${BRAND}
    <p class="lede">${esc(B.lede)}</p>
    <div class="feats">${B.feats.map(([h, t]) => `<div><b>${esc(h)}</b>${esc(t)}</div>`).join('')}</div>
    <div class="row">${u ? `<a class="btn primary" href="/app">Open ${B.name}</a><a class="btn" href="/account">Account</a>` : `<a class="btn primary" href="/login">Sign in</a><a class="btn" href="/register">Create an account</a>`}</div>
    <p class="hint">Sign in with your email address; no password needed. New accounts are reviewed by the ${B.name} administrators before first use.</p></div>`),
  login: (next, msg) => page('Sign in', `<form class="card" id="f">${BRAND}<h2>Sign in</h2>
    ${msg ? `<div class="note info">${esc(msg)}</div>` : ''}
    <label>Email<input name="email" type="email" autocomplete="email" required autofocus></label><input type="hidden" name="next" value="${esc(safeNext(next))}">
    <label class="check"><input type="checkbox" name="remember"> Keep me signed in on this device for ${CFG.rememberDays} days (not on shared computers)</label>
    <p class="msg" role="alert"></p>
    <button class="btn primary" type="submit">Email me a sign-in code</button>
    <p class="hint">No password needed: we email you a one-time code. New here? <a href="/register">Create an account</a></p></form>${CODE_FORM}`,
    { script: `const next=${JSON.stringify(safeNext(next))};
bind('f','/api/login/start',(j,f,m)=>{if(j.noAccount){m.className='msg bad';m.innerHTML='No account uses this email. <a href="/register">Create an account</a>.';return}if(j.status&&j.status!=='code'){m.className='msg bad';m.textContent=j.message;return}const o=formData(f);codeStep({email:o.email.trim().toLowerCase(),remember:o.remember,next,from:f})});
${CODE_JS}` }),
  register: () => page('Create an account', `<form class="card mid" id="f">${BRAND}<h2>Create an account</h2>
    <div class="steps"><span class="on">1 Your details</span><span>2 Confirm your email</span><span>3 Administrator approval</span></div>
    <div class="grid2"><label>Full name<input name="name" required maxlength="120" autocomplete="name"></label><label>Email<input name="email" type="email" required maxlength="200" autocomplete="email"></label>
    <label>Institution / department<input name="institution" required maxlength="200" autocomplete="organization"></label><label>Role<select name="title">${B.roles.map(r => `<option>${esc(r)}</option>`).join('')}</select></label></div>
    <label>How will you use ${B.name}?<textarea name="purpose" maxlength="1000" placeholder="${esc(B.purposeHint)}"></textarea></label>
    <label class="check"><input type="checkbox" name="agree" required> ${esc(B.agree)}</label>
    <p class="msg" role="alert"></p>
    <button class="btn primary" type="submit">Create account</button>
    <p class="hint">No password needed. Already have an account? <a href="/login">Sign in</a></p></form>${CODE_FORM}`,
    { script: `bind('f','/api/register',(j,f,m)=>{if(j.status==='code'){codeStep({email:j.email,remember:false,next:'/app',from:f});return}m.className='msg '+(j.status==='active'?'good':'bad');m.innerHTML=j.message})
${CODE_JS}` }),
  linkConfirm: t => page('Continue', `<form class="card" id="f">${BRAND}<h2>Continue to ${B.name}</h2><p>Click continue to finish signing in on this device.</p><input type="hidden" name="t" value="${esc(t)}"><p class="msg" role="alert"></p><button class="btn primary" type="submit">Continue</button></form>`,
    { script: `bind('f','/api/link',j=>{if(j.status==='signed_in'){location.href=j.next||'/app';return}const f=el('f');f.innerHTML=document.querySelector('.brand').outerHTML+'<h2>Email confirmed</h2><div class="note good">Thank you. Your request has gone to the administrators. You will get an email when your account is approved; then sign in with just your email.</div>'})` }),
  message: (title, html, kind = 'info', actions = '') => page(title, `<div class="card">${BRAND}<h2>${esc(title)}</h2><div class="note ${kind}">${html}</div>${actions ? `<div class="row">${actions}</div>` : ''}</div>`),
  decide: (u, t) => page('Review account request', `<form class="card mid" id="f">${BRAND}<h2>Account request</h2>
    <div class="tbl"><table><tbody>
      <tr><th>Name</th><td>${esc(u.name)}</td></tr><tr><th>Email</th><td>${esc(u.email)}</td></tr><tr><th>Institution</th><td>${esc(u.institution)}</td></tr>
      <tr><th>Role</th><td>${esc(u.title)}</td></tr><tr><th>Intended use</th><td>${esc(u.purpose) || '<span class="hint">not given</span>'}</td></tr><tr><th>Requested</th><td>${esc((u.created_at || '').slice(0, 16).replace('T', ' '))} UTC</td></tr>
      <tr><th>Status</th><td><span class="pill ${esc(u.status)}">${esc(u.status === 'pending' ? 'waiting' : u.status)}</span></td></tr></tbody></table></div>
    ${u.status === 'pending' ? `<input type="hidden" name="token" value="${esc(t)}"><label>Message to the applicant (optional, included in the email)<textarea name="note" maxlength="1000"></textarea></label>
      <label class="check"><input type="checkbox" name="admin"> Make this person an administrator</label>
      <p class="msg" role="alert"></p><div class="row" id="acts"><button class="btn primary" type="submit" name="action" value="approve">Approve</button><button class="btn danger" type="submit" name="action" value="deny">Deny</button></div>` : `<div class="note info">This request has already been handled.</div>`}
    <p class="hint">All accounts: <a href="/admin">admin page</a>.</p></form>`,
    { script: `const f=el('f');let act='approve';f.querySelectorAll('button[name=action]').forEach(b=>b.onclick=()=>act=b.value);f.addEventListener('submit',async e=>{e.preventDefault();const m=f.querySelector('.msg');try{const o=formData(f);o.action=act;const j=await api('/api/decide',o);el('acts').innerHTML='';m.className='msg good';m.textContent=j.message}catch(err){m.className='msg bad';m.textContent=err.message}})` }),
  account: u => page('Account', `<div class="card mid">${BRAND}<h2>Your account</h2>
    <div class="tbl"><table><tbody><tr><th>Name</th><td>${esc(u.name)}</td></tr><tr><th>Email</th><td>${esc(u.email)}</td></tr><tr><th>Institution</th><td>${esc(u.institution)}</td></tr><tr><th>Access</th><td>${u.is_admin ? 'Administrator' : 'User'}</td></tr><tr><th>This device</th><td>${u._remember ? `Kept signed in for up to ${CFG.rememberDays} days` : `Signed out after ${CFG.sessionIdleMin} minutes without activity`}</td></tr></tbody></table></div>
    <p class="hint">${B.name} has no passwords. Each sign-in uses a one-time code sent to your email.</p>
    <p class="msg" id="m" role="status"></p>
    <div class="row"><a class="btn primary" href="/app">Open ${B.name}</a>${u.is_admin ? '<a class="btn" href="/admin">Admin</a>' : ''}<button class="btn" type="button" id="out">Sign out</button><button class="btn" type="button" id="outAll">Sign out on all devices</button></div></div>`,
    { script: `el('out').onclick=async()=>{await api('/api/logout');location.href='/login?m=out'};el('outAll').onclick=async()=>{await api('/api/logout-all');location.href='/login?m=out'}` }),
  admin: () => page('Administration', `<div class="card wide">${BRAND}<div class="row" style="justify-content:space-between"><h2>Accounts</h2><div class="row"><a class="btn small" href="/app">Open ${B.name}</a><a class="btn small" href="/account">Account</a></div></div>
    <div class="tabs" id="tabs"><button data-f="pending" class="on">Waiting for approval</button><button data-f="active">Active</button><button data-f="all">All</button><button data-f="audit">Activity log</button></div>
    <form class="row" id="addForm" style="align-items:end"><label style="flex:1 1 180px">Add a person directly: name<input name="name" required maxlength="120"></label><label style="flex:1 1 220px">Email<input name="email" type="email" required maxlength="200"></label><label style="flex:1 1 180px">Institution<input name="institution" maxlength="200"></label><label class="check" style="flex:0 0 auto;align-self:center"><input type="checkbox" name="admin"> Administrator</label><button class="btn" type="submit">Add and notify</button></form>
    <p class="msg" id="m" role="status"></p><div class="tbl" id="list"><p class="hint">Loading…</p></div></div>`,
    { script: `let users=[],filter='pending';const L=el('list'),M=el('m');
const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load(){const r=await fetch('/api/admin/users',{credentials:'same-origin'});if(r.status===401||r.status===403){location.href='/login?next=/admin';return}users=(await r.json()).users;draw()}
async function audit(){const r=await fetch('/api/admin/audit',{credentials:'same-origin'});const a=(await r.json()).audit;L.innerHTML='<table><thead><tr><th>Time (UTC)</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>'+a.map(x=>'<tr><td class="mono">'+e(x.ts.slice(0,19).replace('T',' '))+'</td><td>'+e(x.actor)+'</td><td>'+e(x.action)+'</td><td>'+e(x.target)+'</td><td class="hint">'+e(x.detail)+'</td></tr>').join('')+'</tbody></table>'}
function draw(){if(filter==='audit')return audit();const rows=users.filter(u=>filter==='all'||u.status===filter);if(!rows.length){L.innerHTML='<p class="hint">'+(filter==='pending'?'No requests are waiting.':'No accounts.')+'</p>';return}
L.innerHTML='<table><thead><tr><th>Name</th><th>Email</th><th>Institution · role</th><th>Intended use</th><th>Status</th><th>Requested</th><th>Last sign-in</th><th></th></tr></thead><tbody>'+rows.map(u=>{const b=[];if(u.status==='pending')b.push(['approve','Approve','primary'],['deny','Deny','danger']);if(u.status==='active'&&!u.self)b.push(['disable','Disable',''],[u.is_admin?'unadmin':'admin',u.is_admin?'Remove admin':'Make admin','']);if(u.status==='disabled'||u.status==='denied')b.push(['enable','Activate','']);if(u.status==='unverified')b.push(['resend','Resend confirmation','']);if(!u.self)b.push(['delete','Delete','danger']);
return '<tr><td>'+e(u.name)+(u.is_admin?' <span class="pill active">admin</span>':'')+'</td><td>'+e(u.email)+'</td><td>'+e(u.institution)+'<br><span class="hint">'+e(u.title)+'</span></td><td class="hint">'+e(u.purpose)+'</td><td><span class="pill '+e(u.status)+'">'+e(u.status==='pending'?'waiting':u.status)+'</span></td><td class="mono">'+e((u.created_at||'').slice(0,10))+'</td><td class="mono">'+e((u.last_login||'').slice(0,10))+'</td><td><div class="row">'+b.map(([a,l,c])=>'<button class="btn small '+c+'" data-a="'+a+'" data-id="'+u.id+'">'+l+'</button>').join('')+'</div></td></tr>'}).join('')+'</tbody></table>'}
el('tabs').onclick=ev=>{const b=ev.target.closest('button');if(!b)return;filter=b.dataset.f;document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('on',x===b));draw()};
L.onclick=async ev=>{const b=ev.target.closest('button[data-a]');if(!b)return;const a=b.dataset.a;if(['deny','delete','disable'].includes(a)&&!b.dataset.c){b.dataset.c=1;b.textContent='Confirm';return}b.disabled=true;try{const j=await api('/api/admin/user',{id:+b.dataset.id,action:a});M.className='msg good';M.textContent=j.message||'Done.';await load()}catch(err){M.className='msg bad';M.textContent=err.message;b.disabled=false}};
el('addForm').addEventListener('submit',async ev=>{ev.preventDefault();const f=ev.target;try{const j=await api('/api/admin/add',formData(f));f.reset();M.className='msg good';M.textContent=j.message;await load()}catch(err){M.className='msg bad';M.textContent=err.message}});
load()` })
};

/* ---------------------------------------------------------------- notifications */
async function notifyAdminsOfRequest(u) {
  const t = issueToken(u.id, 'decide', 24 * 14);
  const link = `${CFG.baseUrl}/decide?t=${encodeURIComponent(t)}`;
  const rows = [['Name', u.name], ['Email', u.email], ['Institution', u.institution], ['Role', u.title], ['Intended use', u.purpose || '(not given)']];
  const text = `A new ${B.name} account request needs your review.\n\n${rows.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\nApprove or deny: ${link}\n(This link works for 14 days. All accounts: ${CFG.baseUrl}/admin)`;
  const html = `<div style="font:15px/1.55 system-ui,sans-serif;color:${B.ink};max-width:560px"><h2 style="font-size:18px;margin:0 0 12px">New ${B.name} account request</h2>
    <table style="border-collapse:collapse;font-size:14px">${rows.map(([k, v]) => `<tr><td style="padding:4px 14px 4px 0;color:#5a6178">${k}</td><td style="padding:4px 0">${esc(v)}</td></tr>`).join('')}</table>
    <p style="margin:18px 0"><a href="${esc(link)}" style="background:${B.hex};color:#fff;text-decoration:none;padding:11px 20px;border-radius:8px;font-weight:600;display:inline-block">Review request</a></p>
    <p style="color:#5a6178;font-size:13px">The button opens a page where you approve or deny. It works for 14 days. All accounts: <a href="${CFG.baseUrl}/admin">${CFG.baseUrl}/admin</a></p></div>`;
  await sendMail(adminRecipients(), `${B.name} account request: ${u.name}`, text, html);
}
async function decide(u, action, by, note, makeAdmin, ip) {
  if (action === 'approve') {
    db.prepare("UPDATE users SET status='active', decided_at=?, decided_by=?, is_admin=? WHERE id=?").run(nowIso(), by, makeAdmin ? 1 : u.is_admin, u.id);
    log(by, 'approved', u.email, makeAdmin ? 'as administrator' : '', ip);
    await sendMail(u.email, `Your ${B.name} account is approved`, `Hello ${u.name},\n\nYour ${B.name} account has been approved${makeAdmin ? ' with administrator access' : ''}.${note ? `\n\nMessage from the administrator:\n${note}` : ''}\n\nSign in at ${CFG.baseUrl}/login with your email address. No password is needed: we email you a one-time code each time.\n\n${B.approvedNote}`);
    return `${u.name} approved. They have been emailed.`;
  }
  db.prepare("UPDATE users SET status='denied', decided_at=?, decided_by=? WHERE id=?").run(nowIso(), by, u.id);
  log(by, 'denied', u.email, String(note || '').slice(0, 200), ip);
  await sendMail(u.email, `Your ${B.name} account request`, `Hello ${u.name},\n\nYour request for a ${B.name} account was not approved.${note ? `\n\nMessage from the administrator:\n${note}` : ''}\n\nIf you have questions, contact the ${CFG.orgName}.`);
  return `${u.name} denied. They have been emailed.`;
}

/* ---------------------------------------------------------------- routes */
async function route(req, res) {
  const url = new URL(req.url, CFG.baseUrl), p = url.pathname, ip = clientIp(req), m = req.method;
  if (m === 'POST') {
    if (!sameOrigin(req)) return json(res, 403, { error: 'Request blocked (cross-site).' });
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) return json(res, 415, { error: 'Unsupported content type.' });
    if (limited('ip:' + ip, 150, 15 * 60e3)) return json(res, 429, { error: 'Too many requests. Try again in a few minutes.' });
  }
  const me = currentUser(req);

  /* ---- public pages ---- */
  if (m === 'GET' && p === '/') return send(res, 200, P.home(me));
  if (m === 'GET' && p === '/icon.svg') return send(res, 200, B.icon, 'image/svg+xml', { 'Cache-Control': 'public, max-age=86400' });
  if (m === 'GET' && p === '/health') return json(res, 200, { ok: true, site: SITE });
  if (m === 'GET' && p === '/login') return me ? redirect(res, safeNext(url.searchParams.get('next'))) : send(res, 200, P.login(url.searchParams.get('next'), url.searchParams.get('m') === 'out' ? 'You have signed out.' : url.searchParams.get('m') === 'expired' ? 'Your session ended. Sign in again.' : ''));
  if (m === 'GET' && p === '/register') return send(res, 200, P.register());
  if (m === 'GET' && p === '/c') {
    const t = url.searchParams.get('t'), r = t ? q.codeByLink.get(sha(t)) : null;
    if (!r || r.used || r.expires < Date.now()) return send(res, 400, P.message('Link expired', `This link has expired or was already used. <a href="/login">Sign in</a> to get a new code.`, 'warn'));
    return send(res, 200, P.linkConfirm(t));
  }
  if (m === 'GET' && p === '/decide') {
    const t = url.searchParams.get('t'), r = readToken(t, 'decide');
    if (!r) return send(res, 400, P.message('Link expired', 'This review link is invalid or has expired. Use the <a href="/admin">admin page</a> instead.', 'warn'));
    return send(res, 200, P.decide(q.userById.get(r.user_id), t));
  }
  if (m === 'GET' && (p === '/forgot' || p === '/reset')) return redirect(res, '/login');

  /* ---- signed-in pages ---- */
  if (m === 'GET' && (p === '/app' || p === '/app/')) {
    if (!me) return redirect(res, '/login?next=/app');
    try { return send(res, 200, fs.readFileSync(CFG.appFile, 'utf8')); } catch (e) { return send(res, 500, P.message('App not installed', `The ${B.name} application file is missing on the server (${esc(path.relative(__dirname, CFG.appFile))}).`, 'bad')); }
  }
  if (m === 'GET' && p === '/account') return me ? send(res, 200, P.account(me)) : redirect(res, '/login?next=/account');
  if (m === 'GET' && p === '/admin') { if (!me) return redirect(res, '/login?next=/admin'); if (!me.is_admin) return send(res, 403, P.message('Administrators only', 'Your account does not have administrator access.', 'warn', `<a class="btn" href="/app">Open ${B.name}</a>`)); return send(res, 200, P.admin()); }

  /* ---- API ---- */
  if (m === 'GET' && p === '/api/me') return me ? json(res, 200, { name: me.name, email: me.email, admin: !!me.is_admin, idleMinutes: me._remember ? CFG.rememberDays * 1440 : CFG.sessionIdleMin }) : json(res, 401, { error: 'Not signed in.' });
  if (m === 'POST' && p === '/api/register') {
    if (limited('reg:' + ip, 10, 60 * 60e3)) return json(res, 429, { error: 'Too many sign-ups from this network. Try again later.' });
    const b = await readBody(req);
    const email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 120), inst = String(b.institution || '').trim().slice(0, 200), title = String(b.title || '').trim().slice(0, 80), purpose = String(b.purpose || '').trim().slice(0, 1000);
    if (!name || !inst) return json(res, 400, { error: 'Enter your name and institution.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 200) return json(res, 400, { error: 'Enter a valid email address.' });
    if (!b.agree) return json(res, 400, { error: 'Please accept the terms of use.' });
    if (limited('send:' + email, 5, 15 * 60e3)) return json(res, 429, { error: 'Too many codes sent to this email. Wait 15 minutes.' });
    let u = q.userByEmail.get(email);
    if (u && u.status === 'active') return json(res, 200, { status: 'active', message: 'You already have an account. <a href="/login">Sign in</a> with your email.' });
    if (u && u.status === 'pending') return json(res, 200, { status: 'pending', message: 'Your request is already waiting for administrator approval. You will get an email when it is approved.' });
    if (u && (u.status === 'denied' || u.status === 'disabled')) return json(res, 200, { status: u.status, message: STATUS_TEXT[u.status] });
    if (!u) { const info = q.insertUser.run(email, name, inst, title, purpose, 'unverified', 0, nowIso()); u = q.userById.get(Number(info.lastInsertRowid)); log(email, 'registered', email, inst, ip); }
    else { db.prepare('UPDATE users SET name=?, institution=?, title=?, purpose=? WHERE id=?').run(name, inst, title, purpose, u.id); u = q.userById.get(u.id); }
    await sendCode(u, 'verify', false, '/app', ip);
    return json(res, 200, { status: 'code', email });
  }
  if (m === 'POST' && p === '/api/login/start') {
    const b = await readBody(req), email = String(b.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return json(res, 400, { error: 'Enter a valid email address.' });
    if (limited('login:' + ip, 30, 15 * 60e3)) return json(res, 429, { error: 'Too many sign-in attempts. Try again in 15 minutes.' });
    const u = q.userByEmail.get(email);
    if (!u) return json(res, 200, { noAccount: true });
    if (u.status === 'pending' || u.status === 'denied' || u.status === 'disabled') return json(res, 200, { status: u.status, message: STATUS_TEXT[u.status] });
    if (limited('send:' + email, 5, 15 * 60e3)) return json(res, 429, { error: 'Too many codes sent to this email. Wait 15 minutes, then use the newest email.' });
    await sendCode(u, u.status === 'unverified' ? 'verify' : 'login', !!b.remember, b.next, ip);
    return json(res, 200, { status: 'code' });
  }
  if (m === 'POST' && p === '/api/login/verify') {
    const b = await readBody(req), email = String(b.email || '').trim().toLowerCase(), u = q.userByEmail.get(email);
    if (!u) return json(res, 400, { error: 'Start again: enter your email to get a code.' });
    const c = checkCode(u, b.code);
    if (c.error) { log(email, 'code_failed', email, '', ip); return json(res, 400, { error: c.error }); }
    const r = await completeCode(req, u, c.row, ip);
    if (r.error) return json(res, 403, { error: r.error });
    return json(res, 200, { status: r.status, next: r.next }, r.cookie ? { 'Set-Cookie': r.cookie } : {});
  }
  if (m === 'POST' && p === '/api/link') {
    const b = await readBody(req), r0 = b.t ? q.codeByLink.get(sha(String(b.t))) : null;
    if (!r0 || r0.used || r0.expires < Date.now()) return json(res, 400, { error: 'This link has expired or was already used. Sign in again to get a new code.' });
    q.codeUse.run(r0.id);
    const u = q.userById.get(r0.user_id);
    const r = await completeCode(req, u, r0, ip);
    if (r.error) return json(res, 403, { error: r.error });
    return json(res, 200, { status: r.status, next: r.next }, r.cookie ? { 'Set-Cookie': r.cookie } : {});
  }
  if (m === 'POST' && p === '/api/logout') { if (me) { q.sessDel.run(me._sess); log(me.email, 'logout', me.email, '', ip); } return json(res, 200, { ok: true }, { 'Set-Cookie': setCookie('') }); }
  if (m === 'POST' && p === '/api/logout-all') { if (me) { q.sessDelUser.run(me.id); log(me.email, 'logout_all', me.email, '', ip); } return json(res, 200, { ok: true }, { 'Set-Cookie': setCookie('') }); }
  if (m === 'POST' && p === '/api/decide') {
    const b = await readBody(req), r = readToken(b.token, 'decide');
    if (!r) return json(res, 400, { error: 'This review link is invalid or has expired. Use the admin page.' });
    const u = q.userById.get(r.user_id);
    if (u.status !== 'pending') return json(res, 400, { error: 'This request has already been handled.' });
    q.tokenUse.run(r.hash);
    return json(res, 200, { ok: true, message: await decide(u, b.action === 'approve' ? 'approve' : 'deny', 'email link', String(b.note || '').slice(0, 1000), !!b.admin, ip) });
  }
  if (p.startsWith('/api/admin/')) {
    if (!me) return json(res, 401, { error: 'Please sign in again.' });
    if (!me.is_admin) return json(res, 403, { error: 'Administrators only.' });
    if (m === 'GET' && p === '/api/admin/users') return json(res, 200, { users: q.allUsers.all().map(u => ({ ...u, self: u.id === me.id })) });
    if (m === 'GET' && p === '/api/admin/audit') return json(res, 200, { audit: q.auditList.all() });
    if (m === 'POST' && p === '/api/admin/add') {
      const b = await readBody(req), email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 120);
      if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return json(res, 400, { error: 'Enter a name and a valid email address.' });
      const ex = q.userByEmail.get(email);
      if (ex) return json(res, 400, { error: `${email} already has an account (${ex.status}).` });
      q.insertUser.run(email, name, String(b.institution || '').trim().slice(0, 200), '', 'Added by administrator', 'active', b.admin ? 1 : 0, nowIso());
      db.prepare('UPDATE users SET verified_at=?, decided_at=?, decided_by=? WHERE email=?').run(nowIso(), nowIso(), me.email, email);
      log(me.email, 'added', email, b.admin ? 'as administrator' : '', ip);
      sendMail(email, `You have been added to ${B.name}`, `Hello ${name},\n\n${me.name} added you to ${B.name}${b.admin ? ' as an administrator' : ''}.\n\nSign in at ${CFG.baseUrl}/login with this email address. No password is needed: we email you a one-time code each time.\n\n${B.approvedNote}`);
      return json(res, 200, { message: `${name} added and emailed.` });
    }
    if (m === 'POST' && p === '/api/admin/user') {
      const b = await readBody(req), u = q.userById.get(+b.id);
      if (!u) return json(res, 404, { error: 'No such account.' });
      if (u.id === me.id) return json(res, 400, { error: 'You cannot change your own account here.' });
      const a = b.action;
      if (a === 'approve' || a === 'deny') { if (u.status !== 'pending') return json(res, 400, { error: 'This account is not waiting for approval.' }); return json(res, 200, { message: await decide(u, a, me.email, '', false, ip) }); }
      if (a === 'disable') { db.prepare("UPDATE users SET status='disabled' WHERE id=?").run(u.id); q.sessDelUser.run(u.id); log(me.email, 'disabled', u.email, '', ip); return json(res, 200, { message: `${u.name} disabled and signed out.` }); }
      if (a === 'enable') { db.prepare("UPDATE users SET status='active', decided_at=?, decided_by=? WHERE id=?").run(nowIso(), me.email, u.id); log(me.email, 'enabled', u.email, '', ip); sendMail(u.email, `Your ${B.name} account is active`, `Hello ${u.name},\n\nYour ${B.name} account is active. Sign in at ${CFG.baseUrl}/login with your email address.`); return json(res, 200, { message: `${u.name} activated.` }); }
      if (a === 'admin' || a === 'unadmin') { if (a === 'unadmin' && q.adminCount.get().n <= 1) return json(res, 400, { error: 'At least one administrator is required.' }); db.prepare('UPDATE users SET is_admin=? WHERE id=?').run(a === 'admin' ? 1 : 0, u.id); log(me.email, a === 'admin' ? 'made_admin' : 'removed_admin', u.email, '', ip); return json(res, 200, { message: a === 'admin' ? `${u.name} is now an administrator.` : `${u.name} is no longer an administrator.` }); }
      if (a === 'resend') { if (u.status !== 'unverified') return json(res, 400, { error: 'Already confirmed.' }); await sendCode(u, 'verify', false, '/app', ip); log(me.email, 'resent_verification', u.email, '', ip); return json(res, 200, { message: 'Confirmation code sent again.' }); }
      if (a === 'delete') { db.prepare('DELETE FROM users WHERE id=?').run(u.id); log(me.email, 'deleted', u.email, '', ip); return json(res, 200, { message: `${u.name}'s account was deleted.` }); }
      return json(res, 400, { error: 'Unknown action.' });
    }
  }
  if (m === 'GET') return send(res, 404, P.message('Page not found', `That page does not exist. <a href="/">Go to the ${B.name} home page</a>.`, 'warn'));
  return json(res, 404, { error: 'Not found.' });
}

/* ---------------------------------------------------------------- bootstrap */
function bootstrap() {
  if (CFG.initialAdminEmail) {
    const ex = q.userByEmail.get(CFG.initialAdminEmail);
    if (!ex) {
      q.insertUser.run(CFG.initialAdminEmail, CFG.initialAdminName, B.name, 'Administrator', '', 'active', 1, nowIso());
      log('system', 'admin_created', CFG.initialAdminEmail, 'initial administrator');
      console.log(`Created administrator ${CFG.initialAdminEmail}`);
    } else if (!ex.is_admin || ex.status !== 'active') {
      db.prepare("UPDATE users SET is_admin=1, status='active' WHERE id=?").run(ex.id);
      log('system', 'admin_restored', CFG.initialAdminEmail, 'INITIAL_ADMIN_EMAIL');
    }
  }
  if (!q.adminCount.get().n) console.warn('WARNING: no administrator account. Set INITIAL_ADMIN_EMAIL and restart.');
  setInterval(() => {
    db.prepare('DELETE FROM sessions WHERE last_seen < ?').run(Date.now() - Math.max(CFG.rememberDays * 864e5, CFG.sessionMaxHours * 3600e3));
    db.prepare('DELETE FROM tokens WHERE expires < ?').run(Date.now() - 86400e3);
    db.prepare('DELETE FROM codes WHERE expires < ?').run(Date.now() - 86400e3);
  }, 3600e3).unref();
}
bootstrap();
http.createServer((req, res) => {
  route(req, res).catch(e => { if (!res.headersSent) { const code = e.status || 500; if (code === 500) console.error(e); json(res, code, { error: code === 500 ? 'Something went wrong on the server.' : e.message }); } });
}).listen(CFG.port, () => console.log(`${B.name} server on ${CFG.baseUrl} (port ${CFG.port}); email via ${CFG.email.provider}`));
