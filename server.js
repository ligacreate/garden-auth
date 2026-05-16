import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const {
  DB_HOST,
  DB_PORT,
  DB_NAME,
  DB_USER,
  DB_PASS,
  DB_SSLMODE,
  DB_SSLROOTCERT,
  JWT_SECRET,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  PUBLIC_URL,
  PORT,
  S3_REGION,
  S3_ENDPOINT,
  S3_BUCKET,
  S3_ACCESS_KEY,
  S3_SECRET_KEY,
  S3_PUBLIC_URL,

} = process.env;

if (!JWT_SECRET) {
  console.error('JWT_SECRET is required');
  process.exit(1);
}

const sslMode = (DB_SSLMODE || '').toLowerCase();
let ssl = false;
if (sslMode) {
  ssl = { rejectUnauthorized: sslMode === 'verify-full' };
  if (DB_SSLROOTCERT) {
    try {
      ssl.ca = fs.readFileSync(DB_SSLROOTCERT).toString();
    } catch (e) {
      console.warn('Failed to read DB_SSLROOTCERT:', e.message);
    }
  }
}

const pool = new Pool({
  host: DB_HOST,
  port: DB_PORT ? Number(DB_PORT) : 5432,
  database: DB_NAME,
  user: DB_USER,
  password: DB_PASS,
  ssl
});

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));

const signToken = (payload) => jwt.sign({ role: 'authenticated', ...payload }, JWT_SECRET, { expiresIn: '30d' });

const authMiddleware = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const [, token] = auth.split(' ');
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const transporter = SMTP_HOST && SMTP_USER ? nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT ? Number(SMTP_PORT) : 465,
  secure: Number(SMTP_PORT) === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
}) : null;

app.get('/health', async (_req, res) => {
  try {
    await pool.query('select 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// MON-001 — health для post-deploy smoke (без DB-зависимости).
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'garden-auth',
    time: new Date().toISOString(),
  });
});

// MON-001 — клиентский error reporter → Telegram @garden_grants_monitor_bot.
const CLIENT_ERROR_LOG = process.env.CLIENT_ERROR_LOG
  || '/var/log/garden-client-errors.log';
const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const TG_API = TG_BOT_TOKEN ? `https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage` : null;

const RL_WINDOW_MS = 60 * 1000;
const RL_HOUR_MS = 60 * 60 * 1000;
const RL_HOURLY_MAX = 50;
const recentByKey = new Map();
const hourlyByIp = new Map();

// IPv4-only POST (обходим happy-eyeballs в node fetch — на этом сервере
// IPv6 outbound к api.telegram.org даёт ENETUNREACH, см.
// docs/_session/2026-05-10_05_codeexec_p1_backend_deployed.md).
const httpsPostJson = (urlStr, jsonBody, timeoutMs = 8000) => new Promise((resolve, reject) => {
  let url;
  try { url = new URL(urlStr); } catch (e) { return reject(e); }
  const body = JSON.stringify(jsonBody);
  const req = https.request({
    hostname: url.hostname,
    port: url.port || 443,
    path: url.pathname + url.search,
    method: 'POST',
    family: 4,
    timeout: timeoutMs,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  }, (res) => {
    let chunks = '';
    res.setEncoding('utf8');
    res.on('data', (c) => { chunks += c; });
    res.on('end', () => resolve({
      ok: res.statusCode >= 200 && res.statusCode < 300,
      status: res.statusCode,
      text: chunks,
    }));
  });
  req.on('error', reject);
  req.on('timeout', () => req.destroy(new Error('TG request timeout')));
  req.write(body);
  req.end();
});

setInterval(() => {
  const now = Date.now();
  for (const [k, ts] of recentByKey) if (now - ts > 10 * RL_WINDOW_MS) recentByKey.delete(k);
  for (const [ip, w] of hourlyByIp) if (now - w.windowStart > RL_HOUR_MS) hourlyByIp.delete(ip);
}, 5 * 60 * 1000).unref();

const clientIp = (req) => {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
};

// Markdown V1 — экранируем только символы форматирования.
const escapeMd = (s) => String(s).replace(/[`*_]/g, '\\$&');

// FEAT-023 — уведомление админа в @garden_grants_monitor_bot о новой регистрации.
// Использует существующий MON-001 sender (httpsPostJson, IPv4-only, обход
// happy-eyeballs к api.telegram.org с этого сервера).
const notifyNewRegistration = async ({ id, name, email, city }) => {
  if (!TG_API || !TG_CHAT_ID) return;

  const safeName  = escapeMd(String(name  || 'без имени'));
  const safeEmail = escapeMd(String(email || ''));
  const safeCity  = escapeMd(String(city  || 'не указан'));
  const adminUrl  = `${PUBLIC_URL || ''}/#/admin?tab=pending&user=${id}`;

  const text = [
    '🌱 *Новая регистрация*',
    `Имя: ${safeName}`,
    `Email: ${safeEmail}`,
    `Город: ${safeCity}`,
    `[Открыть в админке](${adminUrl})`,
  ].join('\n');

  const tgRes = await httpsPostJson(TG_API, {
    chat_id: TG_CHAT_ID,
    text,
    parse_mode: 'Markdown',
    disable_web_page_preview: true,
  }).catch((e) => ({ ok: false, status: 0, text: String(e?.message || e) }));

  if (!tgRes.ok) {
    logClientError({
      ts: new Date().toISOString(),
      level: 'tg-notify-registration-failed',
      status: tgRes.status,
      body: String(tgRes.text || '').slice(0, 500),
      userId: id,
    });
  }
};

const logClientError = (obj) => {
  try {
    fs.appendFile(CLIENT_ERROR_LOG, JSON.stringify(obj) + '\n', () => {});
  } catch { /* ignore */ }
};

app.post('/api/client-error', async (req, res) => {
  res.status(204).end();

  try {
    const body = req.body || {};
    const message = String(body.message || '').slice(0, 500);
    if (!message) return;

    const ip = clientIp(req);
    const stack = String(body.stack || '').slice(0, 4000);
    const source = String(body.source || 'window').slice(0, 50);
    const url = String(body.url || '').slice(0, 500);
    const userAgent = String(body.userAgent || '').slice(0, 300);
    const bundleId = String(body.bundleId || 'unknown').slice(0, 100);
    const bundleScript = String(body.bundleScript || '').slice(0, 200);
    const user = body.user && typeof body.user === 'object' ? body.user : null;

    const msgHash = crypto.createHash('sha1')
      .update(`${message}::${stack.slice(0, 200)}`)
      .digest('hex').slice(0, 12);

    const dedupeKey = `${ip}::${msgHash}`;
    const now = Date.now();
    const last = recentByKey.get(dedupeKey) || 0;
    if (now - last < RL_WINDOW_MS) return;
    recentByKey.set(dedupeKey, now);

    let w = hourlyByIp.get(ip);
    if (!w || now - w.windowStart > RL_HOUR_MS) {
      w = { windowStart: now, uniqueCount: 0 };
      hourlyByIp.set(ip, w);
    }
    w.uniqueCount += 1;
    if (w.uniqueCount > RL_HOURLY_MAX) {
      logClientError({ ts: new Date().toISOString(), level: 'rate-limited', ip, msgHash, message });
      return;
    }

    logClientError({
      ts: new Date().toISOString(),
      ip, msgHash, source, message, stack, url, userAgent, bundleId, bundleScript, user,
    });

    if (!TG_API || !TG_CHAT_ID) return;

    const userLine = user
      ? `${user.email || user.name || 'anon'} (${user.id || '–'})`
      : 'anon';

    const text = [
      '🚨 *Garden client error*',
      '`' + escapeMd(message.slice(0, 300)) + '`',
      `source: \`${source}\``,
      `user: ${escapeMd(userLine)}`,
      `bundle: \`${escapeMd(bundleScript || bundleId)}\``,
      `url: ${escapeMd(url)}`,
      stack ? '```\n' + stack.slice(0, 1000).replace(/```/g, '"""') + '\n```' : '',
    ].filter(Boolean).join('\n');

    const tgRes = await httpsPostJson(TG_API, {
      chat_id: TG_CHAT_ID,
      text,
      parse_mode: 'Markdown',
      disable_web_page_preview: true,
    }).catch((e) => ({ ok: false, status: 0, text: String(e?.message || e) }));
    if (!tgRes.ok) {
      logClientError({
        ts: new Date().toISOString(),
        level: 'tg-failed',
        status: tgRes.status,
        body: String(tgRes.text || '').slice(0, 500),
      });
    }
  } catch (err) {
    logClientError({
      ts: new Date().toISOString(),
      level: 'handler-error',
      error: String(err?.message || err),
    });
  }
});

const s3Client = (S3_BUCKET && S3_REGION && S3_ACCESS_KEY && S3_SECRET_KEY)
  ? new S3Client({
      region: S3_REGION,
      endpoint: S3_ENDPOINT || undefined,
      forcePathStyle: Boolean(S3_ENDPOINT),
      credentials: {
        accessKeyId: S3_ACCESS_KEY,
        secretAccessKey: S3_SECRET_KEY
      }
    })
  : null;

const sanitizeFileName = (name = 'file.jpg') =>
  String(name)
    .replace(/[^a-zA-Z0-9._-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 120) || 'file.jpg';

app.post('/storage/sign', authMiddleware, async (req, res) => {
  try {
    if (!s3Client) {
      return res.status(500).json({ error: 'S3 is not configured' });
    }

    const { folder, fileName, contentType } = req.body || {};
    if (!folder || !fileName || !contentType) {
      return res.status(400).json({ error: 'folder, fileName, contentType are required' });
    }

    const safeFolder = String(folder).replace(/[^a-zA-Z0-9/_-]/g, '');
    const safeName = sanitizeFileName(fileName);
    const key = `${safeFolder}/${Date.now()}-${safeName}`;

    const command = new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      ContentType: contentType
    });

    const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });

    const basePublic = S3_PUBLIC_URL
      ? S3_PUBLIC_URL.replace(/\/$/, '')
      : (S3_ENDPOINT ? S3_ENDPOINT.replace(/\/$/, '') : '');

    const publicUrl = basePublic
      ? `${basePublic}/${key}`
      : uploadUrl.split('?')[0];

    return res.json({ uploadUrl, publicUrl });
  } catch (e) {
    console.error('storage/sign error', e);
    return res.status(500).json({ error: e.message || 'Failed to sign upload' });
  }
});


app.post('/auth/register', async (req, res) => {
  const { email, password, name, city, dob, tree, tree_desc, treeDesc, x, y } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const existing = await pool.query('select id from public.users_auth where email = $1', [email]);
    if (existing.rows.length) return res.status(409).json({ error: 'User already exists' });

    const id = uuidv4();
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      'insert into public.users_auth (id, email, password_hash, status) values ($1,$2,$3,$4)',
      [id, email, hash, 'active']
    );

    // FEAT-023 Phase 2: новые регистрации в pending_approval до одобрения админом.
    // status='suspended' ставим явно — bridge trigger trg_sync_status_from_access_status
    // навешан на UPDATE OF access_status, на INSERT не срабатывает.
    // Доп. поля (dob, tree, x, y) принимаются здесь же — после phase31 фронт
    // не может PATCH'ить /profiles под JWT pending'а (restrictive write guard).
    await pool.query(
      `insert into public.profiles
         (id, email, name, city, role, status, access_status, seeds,
          dob, tree, tree_desc, x, y)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       on conflict (id) do update set email=excluded.email, name=excluded.name, city=excluded.city`,
      [id, email, name || null, city || null,
       'applicant', 'suspended', 'pending_approval', 0,
       dob || null, tree || null, tree_desc || treeDesc || null,
       x ?? null, y ?? null]
    );

    const token = signToken({ sub: id, email });
    res.json({
      token,
      user: { id, email, name, city, role: 'applicant', access_status: 'pending_approval' }
    });

    // FEAT-023 Phase 2: TG-уведомление админу о новой регистрации.
    // Fire-and-forget: не блокируем регистрацию если TG лагает / не настроен.
    notifyNewRegistration({ id, name, email, city }).catch((e) => {
      logClientError({
        ts: new Date().toISOString(),
        level: 'tg-notify-registration-failed',
        error: String(e?.message || e),
        userId: id,
      });
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const { rows } = await pool.query('select id, password_hash, status from public.users_auth where email = $1', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    if (user.status !== 'active') return res.status(403).json({ error: 'Account suspended' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const profile = await pool.query('select * from public.profiles where id = $1', [user.id]);
    const token = signToken({ sub: user.id, email });
    res.json({ token, user: profile.rows[0] || { id: user.id, email } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('select * from public.profiles where id = $1', [req.user.sub]);
    if (!rows.length) return res.status(404).json({ error: 'Profile not found' });
    res.json({ user: rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const normalizedEmail = String(email).trim().toLowerCase();
    const { rows } = await pool.query('select id from public.users_auth where email = $1', [normalizedEmail]);
    if (!rows.length) return res.status(404).json({ error: 'Email not found' });

    if (!transporter) {
      return res.status(500).json({ error: 'SMTP not configured' });
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min

    await pool.query(
      'update public.users_auth set reset_token=$1, reset_expires=$2 where email=$3',
      [tokenHash, expires, normalizedEmail]
    );

    const resetUrl = `${PUBLIC_URL}/reset?token=${rawToken}`;
    await transporter.sendMail({
      from: SMTP_FROM,
      to: normalizedEmail,
      subject: 'Восстановление пароля',
      text: `Ссылка для сброса пароля: ${resetUrl}`
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('request-reset error', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/auth/reset', async (req, res) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password) return res.status(400).json({ error: 'Token and new_password required' });
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = await pool.query(
      'select id, reset_expires from public.users_auth where reset_token = $1',
      [tokenHash]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid token' });
    const row = rows[0];
    if (row.reset_expires && new Date(row.reset_expires) < new Date()) {
      return res.status(400).json({ error: 'Token expired' });
    }
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query(
      'update public.users_auth set password_hash=$1, reset_token=null, reset_expires=null where id=$2',
      [hash, row.id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT || 3001, () => {
  console.log(`Auth server running on port ${PORT || 3001}`);
});
