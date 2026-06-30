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

// FEAT-024 — отдельный TG-бот для уведомлений менторам/студенткам ПВЛ.
// НЕ путать с TG_BOT_TOKEN/TG_CHAT_ID выше (тот — @garden_grants_monitor_bot
// для админ-алертов). Этот — @garden_notifications_bot, юзер-направленный.
const TG_NOTIF_BOT_TOKEN = process.env.TG_NOTIFICATIONS_BOT_TOKEN;
const TG_NOTIF_BOT_USERNAME = process.env.TG_NOTIFICATIONS_BOT_USERNAME || 'garden_notifications_bot';
const TG_NOTIF_WEBHOOK_PATH = process.env.TG_NOTIFICATIONS_WEBHOOK_PATH;
const TG_NOTIF_WEBHOOK_SECRET = process.env.TG_NOTIFICATIONS_WEBHOOK_SECRET;
const TG_NOTIF_API_BASE = TG_NOTIF_BOT_TOKEN
  ? `https://api.telegram.org/bot${TG_NOTIF_BOT_TOKEN}`
  : null;

const RL_WINDOW_MS = 60 * 1000;
const RL_HOUR_MS = 60 * 60 * 1000;
const RL_HOURLY_MAX = 50;
const recentByKey = new Map();
const hourlyByIp = new Map();

// MON-002 — приглушение benign клиентских ошибок: глушим поштучно,
// алертим ОДИН агрегат только при кучковании за скользящее 60-мин окно.
// Категории и пороги (events/час) тюнятся здесь. Счётчик — в памяти процесса
// (garden-auth = один процесс `node server.js`, без cluster/pm2 — Map ок;
// рестарт обнуляет окна, для админ-мониторинга приемлемо).
const BENIGN_WINDOW_MS = 60 * 60 * 1000;          // окно скользящего счётчика
const BENIGN_ALERT_COOLDOWN_MS = 60 * 60 * 1000;  // не чаще 1 агрегата / категорию / час
const BENIGN_THRESHOLDS = {
  jwt_expired: 10,            // >10/час → всплеск протухших подписей / PostgREST 401
  chunk_autoreload: 15,       // >15/час → зацикленный reload / битый деплой
  failed_fetch: 8,            // >8/час  → сетевой/CORS-инцидент
  pvl_hydrate_degradation: 8, // >8/час  → деградация гидрации ПВЛ
};
// per-category: { hits: number[] (timestamps в окне), lastAlertTs, dayCount }
const benignState = new Map();

// MON-002 — отнести входящее событие к benign-категории или 'other'.
// Классифицируем на сервере по message/source/code (клиент шлёт их как есть).
const classifyClientError = ({ message, source, code }) => {
  const msg = message || '';
  const src = source || '';
  if (msg.includes('JWT expired') || code === 'PGRST303') return 'jwt_expired';
  if (src === 'ErrorBoundary.chunkLoad'
      || msg.includes('ChunkLoadError')
      || msg.includes('Importing a module script failed')
      || msg.includes('Failed to fetch dynamically imported module')) return 'chunk_autoreload';
  if (msg === 'Failed to fetch' || msg === 'TypeError: Failed to fetch') return 'failed_fetch';
  if (msg.includes('loadRuntimeSnapshot partial degradation')
      || msg.includes('hydrate_mentor_links failed')
      || src.startsWith('pvlMockApi.hydrate')) return 'pvl_hydrate_degradation';
  return 'other';
};

// MON-002 — учесть benign-событие в скользящем окне; вернуть текст агрегата,
// если пора алертить (порог превышен и кулдаун прошёл), иначе null.
const recordBenign = (category, now) => {
  let st = benignState.get(category);
  if (!st) { st = { hits: [], lastAlertTs: 0, dayCount: 0 }; benignState.set(category, st); }
  st.hits.push(now);
  const cutoff = now - BENIGN_WINDOW_MS;
  while (st.hits.length && st.hits[0] < cutoff) st.hits.shift();
  st.dayCount += 1;
  const threshold = BENIGN_THRESHOLDS[category];
  if (st.hits.length > threshold && now - st.lastAlertTs > BENIGN_ALERT_COOLDOWN_MS) {
    st.lastAlertTs = now;
    return `⚠️ *${category}* ×${st.hits.length} за час (кучкование)\n`
      + `Порог >${threshold}/час превышен — похоже на реальный инцидент, проверь.`;
  }
  return null;
};

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

// IPv4-only GET (тот же обход happy-eyeballs, что и httpsPostJson).
// Используется в pollTgUpdates ниже для getUpdates с long-polling timeout.
// Все ошибки → resolve({ok:false,...}), без reject — poll-loop не должен
// ломаться на одной сбойной итерации.
const httpsGetJson = (urlStr, timeoutMs = 30000) => new Promise((resolve) => {
  let url;
  try { url = new URL(urlStr); } catch (e) { return resolve({ ok: false, status: 0, text: String(e?.message || e) }); }
  const req = https.request({
    hostname: url.hostname,
    port: url.port || 443,
    path: url.pathname + url.search,
    method: 'GET',
    family: 4,
    timeout: timeoutMs,
  }, (res) => {
    let chunks = '';
    res.setEncoding('utf8');
    res.on('data', (c) => { chunks += c; });
    res.on('end', () => {
      try {
        resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, data: JSON.parse(chunks), text: chunks });
      } catch (e) {
        resolve({ ok: false, status: res.statusCode, text: chunks });
      }
    });
  });
  req.on('error', (e) => resolve({ ok: false, status: 0, text: String(e?.message || e) }));
  req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, text: 'timeout' }); });
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

// HTML-escape для parse_mode='HTML' в FEAT-024 уведомлениях.
const escapeHtml = (s) => String(s)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;');

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

// FEAT-024 — sender уведомлений в @garden_notifications_bot.
// Возвращает { ok, terminal?, code?, detail? }:
//   ok=true                 — отправлено;
//   ok=false terminal=true  — больше не пробуем (403/400);
//   ok=false terminal=false — retry с бэкоффом (5xx/timeout/network).
// Использует httpsPostJson (IPv4-only, обход happy-eyeballs к api.telegram.org).
const sendTgNotification = async (tgUserId, text, options = {}) => {
  if (!TG_NOTIF_API_BASE) {
    return { ok: false, terminal: true, code: 'bot_not_configured' };
  }
  const body = {
    chat_id: tgUserId,
    text,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
    ...options,
  };
  try {
    const r = await httpsPostJson(`${TG_NOTIF_API_BASE}/sendMessage`, body);
    if (r.ok) return { ok: true };
    if (r.status === 403) {
      return { ok: false, terminal: true, code: 'blocked_by_user', detail: r.text };
    }
    if (r.status === 400) {
      return { ok: false, terminal: true, code: 'bad_request', detail: r.text };
    }
    return { ok: false, terminal: false, code: `http_${r.status}`, detail: r.text };
  } catch (e) {
    return { ok: false, terminal: false, code: 'network_error', detail: String(e?.message || e) };
  }
};

// FEAT-024 linking flow — одноразовый код LINK-XXXXXX.
// Алфавит без визуально похожих символов (0/O, 1/I/L) — UX при ручном вводе.
const LINK_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const generateLinkCode = () => {
  const bytes = crypto.randomBytes(6);
  let s = '';
  for (let i = 0; i < 6; i++) s += LINK_CODE_ALPHABET[bytes[i] % LINK_CODE_ALPHABET.length];
  return `LINK-${s}`;
};

const logClientError = (obj) => {
  try {
    fs.appendFile(CLIENT_ERROR_LOG, JSON.stringify(obj) + '\n', () => {});
  } catch { /* ignore */ }
};

// MON-002 — общий sender админ-алерта в @garden_grants_monitor_bot
// (агрегат при кучковании + суточный дайджест). Reuse того же IPv4-only
// httpsPostJson; ошибку TG пишем в CLIENT_ERROR_LOG, не роняем вызывающего.
const postAdminTg = async (text) => {
  if (!TG_API || !TG_CHAT_ID) return;
  const tgRes = await httpsPostJson(TG_API, {
    chat_id: TG_CHAT_ID, text, parse_mode: 'Markdown', disable_web_page_preview: true,
  }).catch((e) => ({ ok: false, status: 0, text: String(e?.message || e) }));
  if (!tgRes.ok) {
    logClientError({
      ts: new Date().toISOString(), level: 'tg-failed',
      status: tgRes.status, body: String(tgRes.text || '').slice(0, 500),
    });
  }
};

// MON-002 — раз в сутки короткий дайджест benign-фона: чтобы фон был виден,
// но не дёргал поштучно. Молчим, если за сутки ничего не накопилось.
setInterval(() => {
  const cats = Object.keys(BENIGN_THRESHOLDS);
  const total = cats.reduce((s, c) => s + (benignState.get(c)?.dayCount || 0), 0);
  if (total > 0) {
    const parts = cats.map((c) => `${c} ×${benignState.get(c)?.dayCount || 0}`);
    postAdminTg(`📊 *benign за сутки*: ${parts.join(', ')}`);
  }
  for (const c of cats) { const st = benignState.get(c); if (st) st.dayCount = 0; }
}, 24 * 60 * 60 * 1000).unref();

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

    // MON-002 — benign-категории: в TG поштучно НЕ шлём, копим в окне, алертим
    // один агрегат при кучковании. FAIL-OPEN: любой сбой throttle-логики →
    // проваливаемся к обычной пересылке 'other' ниже (ничего не глотаем, не
    // роняем /api/client-error и тем более несвязанные /api/* login/reset).
    try {
      const category = classifyClientError({ message, source, code: body.code });
      if (category !== 'other') {
        const alert = recordBenign(category, now);
        if (alert) await postAdminTg(alert);
        return;
      }
    } catch (throttleErr) {
      logClientError({
        ts: new Date().toISOString(),
        level: 'mon002-throttle-error',
        error: String(throttleErr?.message || throttleErr),
      });
      // не return — событие уйдёт в TG как 'other' ниже (fail-open).
    }

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

// FEAT-024 — webhook handler для @garden_notifications_bot.
// Регистрация webhook'а: см. setWebhook в docs/_session/_45 §4.
// FEAT-024 / TG-WEBHOOK-INBOUND-BLOCKED (2026-05-19) — переключение на
// long-polling. Webhook handler заменён на pure-функцию, которую зовёт
// pollTgUpdates ниже. Логика парсинга /start + LINK-кода + привязки в
// profiles + confirm-message сохранена 1:1 из старого webhook-handler'а.
// См. docs/_session/2026-05-19_70_strategist_tg_webhook_to_polling.md
const processTgUpdate = async (update) => {
  try {
    const msg = update?.message;
    if (!msg || !msg.from || typeof msg.text !== 'string') return;

    const tgUserId = msg.from.id;
    const text = msg.text.trim();

    // Только команды /start (с LINK-кодом или без). Всё остальное — silently игнорим.
    const startMatch = text.match(/^\/start(?:\s+(LINK-[A-Z2-9]{6}))?\s*$/i);
    if (!startMatch) {
      return;
    }
    const code = (startMatch[1] || '').toUpperCase();
    if (!code) {
      // Голый /start без кода — отвечаем help'ом.
      await sendTgNotification(tgUserId,
        'Здравствуйте! Чтобы подписаться на уведомления о ДЗ, откройте свой профиль в Саду ведущих и нажмите «Привязать Telegram» — там появится одноразовый код.');
      return;
    }

    // 3. Найти код в БД, проверить валидность.
    const { rows: codeRows } = await pool.query(
      `select code, profile_id, expires_at, consumed_at
         from public.tg_link_codes
        where code = $1
        limit 1`,
      [code]
    );
    if (!codeRows.length) {
      await sendTgNotification(tgUserId,
        '🤔 Код не найден. Сгенерируйте новый в профиле Сада.');
      return;
    }
    const codeRow = codeRows[0];
    if (codeRow.consumed_at) {
      await sendTgNotification(tgUserId,
        '⌛️ Этот код уже использован. Сгенерируйте новый в профиле Сада.');
      return;
    }
    if (new Date(codeRow.expires_at) < new Date()) {
      await sendTgNotification(tgUserId,
        '⌛️ Код истёк (срок жизни — 15 минут). Сгенерируйте новый в профиле Сада.');
      return;
    }

    // 4. Q7 — этот TG уже привязан к ДРУГОМУ профилю?
    const { rows: existingTg } = await pool.query(
      `select id from public.profiles where telegram_user_id = $1 limit 1`,
      [tgUserId]
    );
    if (existingTg.length && existingTg[0].id !== codeRow.profile_id) {
      await sendTgNotification(tgUserId,
        '⚠️ Этот Telegram уже привязан к другому профилю Сада. Сначала отвяжите его там (в карточке профиля кнопка «Отвязать Telegram»), потом сгенерируйте новый код.');
      // Код НЕ консумируем — может попробовать после unlink.
      return;
    }

    // 5. Привязка транзакционно: UPDATE profiles + UPDATE tg_link_codes.
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `update public.profiles
            set telegram_user_id = $1,
                telegram_linked_at = now()
          where id = $2`,
        [tgUserId, codeRow.profile_id]
      );
      await client.query(
        `update public.tg_link_codes
            set consumed_at = now(),
                consumed_by_tg_user_id = $1
          where code = $2`,
        [tgUserId, code]
      );
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    // 6. Подтверждение.
    await sendTgNotification(tgUserId,
      '✅ Готово! Теперь буду писать сюда о том, что происходит с домашними заданиями! Тихие часы: 23:00–08:00 МСК, в это время сообщения копятся и приходят утром.');
  } catch (e) {
    logClientError({
      ts: new Date().toISOString(),
      level: 'tg-update-handler-error',
      error: String(e?.message || e),
    });
  }
};

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
  // Email — строчный с момента входа в систему: один источник истины для
  // users_auth, profiles, JWT, ответа и TG-уведомления. Тот же паттерн, что
  // в /auth/request-reset, иначе регистрозависимость переедет в profiles.email.
  const normalizedEmail = String(email).trim().toLowerCase();
  try {
    const existing = await pool.query('select id from public.users_auth where email = $1', [normalizedEmail]);
    if (existing.rows.length) return res.status(409).json({ error: 'User already exists' });

    const id = uuidv4();
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      'insert into public.users_auth (id, email, password_hash, status) values ($1,$2,$3,$4)',
      [id, normalizedEmail, hash, 'active']
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
      [id, normalizedEmail, name || null, city || null,
       'applicant', 'suspended', 'pending_approval', 0,
       dob || null, tree || null, tree_desc || treeDesc || null,
       x ?? null, y ?? null]
    );

    const token = signToken({ sub: id, email: normalizedEmail });
    res.json({
      token,
      user: { id, email: normalizedEmail, name, city, role: 'applicant', access_status: 'pending_approval' }
    });

    // FEAT-023 Phase 2: TG-уведомление админу о новой регистрации.
    // Fire-and-forget: не блокируем регистрацию если TG лагает / не настроен.
    notifyNewRegistration({ id, name, email: normalizedEmail, city }).catch((e) => {
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
  // Email регистронезависим на входе: лукап и JWT по строчному значению —
  // тот же источник истины, что и в register/request-reset. users_auth.email
  // в проде весь строчный, поэтому нормализация ввода никого не ломает.
  const normalizedEmail = String(email).trim().toLowerCase();
  try {
    const { rows } = await pool.query('select id, password_hash, status from public.users_auth where email = $1', [normalizedEmail]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    if (user.status !== 'active') return res.status(403).json({ error: 'Account suspended' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const profile = await pool.query('select * from public.profiles where id = $1', [user.id]);
    const token = signToken({ sub: user.id, email: normalizedEmail });
    res.json({ token, user: profile.rows[0] || { id: user.id, email: normalizedEmail } });
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

// FEAT-024 — генерация одноразового LINK-кода для привязки TG.
app.post('/api/profile/generate-tg-link-code', authMiddleware, async (req, res) => {
  try {
    // Гасим прошлые активные коды этого юзера — на один профиль не больше
    // одного «живого» неконсумированного кода.
    await pool.query(
      `update public.tg_link_codes
          set consumed_at = now()
        where profile_id = $1 and consumed_at is null and expires_at > now()`,
      [req.user.sub]
    );

    // Retry на коллизию PK (вероятность мизерная, 31^6 = ~887M).
    let code = null;
    for (let attempt = 0; attempt < 5 && !code; attempt++) {
      const candidate = generateLinkCode();
      try {
        await pool.query(
          `insert into public.tg_link_codes (code, profile_id) values ($1, $2)`,
          [candidate, req.user.sub]
        );
        code = candidate;
      } catch (e) {
        if (e.code !== '23505') throw e; // 23505 = unique_violation, retry
      }
    }
    if (!code) {
      return res.status(500).json({ error: 'Failed to allocate link code' });
    }

    return res.json({
      code,
      deep_link: `https://t.me/${TG_NOTIF_BOT_USERNAME}?start=${code}`,
      expires_in_seconds: 15 * 60,
    });
  } catch (e) {
    console.error('generate-tg-link-code error', e);
    return res.status(500).json({ error: e.message });
  }
});

// FEAT-024 — отвязка TG (по кнопке «Отвязать Telegram» в UI).
app.post('/api/profile/unlink-telegram', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `update public.profiles
          set telegram_user_id = null,
              telegram_linked_at = null,
              telegram_notifications_enabled = true
        where id = $1`,
      [req.user.sub]
    );
    return res.json({ ok: true });
  } catch (e) {
    console.error('unlink-telegram error', e);
    return res.status(500).json({ error: e.message });
  }
});

app.post('/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const normalizedEmail = String(email).trim().toLowerCase();
    const { rows } = await pool.query('select id from public.users_auth where email = $1', [normalizedEmail]);
    if (!rows.length) {
      console.info(`[request-reset] unknown email: ${normalizedEmail}`);
      return res.json({ ok: true });  // silent ok для anti-enum (FEAT-025-INFO-DISCLOSURE-FIX)
    }

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

// FEAT-024 worker — vacuum tg_notifications_queue, send to TG with backoff.
// Запускается setInterval каждые 15с. SKIP LOCKED защищает от двойной
// обработки (даже если случайно запустим два инстанса garden-auth).
// Бэкофф: 1→1м, 2→2м, 3→4м, 4→8м, 5→16м; после 5 attempts — dead_letter.
const TG_QUEUE_INTERVAL_MS = 15_000;
const TG_QUEUE_BATCH_SIZE = 50;
const TG_QUEUE_MAX_ATTEMPTS = 5;

const computeBackoffMs = (attempts) => Math.pow(2, attempts - 1) * 60_000;

const processTgQueueBatch = async () => {
  if (!TG_NOTIF_API_BASE) return; // бот не настроен — silent skip
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `select id, recipient_profile_id, recipient_tg_user_id,
              event_type, message_text, attempt_count
         from public.tg_notifications_queue
        where sent_at is null
          and dead_letter_at is null
          and scheduled_for <= now()
        order by scheduled_for asc
        limit $1
        for update skip locked`,
      [TG_QUEUE_BATCH_SIZE]
    );
    if (rows.length === 0) {
      await client.query('COMMIT');
      return;
    }

    for (const row of rows) {
      const result = await sendTgNotification(row.recipient_tg_user_id, row.message_text);
      const nextAttempts = (row.attempt_count || 0) + 1;
      if (result.ok) {
        await client.query(
          `update public.tg_notifications_queue
              set sent_at = now(),
                  attempt_count = $2,
                  last_attempt_at = now(),
                  last_error = null
            where id = $1`,
          [row.id, nextAttempts]
        );
        continue;
      }
      const errText = `${result.code}: ${String(result.detail || '').slice(0, 200)}`;
      if (result.terminal) {
        await client.query(
          `update public.tg_notifications_queue
              set dead_letter_at = now(),
                  attempt_count = $2,
                  last_attempt_at = now(),
                  last_error = $3
            where id = $1`,
          [row.id, nextAttempts, errText]
        );
        if (result.code === 'blocked_by_user') {
          // 403 → юзер заблокировал бота → выключаем нотификации в профиле
          // (когда сделает /start снова — unlink сбросит флаг обратно).
          await client.query(
            `update public.profiles
                set telegram_notifications_enabled = false
              where telegram_user_id = $1`,
            [row.recipient_tg_user_id]
          );
        }
        continue;
      }
      // Transient → backoff или dead-letter если достигли max.
      if (nextAttempts >= TG_QUEUE_MAX_ATTEMPTS) {
        await client.query(
          `update public.tg_notifications_queue
              set dead_letter_at = now(),
                  attempt_count = $2,
                  last_attempt_at = now(),
                  last_error = $3
            where id = $1`,
          [row.id, nextAttempts, `max_attempts: ${errText}`]
        );
      } else {
        const backoff = computeBackoffMs(nextAttempts);
        await client.query(
          `update public.tg_notifications_queue
              set attempt_count = $2,
                  last_attempt_at = now(),
                  last_error = $3,
                  scheduled_for = now() + ($4 || ' milliseconds')::interval
            where id = $1`,
          [row.id, nextAttempts, errText, String(backoff)]
        );
      }
    }
    await client.query('COMMIT');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    console.error('[tg-queue] batch error', e);
  } finally {
    client.release();
  }
};

setInterval(() => {
  processTgQueueBatch().catch((e) => console.error('[tg-queue] unhandled', e));
}, TG_QUEUE_INTERVAL_MS).unref();

// FEAT-024 / TG-WEBHOOK-INBOUND-BLOCKED (2026-05-19) — long-polling вместо
// webhook. Timeweb блокирует inbound к 5.129.251.56:443 для TG IP-ranges
// (требования РКН), outbound к api.telegram.org работает через IPv4-only
// (см. 2026-05-10 lesson про happy-eyeballs).
let tgPollOffset = 0;
const TG_POLL_INTERVAL_MS = 2000;
const TG_POLL_TIMEOUT_S = 25; // long-poll: TG держит запрос до 25с, экономит трафик

const pollTgUpdates = async () => {
  if (!TG_NOTIF_API_BASE) return; // бот не настроен — silent skip
  try {
    const url = `${TG_NOTIF_API_BASE}/getUpdates?offset=${tgPollOffset}&limit=100&timeout=${TG_POLL_TIMEOUT_S}&allowed_updates=${encodeURIComponent('["message"]')}`;
    const res = await httpsGetJson(url, (TG_POLL_TIMEOUT_S + 5) * 1000);
    if (!res.ok || !res.data || !Array.isArray(res.data.result)) {
      // 409 Conflict — включён webhook ИЛИ другой instance polling'ит.
      // Громкий лог чтобы оператор заметил.
      if (res.status === 409) {
        console.error('[tg-poll] 409 Conflict — webhook still active OR multiple pollers', res.text?.slice(0, 200));
      } else {
        console.error('[tg-poll] unexpected response', res.status, res.text?.slice(0, 200));
      }
      return;
    }
    const updates = res.data.result;
    if (updates.length === 0) return;

    for (const update of updates) {
      try {
        await processTgUpdate(update);
      } catch (e) {
        console.error('[tg-poll] handler error for update_id=' + update.update_id, e);
      }
      tgPollOffset = update.update_id + 1;
    }
  } catch (e) {
    console.error('[tg-poll] unhandled', e);
  }
};

// Рекурсивный setTimeout (не setInterval!) гарантирует ровно ОДИН
// in-flight getUpdates: следующий вызов планируется только ПОСЛЕ возврата
// предыдущего. setInterval с интервалом меньше TG_POLL_TIMEOUT_S создавал
// бы N параллельных long-poll запросов, TG возвращал бы 409 Conflict
// "make sure that only one bot instance is running" (см. лог 2026-05-19
// перед фиксом этого паттерна).
const pollTgLoop = async () => {
  await pollTgUpdates();
  setTimeout(pollTgLoop, TG_POLL_INTERVAL_MS).unref();
};

if (TG_NOTIF_API_BASE) {
  setTimeout(pollTgLoop, 1000).unref();
}

app.listen(PORT || 3001, () => {
  console.log(`Auth server running on port ${PORT || 3001}`);
});
