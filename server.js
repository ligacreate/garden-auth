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
  PORT
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

const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });

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

app.post('/auth/register', async (req, res) => {
  const { email, password, name, city } = req.body || {};
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

    await pool.query(
      `insert into public.profiles (id, email, name, city, role, status, seeds)
       values ($1,$2,$3,$4,$5,$6,$7)
       on conflict (id) do update set email=excluded.email, name=excluded.name, city=excluded.city`,
      [id, email, name || null, city || null, 'applicant', 'active', 0]
    );

    const token = signToken({ sub: id, email });
    res.json({ token, user: { id, email, name, city, role: 'applicant' } });
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
    const { rows } = await pool.query('select id from public.users_auth where email = $1', [email]);
    if (!rows.length) return res.json({ ok: true });

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min

    await pool.query(
      'update public.users_auth set reset_token=$1, reset_expires=$2 where email=$3',
      [tokenHash, expires, email]
    );

    if (transporter) {
      const resetUrl = `${PUBLIC_URL}/reset?token=${rawToken}`;
      await transporter.sendMail({
        from: SMTP_FROM,
        to: email,
        subject: 'Восстановление пароля',
        text: `Ссылка для сброса пароля: ${resetUrl}`
      });
    }

    res.json({ ok: true });
  } catch (e) {
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
