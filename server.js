'use strict';

/*
 AJ Panel backend for Render + Supabase
 Node.js 20+
 Required environment variables:
   SUPABASE_URL
   SUPABASE_ANON_KEY
   SUPABASE_SERVICE_ROLE_KEY  (keep secret; Render only)
 Optional:
   FRONTEND_URL=https://tourmaline-sorbet-d89e38.netlify.app
   RAZORPAY_KEY_ID
   RAZORPAY_KEY_SECRET
   SMM_PROVIDER_URL=https://smmkings.com/api/v2
   SMMKINGS_API_KEY (or SMM_PROVIDER_KEY)

 IMPORTANT:
 - Never put SUPABASE_SERVICE_ROLE_KEY or RAZORPAY_KEY_SECRET in frontend code.
 - This server implements AJ Panel's API routes. SMMKings order submission and status refresh are implemented; verify provider credentials, service IDs, and database columns before live orders.
*/

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const Razorpay = require('razorpay');

const app = express();
const PORT = Number(process.env.PORT || 10000);
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

const FRONTEND_URL = String(
  process.env.FRONTEND_URL || 'https://tourmaline-sorbet-d89e38.netlify.app'
).replace(/\/+$/, '');

const allowedOrigins = new Set([
  FRONTEND_URL,
  'http://localhost:3000',
  'http://localhost:5173'
]);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseSecretKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = supabaseUrl && supabaseAnonKey
  ? createClient(supabaseUrl, supabaseAnonKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;

const db = supabaseUrl && supabaseSecretKey
  ? createClient(supabaseUrl, supabaseSecretKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;

const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET
    })
  : null;

function fail(res, status, message) {
  return res.status(status).json({ ok: false, error: message });
}
function asNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}
function money(value) {
  return Math.round(asNumber(value) * 100) / 100;
}
function normalizeService(s) {
  if (!s) return s;
  return {
    ...s,
    min_qty: s.min_qty ?? s.min_quantity ?? 1,
    max_qty: s.max_qty ?? s.max_quantity ?? 1000000,
    provider_service_id: s.provider_service_id ?? s.providerServiceId ?? null
  };
}
function normalizeOrder(o) {
  if (!o) return o;
  return {
    ...o,
    service_name: o.service_name ?? o.services?.name ?? 'Service',
    target_url: o.target_url ?? o.link ?? '',
    charge: money(o.charge)
  };
}
function requireConfig(req, res, next) {
  if (!supabase || !db) return fail(res, 503, 'Supabase configuration missing in Render Environment.');
  next();
}
async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!token) return fail(res, 401, 'Please sign in first.');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) return fail(res, 401, 'Invalid or expired login session.');
    req.user = data.user;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    return fail(res, 500, 'Authentication failed.');
  }
}
async function getProfile(userId) {
  const { data, error } = await db.from('profiles').select('*').eq('id', userId).maybeSingle();
  if (error) throw error;
  return data || null;
}
async function isAdminUser(userId) {
  const profile = await getProfile(userId);
  return profile?.role === 'admin';
}
async function adminOnly(req, res, next) {
  try {
    if (!(await isAdminUser(req.user.id))) return fail(res, 403, 'Admin access required.');
    next();
  } catch (error) {
    console.error('Admin role lookup:', error.message);
    return fail(res, 500, 'Could not verify admin role.');
  }
}
function protectedRoute(...handlers) {
  return [requireConfig, auth, ...handlers];
}
async function getWallet(userId) {
  const { data, error } = await db.from('wallets').select('*').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data || { user_id: userId, balance: 0 };
}
async function getSettings() {
  const { data, error } = await db.from('site_settings').select('*').limit(1).maybeSingle();
  if (error) throw error;
  return data || {};
}
async function walletTransactions(userId) {
  const { data, error } = await db.from('wallet_transactions').select('*')
    .eq('user_id', userId).order('created_at', { ascending: false }).limit(100);
  if (error) {
    // Some installations may use a different ledger schema; surface a clear error.
    throw error;
  }
  return data || [];
}
async function insertWalletTransaction(payload) {
  const { error } = await db.from('wallet_transactions').insert(payload);
  if (error) throw error;
}
async function updateWalletBalance(userId, delta) {
  // The database should use a transaction/RPC for high-volume payments. This
  // guarded read/update is suitable for a small test panel, not concurrent billing.
  const current = await getWallet(userId);
  const oldBalance = asNumber(current.balance);
  const newBalance = money(oldBalance + delta);
  if (newBalance < 0) throw new Error('Insufficient wallet balance.');
  const { data, error } = await db.from('wallets').upsert(
    { user_id: userId, balance: newBalance },
    { onConflict: 'user_id' }
  ).select('*').single();
  if (error) throw error;
  return data;
}

// SMMKings standard API v2. Credentials are read only from Render environment.
const SMMKINGS_URL = String(process.env.SMM_PROVIDER_URL || 'https://smmkings.com/api/v2').trim();
const SMMKINGS_KEY = String(process.env.SMMKINGS_API_KEY || process.env.SMM_PROVIDER_KEY || '').trim();
async function smmKingsRequest(params) {
  if (!SMMKINGS_KEY) throw new Error('SMMKings API key is not configured on Render.');
  const body = new URLSearchParams({ key: SMMKINGS_KEY, ...params });
  const response = await fetch(SMMKINGS_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(20000)
  });
  const raw = await response.text();
  let data;
  try { data = JSON.parse(raw); } catch { throw new Error('SMMKings returned a non-JSON response.'); }
  if (!response.ok) throw new Error(`SMMKings HTTP ${response.status}`);
  if (data && !Array.isArray(data) && data.error) throw new Error(String(data.error));
  return data;
}
function mapProviderStatus(value) {
  const status = String(value || 'pending').trim().toLowerCase();
  if (status === 'completed' || status === 'complete') return 'completed';
  if (status === 'partial') return 'partial';
  if (status === 'canceled' || status === 'cancelled') return 'cancelled';
  if (status === 'failed' || status === 'rejected') return 'failed';
  if (status === 'in progress' || status === 'in_progress' || status === 'processing') return 'processing';
  return 'pending';
}

// Basic health checks
app.get('/', (req, res) => res.type('text').send('AJ Panel API is running. Frontend is hosted on Netlify.'));
app.get('/health', (req, res) => res.json({ ok: true, service: 'AJ Panel API' }));

// Public config: only public Supabase URL/key and Razorpay public key are exposed.
app.get('/api/config', (req, res) => {
  const missing = [];
  if (!supabaseUrl) missing.push('SUPABASE_URL');
  if (!supabaseAnonKey) missing.push('SUPABASE_ANON_KEY');
  if (!supabaseSecretKey) missing.push('SUPABASE_SERVICE_ROLE_KEY');
  res.json({
    ok: missing.length === 0,
    supabaseUrl: supabaseUrl || '',
    supabaseAnonKey: supabaseAnonKey || '',
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || '',
    missing
  });
});

// Public site settings
app.get('/api/settings/public', async (req, res) => {
  try {
    if (!db) return fail(res, 503, 'Supabase configuration missing.');
    const settings = await getSettings();
    res.json({
      ok: true,
      ...settings,
      settings,
      theme: settings.theme || 'green',
      whatsapp_url: settings.whatsapp_url || '',
      telegram_url: settings.telegram_url || '',
      payment_label: settings.payment_label || 'Razorpay',
      payment_method: settings.payment_method || 'razorpay',
      upi_id: settings.upi_id || '',
      upi_qr_url: settings.upi_qr_url || '',
      site_name: settings.site_name || 'AJ Panel',
      announcement: settings.announcement || ''
    });
  } catch (error) {
    console.error('Public settings error:', error.message);
    return fail(res, 500, 'Could not load public settings. Check site_settings columns.');
  }
});

// Signup and login routes are available for API clients. The supplied frontend
// uses Supabase Auth directly.
app.post('/api/auth/signup', requireConfig, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email.includes('@')) return fail(res, 400, 'Enter a valid email address.');
    if (password.length < 6) return fail(res, 400, 'Password must be at least 6 characters.');
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) return fail(res, 400, error.message);
    res.json({ ok: true, user: data.user, session: data.session });
  } catch (error) {
    return fail(res, 500, 'Signup failed.');
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    if (!supabase) return fail(res, 503, 'Supabase configuration missing.');
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return fail(res, 400, 'Enter email and password.');
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return fail(res, 401, error.message);
    res.json({ ok: true, user: data.user, session: data.session });
  } catch (error) {
    return fail(res, 500, 'Login failed.');
  }
});
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    if (!supabase) return fail(res, 503, 'Supabase configuration missing.');
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email.includes('@')) return fail(res, 400, 'Enter a valid email address.');
    const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: FRONTEND_URL });
    if (error) return fail(res, 400, error.message);
    res.json({ ok: true, message: 'If registered, a password reset email will be sent.' });
  } catch (error) {
    return fail(res, 500, 'Password reset failed.');
  }
});

// Current user. Provides both top-level role/isAdmin and nested profile for UI compatibility.
app.get('/api/me', ...protectedRoute(), async (req, res) => {
  try {
    let profile = await getProfile(req.user.id);
    if (!profile) {
      // Repair a missing profile row for an already-authenticated account.
      const { data, error } = await db.from('profiles')
        .upsert({ id: req.user.id, email: req.user.email, role: 'user' }, { onConflict: 'id' })
        .select('*').single();
      if (error) {
        console.error('Profile auto-create failed:', error.message);
        return fail(res, 500, 'Profile is missing and could not be created. Check profiles table columns/trigger.');
      }
      profile = data;
    }
    let wallet;
    try {
      wallet = await getWallet(req.user.id);
    } catch (error) {
      console.error('Wallet lookup:', error.message);
      wallet = { user_id: req.user.id, balance: 0 };
    }
    res.json({
      ok: true,
      id: req.user.id,
      email: req.user.email,
      role: profile.role || 'user',
      isAdmin: profile.role === 'admin',
      user: { id: req.user.id, email: req.user.email },
      profile,
      wallet,
      balance: asNumber(wallet.balance)
    });
  } catch (error) {
    console.error('Profile error:', error.message);
    return fail(res, 500, 'Could not load profile.');
  }
});

// Active services. Returns an array because the frontend expects services.map(...).
app.get('/api/services', ...protectedRoute(), async (req, res) => {
  try {
    const { data, error } = await db.from('services').select('*').eq('active', true).order('id');
    if (error) return fail(res, 500, 'Could not load services. Check services table columns.');
    res.json((data || []).map(normalizeService));
  } catch (error) {
    return fail(res, 500, 'Could not load services.');
  }
});

// Dashboard summary in the exact shape expected by the supplied frontend.
app.get('/api/dashboard', ...protectedRoute(), async (req, res) => {
  try {
    const [wallet, orderResult, serviceResult] = await Promise.all([
      getWallet(req.user.id),
      db.from('orders').select('*').eq('user_id', req.user.id),
      db.from('services').select('id', { count: 'exact', head: true }).eq('active', true)
    ]);
    if (orderResult.error) return fail(res, 500, 'Could not load dashboard orders.');
    if (serviceResult.error) return fail(res, 500, 'Could not load service count.');
    const orders = orderResult.data || [];
    res.json({
      ok: true,
      balance: asNumber(wallet.balance),
      orderCount: orders.length,
      spent: money(orders.filter(o => !['canceled', 'cancelled', 'failed', 'refunded'].includes(String(o.status).toLowerCase()))
        .reduce((sum, o) => sum + asNumber(o.charge), 0)),
      serviceCount: serviceResult.count || 0
    });
  } catch (error) {
    console.error('Dashboard error:', error.message);
    return fail(res, 500, 'Dashboard failed. Check wallet/orders/services schema.');
  }
});

// Wallet + ledger
app.get('/api/wallet', ...protectedRoute(), async (req, res) => {
  try {
    const wallet = await getWallet(req.user.id);
    let transactions = [];
    try { transactions = await walletTransactions(req.user.id); }
    catch (error) { console.error('Wallet ledger lookup:', error.message); }
    res.json({ ok: true, balance: asNumber(wallet.balance), transactions });
  } catch (error) {
    return fail(res, 500, 'Wallet load failed.');
  }
});

// User order history
app.get('/api/orders', ...protectedRoute(), async (req, res) => {
  try {
    const { data, error } = await db.from('orders').select('*')
      .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(100);
    if (error) return fail(res, 500, 'Orders load failed.');
    res.json((data || []).map(normalizeOrder));
  } catch (error) {
    return fail(res, 500, 'Orders load failed.');
  }
});

// Place an order: debit wallet, submit to SMMKings, and refund if provider rejects it.
// For production-scale billing, move debit/order/provider state into a DB RPC/queue.
app.post('/api/orders', ...protectedRoute(), async (req, res) => {
  let localOrder = null;
  let debited = false;
  let charge = 0;
  try {
    const serviceId = req.body?.serviceId ?? req.body?.service_id;
    const quantity = Number(req.body?.quantity);
    const targetUrl = String(req.body?.targetUrl ?? req.body?.target_url ?? req.body?.link ?? '').trim();
    if (!serviceId || !Number.isInteger(quantity) || quantity < 1 || !/^https?:\/\/\S+/i.test(targetUrl)) {
      return fail(res, 400, 'Enter a valid service, quantity and target URL.');
    }
    if (!SMMKINGS_KEY) return fail(res, 503, 'SMMKings API key is not configured on Render.');

    const { data: service, error: serviceError } = await db.from('services')
      .select('*').eq('id', serviceId).eq('active', true).maybeSingle();
    if (serviceError || !service) return fail(res, 400, 'Service not found or inactive.');
    const s = normalizeService(service);
    if (!s.provider_service_id) return fail(res, 400, 'Admin must set the SMMKings service ID for this service first.');
    if (quantity < Number(s.min_qty) || quantity > Number(s.max_qty)) {
      return fail(res, 400, `Quantity must be between ${s.min_qty} and ${s.max_qty}.`);
    }
    charge = money(quantity * asNumber(s.rate) / 1000);
    if (charge <= 0) return fail(res, 400, 'Service charge is invalid.');
    const currentWallet = await getWallet(req.user.id);
    if (asNumber(currentWallet.balance) < charge) return fail(res, 400, 'Insufficient wallet balance. Add amount to wallet.');

    const { data: created, error: createError } = await db.from('orders').insert({
      user_id: req.user.id, service_id: service.id, service_name: service.name,
      quantity, target_url: targetUrl, charge, status: 'submitting', remains: quantity
    }).select('*').single();
    if (createError) {
      console.error('Order insert:', createError.message);
      return fail(res, 500, 'Could not create local order. Check orders table columns.');
    }
    localOrder = created;

    await updateWalletBalance(req.user.id, -charge);
    debited = true;
    await insertWalletTransaction({ user_id: req.user.id, type: 'order', amount: -charge,
      status: 'completed', description: `Order #${localOrder.id}` });

    let providerResult;
    try {
      providerResult = await smmKingsRequest({
        action: 'add', service: String(s.provider_service_id), link: targetUrl, quantity: String(quantity)
      });
    } catch (providerError) {
      console.error('SMMKings order rejected:', providerError.message);
      await updateWalletBalance(req.user.id, charge);
      await insertWalletTransaction({ user_id: req.user.id, type: 'refund', amount: charge,
        status: 'completed', description: `Refund for failed provider submission #${localOrder.id}` });
      await db.from('orders').update({ status: 'failed', remains: quantity }).eq('id', localOrder.id);
      return fail(res, 502, `Provider did not accept the order. Wallet refund attempted. ${providerError.message}`);
    }

    const providerOrderId = providerResult?.order;
    if (!providerOrderId) {
      // A response without an order ID is ambiguous; do not automatically retry or refund.
      await db.from('orders').update({ status: 'pending' }).eq('id', localOrder.id);
      return fail(res, 502, 'SMMKings response had no order ID. Check provider dashboard before retrying.');
    }

    const { data: updated, error: updateError } = await db.from('orders').update({
      provider_order_id: String(providerOrderId), status: 'pending', remains: quantity
    }).eq('id', localOrder.id).select('*').single();
    if (updateError) {
      console.error('Provider accepted order but local update failed:', updateError.message);
      return fail(res, 500, `Provider accepted order ${providerOrderId}, but local record needs admin reconciliation.`);
    }
    return res.status(201).json({ ok: true, order: normalizeOrder(updated), providerOrderId: String(providerOrderId), message: 'Order submitted to SMMKings.' });
  } catch (error) {
    console.error('Order create error:', error.message);
    if (localOrder && debited) {
      // Avoid an automatic second provider submission; leave record for admin review.
      await db.from('orders').update({ status: 'pending' }).eq('id', localOrder.id);
    }
    return fail(res, 500, 'Order could not be completed. Check order history/admin before retrying.');
  }
});

// Refresh a user's order status from SMMKings.
app.post('/api/orders/:id/refresh', ...protectedRoute(), async (req, res) => {
  try {
    const { data: order, error: readError } = await db.from('orders').select('*')
      .eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
    if (readError || !order) return fail(res, 404, 'Order not fou
