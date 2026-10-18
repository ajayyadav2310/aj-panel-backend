'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const Razorpay = require('razorpay');

const app = express();
const PORT = process.env.PORT || 10000;
const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  'https://tourmaline-sorbet-d89e38.netlify.app'
).replace(/\/+$/, '');

app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:5173'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
}));
app.use(express.json({ limit: '1mb' }));

const supabase = process.env.SUPABASE_URL &&
  process.env.SUPABASE_ANON_KEY
  ? createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    )
  : null;

const db = process.env.SUPABASE_URL &&
  process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      { auth: { persistSession: false } }
    )
  : null;

const razorpay = process.env.RAZORPAY_KEY_ID &&
  process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET
    })
  : null;

function error(res, status, message) {
  return res.status(status).json({ ok: false, error: message });
}

function configured(req, res, next) {
  if (!supabase || !db) {
    return error(res, 503, 'Supabase environment variables missing.');
  }
  next();
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
      ? header.slice(7).trim()
      : '';

    if (!token) return error(res, 401, 'Please log in first.');

    const { data, error: authError } =
      await supabase.auth.getUser(token);

    if (authError || !data.user) {
      return error(res, 401, 'Invalid or expired session.');
    }

    req.user = data.user;
    next();
  } catch (e) {
    error(res, 500, 'Authentication failed.');
  }
}

async function admin(req, res, next) {
  try {
    const { data, error: e } = await db
      .from('profiles')
      .select('role')
      .eq('id', req.user.id)
      .maybeSingle();

    if (e) return error(res, 500, 'Could not verify admin role.');
    if (data?.role !== 'admin') {
      return error(res, 403, 'Admin access required.');
    }
    next();
  } catch (e) {
    error(res, 500, 'Admin verification failed.');
  }
}

const protectedRoute = (...handlers) =>
  [configured, auth, ...handlers];

async function wallet(userId) {
  const { data, error: e } = await db
    .from('wallets')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle();

  if (e) throw e;
  return data || { user_id: userId, balance: 0 };
}

async function settings() {
  const { data, error: e } = await db
    .from('site_settings')
    .select('*')
    .limit(1)
    .maybeSingle();

  if (e) throw e;
  return data || {};
}

app.get('/', (req, res) => {
  res.send('AJ Panel API is running.');
});

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'AJ Panel API' });
});

app.get('/api/config', (req, res) => {
  res.json({
    ok: Boolean(supabase && db),
    supabaseUrl: process.env.SUPABASE_URL || '',
    supabaseAnonKey: process.env.SUPABASE_ANON_KEY || '',
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || ''
  });
});

app.post('/api/auth/signup', configured, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!email.includes('@') || password.length < 6) {
      return error(res, 400, 'Enter a valid email and password.');
    }

    const { data, error: e } = await supabase.auth.signUp({
      email,
      password
    });

    if (e) return error(res, 400, e.message);
    res.status(201).json({ ok: true, user: data.user });
  } catch (e) {
    error(res, 500, 'Signup failed.');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    if (!supabase) return error(res, 503, 'Supabase is not configured.');

    const { email, password } = req.body || {};
    const { data, error: e } =
      await supabase.auth.signInWithPassword({ email, password });

    if (e) return error(res, 401, e.message);
    res.json({ ok: true, user: data.user, session: data.session });
  } catch (e) {
    error(res, 500, 'Login failed.');
  }
});

app.get('/api/me', ...protectedRoute(), async (req, res) => {
  try {
    let { data: profile, error: e } = await db
      .from('profiles')
      .select('*')
      .eq('id', req.user.id)
      .maybeSingle();

    if (e) throw e;

    if (!profile) {
      const result = await db.from('profiles').insert({
        id: req.user.id,
        email: req.user.email,
        role: 'user'
      }).select('*').single();

      if (result.error) throw result.error;
      profile = result.data;
    }

    const userWallet = await wallet(req.user.id);

    res.json({
      ok: true,
      id: req.user.id,
      email: req.user.email,
      role: profile.role || 'user',
      isAdmin: profile.role === 'admin',
      user: { id: req.user.id, email: req.user.email },
      profile,
      wallet: userWallet
    });
  } catch (e) {
    console.error(e.message);
    error(res, 500, 'Could not load profile. Check database columns.');
  }
});

app.get('/api/settings/public', async (req, res) => {
  try {
    if (!db) return error(res, 503, 'Supabase is not configured.');
    const s = await settings();
    res.json({ ok: true, ...s, settings: s });
  } catch (e) {
    error(res, 500, 'Could not load public settings.');
  }
});

app.get('/api/dashboard', ...protectedRoute(), async (req, res) => {
  try {
    const w = await wallet(req.user.id);

    const { data: orders, error: oe } = await db
      .from('orders')
      .select('charge')
      .eq('user_id', req.user.id);

    if (oe) throw oe;

    const { count, error: se } = await db
      .from('services')
      .select('*', { count: 'exact', head: true })
      .eq('active', true);

    if (se) throw se;

    res.json({
      ok: true,
      balance: Number(w.balance || 0),
      orderCount: orders.length,
      spent: orders.reduce((sum, o) => sum + Number(o.charge || 0), 0),
      serviceCount: count || 0
    });
  } catch (e) {
    error(res, 500, 'Could not load dashboard.');
  }
});

app.get('/api/services', async (req, res) => {
  try {
    if (!db) return error(res, 503, 'Supabase is not configured.');

    const { data, error: e } = await db
      .from('services')
      .select('*')
      .eq('active', true)
      .order('id');

    if (e) throw e;
    res.json(data || []);
  } catch (e) {
    error(res, 500, 'Could not load services.');
  }
});

app.get('/api/orders', ...protectedRoute(), async (req, res) => {
  try {
    const { data, error: e } = await db
      .from('orders')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (e) throw e;
    res.json(data || []);
  } catch (e) {
    error(res, 500, 'Could not load orders.');
  }
});

app.get('/api/wallet', ...protectedRoute(), async (req, res) => {
  try {
    const w = await wallet(req.user.id);
    const { data, error: e } = await db
      .from('wallet_transactions')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(100);

    if (e) throw e;
    res.json({
      ok: true,
      balance: Number(w.balance || 0),
      wallet: w,
      transactions: data || []
    });
  } catch (e) {
    error(res, 500, 'Could not load wallet.');
  }
});

app.get('/api/admin/overview',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const tables = ['profiles', 'orders', 'services', 'payment_transactions'];
      const counts = {};

      for (const table of tables) {
        const { count, error: e } = await db
          .from(table)
          .select('*', { count: 'exact', head: true });

        if (e) throw e;
        counts[table] = count || 0;
      }

      res.json({
        ok: true,
        users: counts.profiles,
        orders: counts.orders,
        services: counts.services,
        payments: counts.payment_transactions
      });
    } catch (e) {
      error(res, 500, 'Could not load admin overview.');
    }
  }
);

app.get('/api/admin/services',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const { data, error: e } = await db
        .from('services')
        .select('*')
        .order('id', { ascending: false });

      if (e) throw e;
      res.json(data || []);
    } catch (e) {
      error(res, 500, 'Could not load admin services.');
    }
  }
);

app.post('/api/admin/services',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const b = req.body || {};
      if (!String(b.name || '').trim() || Number(b.rate) < 0) {
        return error(res, 400, 'Enter service name and rate.');
      }

      const payload = {
        name: String(b.name).trim(),
        category: b.category || 'General',
        description: b.description || '',
        rate: Number(b.rate),
        min_qty: Number(b.min_qty || 1),
        max_qty: Number(b.max_qty || 1000000),
        active: b.active !== false,
        provider_service_id: b.provider_service_id || null
      };

      const { data, error: e } = await db
        .from('services')
        .insert(payload)
        .select('*')
        .single();

      if (e) throw e;
      res.status(201).json(data);
    } catch (e) {
      error(res, 500, 'Could not create service. Check table columns.');
    }
  }
);

app.put('/api/admin/services/:id',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const allowed = [
        'name', 'category', 'description', 'rate',
        'min_qty', 'max_qty', 'active', 'provider_service_id'
      ];
      const payload = {};

      for (const key of allowed) {
        if (req.body?.[key] !== undefined) payload[key] = req.body[key];
      }

      const { data, error: e } = await db
        .from('services')
        .update(payload)
        .eq('id', req.params.id)
        .select('*')
        .single();

      if (e) throw e;
      res.json(data);
    } catch (e) {
      error(res, 500, 'Could not update service.');
    }
  }
);

app.get('/api/admin/orders',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const { data, error: e } = await db
        .from('orders')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(500);

      if (e) throw e;
      res.json(data || []);
    } catch (e) {
      error(res, 500, 'Could not load admin orders.');
    }
  }
);

app.patch('/api/admin/orders/:id',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const allowed = [
        'pending', 'processing', 'completed',
        'partial', 'cancelled', 'failed'
      ];
      const status = String(req.body?.status || '').toLowerCase();

      if (!allowed.includes(status)) {
        return error(res, 400, 'Invalid order status.');
      }

      const { data, error: e } = await db
        .from('orders')
        .update({ status })
        .eq('id', req.params.id)
        .select('*')
        .single();

      if (e) throw e;
      res.json({ ok: true, order: data });
    } catch (e) {
      error(res, 500, 'Could not update order.');
    }
  }
);

app.get('/api/admin/settings',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const s = await settings();
      res.json({ ok: true, ...s, settings: s });
    } catch (e) {
      error(res, 500, 'Could not load settings.');
    }
  }
);

app.put('/api/admin/settings',
  ...protectedRoute(admin), async (req, res) => {
    try {
      const b = req.body || {};
      const { data: old, error: readError } = await db
        .from('site_settings')
        .select('id')
        .limit(1)
        .maybeSingle();

      if (readError) throw readError;

      const payload = {
        theme: b.theme || 'green',
        whatsapp_url: b.whatsapp_url || '',
        telegram_url: b.telegram_url || '',
        payment_label: b.payment_label || 'Razorpay'
      };

      const result = old?.id
        ? await db.from('site_settings').update(payload)
            .eq('id', old.id).select('*').single()
        : await db.from('site_settings').insert(payload)
            .select('*').single();

      if (result.error) throw result.error;
      res.json({ ok: true, ...result.data, settings: result.data });
    } catch (e) {
      error(res, 500, 'Could not save settings.');
    }
  }
);

app.get('/api/payments/key', ...protectedRoute(), (req, res) => {
  res.json({ ok: true, key: process.env.RAZORPAY_KEY_ID || '' });
});

app.post('/api/payments/create',
  ...protectedRoute(), async (req, res) => {
    try {
      if (!razorpay) return error(res, 503, 'Razorpay is not configured.');

      const amount = Number(req.body?.amount);
      if (!Number.isFinite(amount) || amount < 10 || amount > 50000) {
        return error(res, 400, 'Amount must be ₹10–₹50,000.');
      }

      const order = await razorpay.orders.create({
        amount: Math.round(amount * 100),
        currency: 'INR',
        receipt: `aj_${Date.now()}`,
        notes: { user_id: req.user.id }
      });

      const { error: e } = await db.from('payment_transactions').insert({
        user_id: req.user.id,
        amount,
        status: 'created',
        razorpay_order_id: order.id
      });

      if (e) throw e;
      res.json({
        ok: true,
        razorpayOrderId: order.id,
        amount: order.amount,
        currency: order.currency
      });
    } catch (e) {
      error(res, 500, 'Could not create payment order.');
    }
  }
);

app.post('/api/payments/verify',
  ...protectedRoute(), async (req, res) => {
    try {
      const secret = process.env.RAZORPAY_KEY_SECRET;
      if (!secret) return error(res, 503, 'Razorpay is not configured.');

      const orderId = String(req.body?.razorpay_order_id || '');
      const paymentId = String(req.body?.razorpay_payment_id || '');
      const signature = String(req.body?.razorpay_signature || '');

      if (!orderId || !paymentId || !signature) {
        return error(res, 400, 'Missing payment verification fields.');
      }

      const expected = crypto.createHmac('sha256', secret)
        .update(`${orderId}|${paymentId}`)
        .digest('hex');

      const a = Buffer.from(expected);
      const b = Buffer.from(signature);

      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return error(res, 400, 'Invalid payment signature.');
      }

      const { data: tx, error: e } = await db
        .from('payment_transactions')
        .select('*')
        .eq('user_id', req.user.id)
        .eq('razorpay_order_id', orderId)
        .maybeSingle();

      if (e || !tx) return error(res, 404, 'Payment record not found.');
      if (['paid', 'completed'].includes(tx.status)) {
        return res.json({ ok: true, message: 'Already verified.' });
      }

      const { error: updateError } = await db
        .from('payment_transactions')
        .update({
          status: 'paid',
          razorpay_payment_id: paymentId
        })
        .eq('razorpay_order_id', orderId)
        .eq('user_id', req.user.id);

      if (updateError) throw updateError;

      const w = await wallet(req.user.id);
      const { error: walletError } = await db.from('wallets').upsert({
        user_id: req.user.id,
        balance: Number(w.balance || 0) + Number(tx.amount || 0)
      }, { onConflict: 'user_id' });

      if (walletError) throw walletError;

      await db.from('wallet_transactions').insert({
        user_id: req.user.id,
        type: 'deposit',
        amount: Number(tx.amount || 0),
        status: 'completed',
        description: `Razorpay payment ${paymentId}`
      });

      res.json({ ok: true, message: 'Payment verified.' });
    } catch (e) {
      console.error('Payment verification:', e.message);
      error(res, 500, 'Payment verification failed.');
    }
  }
);

app.use((req, res) => {
  error(res, 404, `Route not found: ${req.method} ${req.path}`);
});

app.use((err, req, res, next) => {
  console.error(err.message);
  if (res.headersSent) return next(err);
  error(res, 500, 'Internal server error.');
});

app.listen(PORT, () => {
  console.log(`AJ Panel API listening on ${PORT}`);
});
