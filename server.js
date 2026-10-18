
'use strict';

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json({ limit: '1mb' }));

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  'https://tourmaline-sorbet-d89e38.netlify.app'
).replace(/\/+$/, '');

const allowedOrigins = new Set([
  FRONTEND_URL,
  'http://localhost:3000',
  'http://localhost:5173'
]);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
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

const admin = supabaseUrl && supabaseSecretKey
  ? createClient(supabaseUrl, supabaseSecretKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;

function fail(res, status, message) {
  return res.status(status).json({
    ok: false,
    error: message
  });
}

function requireConfig(req, res, next) {
  if (!supabase || !admin) {
    return fail(
      res,
      503,
      'Supabase configuration missing in Render Environment.'
    );
  }
  next();
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
      ? header.slice(7).trim()
      : '';

    if (!token) {
      return fail(res, 401, 'Please sign in first.');
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data?.user) {
      return fail(res, 401, 'Invalid or expired login session.');
    }

    req.user = data.user;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    return fail(res, 500, 'Authentication failed.');
  }
}

async function adminOnly(req, res, next) {
  try {
    const { data, error } = await admin
      .from('profiles')
      .select('role')
      .eq('id', req.user.id)
      .maybeSingle();

    if (error) {
      console.error('Admin role lookup:', error.message);
      return fail(res, 500, 'Could not verify admin role.');
    }

    if (data?.role !== 'admin') {
      return fail(res, 403, 'Admin access required.');
    }

    next();
  } catch (error) {
    return fail(res, 500, 'Admin check failed.');
  }
}

// Health checks
app.get('/', (req, res) => {
  res.type('text').send(
    'AJ Panel API is running. Frontend is hosted on Netlify.'
  );
});

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'AJ Panel API' });
});

// Frontend configuration
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

// Public site settings — required by frontend
app.get('/api/settings/public', async (req, res) => {
  try {
    if (!admin) {
      return fail(res, 503, 'Supabase configuration missing.');
    }

    const { data, error } = await admin
      .from('site_settings')
      .select('*')
      .limit(1)
      .maybeSingle();

    if (error) {
      console.error('Public settings error:', error.message);
      return fail(res, 500, 'Could not load public settings.');
    }

    res.json({
      ok: true,
      settings: data || {}
    });
  } catch (error) {
    console.error('Settings error:', error.message);
    return fail(res, 500, 'Could not load public settings.');
  }
});

// Signup
app.post('/api/auth/signup', requireConfig, async (req, res) => {
  try {
    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || '');

    if (!email || !email.includes('@')) {
      return fail(res, 400, 'Enter a valid email address.');
    }

    if (password.length < 6) {
      return fail(res, 400, 'Password must be at least 6 characters.');
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password
    });

    if (error) return fail(res, 400, error.message);

    res.json({
      ok: true,
      user: data.user,
      session: data.session,
      message: data.session
        ? 'Account created.'
        : 'Check your email to confirm your account.'
    });
  } catch (error) {
    console.error('Signup error:', error.message);
    return fail(res, 500, 'Signup failed.');
  }
});

// Login
app.post('/api/auth/login', requireConfig, async (req, res) => {
  try {
    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || '');

    if (!email || !password) {
      return fail(res, 400, 'Enter email and password.');
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) return fail(res, 401, error.message);

    res.json({
      ok: true,
      user: data.user,
      session: data.session
    });
  } catch (error) {
    console.error('Login error:', error.message);
    return fail(res, 500, 'Login failed.');
  }
});

// Forgot password
app.post(
  '/api/auth/forgot-password',
  requireConfig,
  async (req, res) => {
    try {
      const email = String(req.body?.email || '')
        .trim()
        .toLowerCase();

      if (!email || !email.includes('@')) {
        return fail(res, 400, 'Enter a valid email address.');
      }

      const { error } = await supabase.auth.resetPasswordForEmail(
        email,
        { redirectTo: FRONTEND_URL }
      );

      if (error) return fail(res, 400, error.message);

      res.json({
        ok: true,
        message: 'If registered, a password reset email will be sent.'
      });
    } catch (error) {
      console.error('Password reset error:', error.message);
      return fail(res, 500, 'Password reset failed.');
    }
  }
);

// Current user and profile
app.get('/api/me', requireConfig, auth, async (req, res) => {
  try {
    const { data: profile, error } = await admin
      .from('profiles')
      .select('*')
      .eq('id', req.user.id)
      .maybeSingle();

    if (error) {
      console.error('Profile lookup:', error.message);
      return fail(res, 500, 'Could not load profile.');
    }

    const { data: wallet, error: walletError } = await admin
      .from('wallets')
      .select('*')
      .eq('user_id', req.user.id)
      .maybeSingle();

    if (walletError) {
      console.error('Wallet lookup:', walletError.message);
    }

    res.json({
      ok: true,
      user: {
        id: req.user.id,
        email: req.user.email
      },
      profile: profile || null,
      wallet: wallet || { balance: 0 }
    });
  } catch (error) {
    console.error('Profile error:', error.message);
    return fail(res, 500, 'Could not load user.');
  }
});

// Active services
app.get('/api/services', requireConfig, async (req, res) => {
  try {
    const { data, error } = await admin
      .from('services')
      .select('*')
      .eq('active', true)
      .order('id');

    if (error) {
      console.error('Services error:', error.message);
      return fail(res, 500, 'Could not load services.');
    }

    res.json({ ok: true, services: data || [] });
  } catch (error) {
    return fail(res, 500, 'Could not load services.');
  }
});

// Dashboard
app.get('/api/dashboard', requireConfig, auth, async (req, res) => {
  try {
    const [walletResult, ordersResult] = await Promise.all([
      admin.from('wallets')
        .select('*')
        .eq('user_id', req.user.id)
        .maybeSingle(),
      admin.from('orders')
        .select('*')
        .eq('user_id', req.user.id)
        .order('created_at', { ascending: false })
        .limit(50)
    ]);

    if (walletResult.error || ordersResult.error) {
      return fail(res, 500, 'Could not load dashboard data.');
    }

    res.json({
      ok: true,
      wallet: walletResult.data || { balance: 0 },
      orders: ordersResult.data || []
    });
  } catch (error) {
    return fail(res, 500, 'Dashboard failed.');
  }
});

// Wallet
app.get('/api/wallet', requireConfig, auth, async (req, res) => {
  const { data, error } = await admin
    .from('wallets')
    .select('*')
    .eq('user_id', req.user.id)
    .maybeSingle();

  if (error) return fail(res, 500, 'Wallet load failed.');

  res.json({
    ok: true,
    wallet: data || { balance: 0 }
  });
});

// Order history
app.get('/api/orders', requireConfig, auth, async (req, res) => {
  const { data, error } = await admin
    .from('orders')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) return fail(res, 500, 'Orders load failed.');

  res.json({ ok: true, orders: data || [] });
});

// Admin users
app.get(
  '/api/admin/users',
  requireConfig,
  auth,
  adminOnly,
  async (req, res) => {
    const { data, error } = await admin
      .from('profiles')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(500);

    if (error) return fail(res, 500, 'Users load failed.');

    res.json({ ok: true, users: data || [] });
  }
);

// Admin services
app.get(
  '/api/admin/services',
  requireConfig,
  auth,
  adminOnly,
  async (req, res) => {
    const { data, error } = await admin
      .from('services')
      .select('*')
      .order('id');

    if (error) return fail(res, 500, 'Services load failed.');

    res.json({ ok: true, services: data || [] });
  }
);

// Admin create service
app.post(
  '/api/admin/services',
  requireConfig,
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const body = req.body || {};
      const name = String(body.name || '').trim();
      const rate = Number(body.rate);

      if (!name || !Number.isFinite(rate) || rate < 0) {
        return fail(res, 400, 'Enter a service name and valid rate.');
      }

      const payload = {
        name,
        rate,
        platform: String(body.platform || 'Other'),
        category: String(body.category || 'General'),
        min_quantity: Math.max(1, Math.floor(Number(body.min_quantity) || 1)),
        max_quantity: Math.max(1, Math.floor(Number(body.max_quantity) || 1000000)),
        active: body.active !== false
      };

      const { data, error } = await admin
        .from('services')
        .insert(payload)
        .select('*')
        .single();

      if (error) {
        console.error('Create service error:', error.message);
        return fail(res, 500, 'Could not create service.');
      }

      res.json({ ok: true, service: data });
    } catch (error) {
      return fail(res, 500, 'Could not create service.');
    }
  }
);

// Admin orders
app.get(
  '/api/admin/orders',
  requireConfig,
  auth,
  adminOnly,
  async (req, res) => {
    const { data, error } = await admin
      .from('orders')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(500);

    if (error) return fail(res, 500, 'Orders load failed.');

    res.json({ ok: true, orders: data || [] });
  }
);

// Admin settings
app.get(
  '/api/admin/settings',
  requireConfig,
  auth,
  adminOnly,
  async (req, res) => {
    const { data, error } = await admin
      .from('site_settings')
      .select('*')
      .limit(1)
      .maybeSingle();

    if (error) return fail(res, 500, 'Settings load failed.');

    res.json({ ok: true, settings: data || {} });
  }
);

// Provider status placeholder
app.get(
  '/api/admin/provider/balance',
  requireConfig,
  auth,
  adminOnly,
  async (req, res) => {
    res.json({
      ok: true,
      configured: Boolean(
        process.env.SMM_PROVIDER_URL &&
        process.env.SMM_PROVIDER_KEY
      ),
      message: 'Provider balance API must be connected separately.'
    });
  }
);

// Netlify serves the frontend; Render only serves API routes.
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: `Route not found: ${req.method} ${req.path}`
  });
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error.message);
  if (res.headersSent) return next(error);
  return fail(res, 500, 'Internal server error.');
});

app.listen(PORT, () => {
  console.log(`AJ Panel API listening on port ${PORT}`);

  const missing = [];
  if (!supabaseUrl) missing.push('SUPABASE_URL');
  if (!supabaseAnonKey) missing.push('SUPABASE_ANON_KEY');
  if (!supabaseSecretKey) missing.push('SUPABASE_SERVICE_ROLE_KEY');

  if (missing.length) {
    console.error('Missing environment variables:', missing.join(', '));
  } else {
    console.log('Supabase environment variables are present.');
  }

  console.log(`Allowed frontend origin: ${FRONTEND_URL}`);
});
       
