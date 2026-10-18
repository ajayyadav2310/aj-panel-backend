 
'use strict';

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  'https://tourmaline-sorbet-d89e38.netlify.app';

app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseSecretKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = supabaseUrl && supabaseAnonKey
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

const admin = supabaseUrl && supabaseSecretKey
  ? createClient(supabaseUrl, supabaseSecretKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    })
  : null;

function requireConfig(req, res, next) {
  if (!supabase || !admin) {
    return res.status(503).json({
      ok: false,
      error: 'Supabase configuration missing in Render Environment.'
    });
  }
  next();
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

    if (!token) {
      return res.status(401).json({
        ok: false,
        error: 'Please sign in first.'
      });
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid or expired login session.'
      });
    }

    req.user = data.user;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    res.status(500).json({ ok: false, error: 'Authentication failed.' });
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
      return res.status(500).json({
        ok: false,
        error: 'Could not verify admin role.'
      });
    }

    if (data?.role !== 'admin') {
      return res.status(403).json({
        ok: false,
        error: 'Admin access required.'
      });
    }

    next();
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Admin check failed.' });
  }
}

// Health check: no index.html required
app.get('/', (req, res) => {
  res.send('AJ Panel API is running.');
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

// Signup
app.post('/api/auth/signup', requireConfig, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !email.includes('@')) {
      return res.status(400).json({
        ok: false, error: 'Enter a valid email address.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false, error: 'Password must be at least 6 characters.'
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password
    });

    if (error) {
      return res.status(400).json({ ok: false, error: error.message });
    }

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
    res.status(500).json({ ok: false, error: 'Signup failed.' });
  }
});

// Login
app.post('/api/auth/login', requireConfig, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({
        ok: false, error: 'Enter email and password.'
      });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      return res.status(401).json({ ok: false, error: error.message });
    }

    res.json({
      ok: true,
      user: data.user,
      session: data.session
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ ok: false, error: 'Login failed.' });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', requireConfig, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();

    if (!email || !email.includes('@')) {
      return res.status(400).json({
        ok: false, error: 'Enter a valid email address.'
      });
    }

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: FRONTEND_URL
    });

    if (error) {
      return res.status(400).json({ ok: false, error: error.message });
    }

    res.json({
      ok: true,
      message: 'If registered, a password reset email will be sent.'
    });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    res.status(500).json({ ok: false, error: 'Password reset failed.' });
  }
});

// Current user
app.get('/api/me', requireConfig, auth, async (req, res) => {
  try {
    const { data: profile, error } = await admin
      .from('profiles')
      .select('*')
      .eq('id', req.user.id)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false, error: 'Could not load profile.'
      });
    }

    res.json({ ok: true, user: req.user, profile });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Could not load user.' });
  }
});

// Services
app.get('/api/services', requireConfig, async (req, res) => {
  const { data, error } = await admin
    .from('services')
    .select('*')
    .eq('active', true);

  if (error) {
    return res.status(500).json({
      ok: false, error: 'Could not load services.'
    });
  }

  res.json({ ok: true, services: data || [] });
});

// Dashboard
app.get('/api/dashboard', requireConfig, auth, async (req, res) => {
  try {
    const { data: wallet, error: walletError } = await admin
      .from('wallets')
      .select('*')
      .eq('user_id', req.user.id)
      .maybeSingle();

    const { data: orders, error: orderError } = await admin
      .from('orders')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (walletError || orderError) {
      return res.status(500).json({
        ok: false, error: 'Could not load dashboard data.'
      });
    }

    res.json({
      ok: true,
      wallet: wallet || { balance: 0 },
      orders: orders || []
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Dashboard failed.' });
  }
});

// Wallet
app.get('/api/wallet', requireConfig, auth, async (req, res) => {
  const { data, error } = await admin
    .from('wallets')
    .select('*')
    .eq('user_id', req.user.id)
    .maybeSingle();

  if (error) {
    return res.status(500).json({ ok: false, error: 'Wallet load failed.' });
  }

  res.json({ ok: true, wallet: data || { balance: 0 } });
});

// User order history
app.get('/api/orders', requireConfig, auth, async (req, res) => {
  const { data, error } = await admin
    .from('orders')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(100);

  if (error) {
    return res.status(500).json({ ok: false, error: 'Orders load failed.' });
  }

  res.json({ ok: true, orders: data || [] });
});

// Admin users
app.get('/api/admin/users', requireConfig, auth, adminOnly, async (req, res) => {
  const { data, error } = await admin.from('profiles').select('*').limit(500);

  if (error) {
    return res.status(500).json({ ok: false, error: 'Users load failed.' });
  }

  res.json({ ok: true, users: data || [] });
});

// Admin services
app.get('/api/admin/services', requireConfig, auth, adminOnly, async (req, res) => {
  const { data, error } = await admin.from('services').select('*').order('id');

  if (error) {
    return res.status(500).json({ ok: false, error: 'Services load failed.' });
  }

  res.json({ ok: true, services: data || [] });
});

// Admin orders
app.get('/api/admin/orders', requireConfig, auth, adminOnly, async (req, res) => {
  const { data, error } = await admin.from('orders').select('*')
    .order('created_at', { ascending: false }).limit(500);

  if (error) {
    return res.status(500).json({ ok: false, error: 'Orders load failed.' });
  }

  res.json({ ok: true, orders: data || [] });
});

// Do not serve index.html from Render; Netlify hosts the frontend.
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: `Route not found: ${req.method} ${req.path}`
  });
});

app.listen(PORT, () => {
  console.log(`AJ Panel API listening on port ${PORT}`);
  if (!supabaseUrl || !supabaseAnonKey || !supabaseSecretKey) {
    console.error('Missing one or more Supabase environment variables.');
  } else {
    console.log('Supabase environment variables are present.');
  }
});
