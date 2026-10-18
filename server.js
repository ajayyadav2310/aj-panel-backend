res.json({
  ok: true,
  id: req.user.id,
  email: req.user.email,
  role: profile?.role || 'user',
  isAdmin: profile?.role === 'admin',
  user: {
    id: req.user.id,
    email: req.user.email
  },
  profile: profile || null,
  wallet: wallet || { balance: 0 }
});
