// dotenv not needed on Vercel — set env vars in the Vercel dashboard
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'https://jwt-concept.vercel.app',
  credentials: true
}));

// =================================================================
// SECTION 1: IN-MEMORY "DATABASE"
// NOTE: Vercel serverless functions have no persistent filesystem.
// Users reset on every cold start. For production, replace this
// with a real database (e.g. Supabase, PlanetScale, MongoDB Atlas).
// Each user record: { id, firstName, lastName, email, passwordHash, provider }
// =================================================================
let usersStore = [];

function readUsers() {
  return usersStore;
}

function writeUsers(users) {
  usersStore = users;
}

function findUserByEmail(email) {
  return usersStore.find(u => u.email === email);
}

// =================================================================
// SECTION 2: TOKEN + SESSION HELPERS
// =================================================================
let validRefreshTokens = new Set(); // swap for a DB table in production

function generateAccessToken(email) {
  return jwt.sign({ sub: email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20m' });
}

function generateRefreshToken(email) {
  return jwt.sign({ sub: email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' });
}

// Sets the access cookie (always) and refresh cookie (only if "remember" is true),
// then either replies with JSON (normal login/signup) or redirects the browser
// (OAuth callbacks arrive via full-page navigation, not fetch).
function issueSession(user, remember, res, redirectTo) {
  const accessToken = generateAccessToken(user.email);
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 20 * 60 * 1000 // 20 minutes
  });

  if (remember) {
    const refreshToken = generateRefreshToken(user.email);
    validRefreshTokens.add(refreshToken);
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
  }

  if (redirectTo) return res.redirect(redirectTo);
  res.json({ firstName: user.firstName, lastName: user.lastName, email: user.email });
}

function authenticateToken(req, res, next) {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Access token expired or invalid' });
    req.user = payload;
    next();
  });
}

// =================================================================
// SECTION 3: EMAIL + PASSWORD SIGNUP / LOGIN
// =================================================================
app.post('/api/signup', async (req, res) => {
  const { firstName, lastName, email, password, remember } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'First name, last name, email and password are all required' });
  }
  if (findUserByEmail(email)) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now().toString(),
    firstName,
    lastName,
    email,
    passwordHash,
    provider: 'local'
  };

  const users = readUsers();
  users.push(newUser);
  writeUsers(users);

  issueSession(newUser, remember, res);
});

app.post('/api/login', async (req, res) => {
  const { email, password, remember } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = findUserByEmail(email);
  const passwordMatches = user && user.passwordHash && await bcrypt.compare(password, user.passwordHash);

  if (!passwordMatches) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  issueSession(user, remember, res);
});

// =================================================================
// SECTION 4: GOOGLE OAUTH2
// Flow: browser -> /auth/google -> accounts.google.com -> back to
// /auth/google/callback?code=... -> server exchanges code for
// profile info -> creates/finds user -> sets cookies -> redirects
// the browser to your frontend.
// =================================================================
app.get('/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'select_account'
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect(`${process.env.FRONTEND_URL}?error=google_auth_failed`);

  try {
    // Trade the one-time code for an access token (this step REQUIRES the client secret)
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();

    // Use that access token to ask Google who this person is
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json(); // { email, given_name, family_name, ... }

    let user = findUserByEmail(profile.email);
    if (!user) {
      user = {
        id: Date.now().toString(),
        firstName: profile.given_name || 'Friend',
        lastName: profile.family_name || '',
        email: profile.email,
        passwordHash: null,
        provider: 'google'
      };
      const users = readUsers();
      users.push(user);
      writeUsers(users);
    }

    issueSession(user, true, res, process.env.FRONTEND_URL);
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.redirect(`${process.env.FRONTEND_URL}?error=google_auth_failed`);
  }
});

// =================================================================
// SECTION 5: GITHUB OAUTH2 (same shape as Google, different endpoints)
// =================================================================
app.get('/auth/github', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_REDIRECT_URI,
    scope: 'read:user user:email'
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

app.get('/auth/github/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect(`${process.env.FRONTEND_URL}?error=github_auth_failed`);

  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        redirect_uri: process.env.GITHUB_REDIRECT_URI,
        code
      })
    });
    const tokenData = await tokenRes.json();

    const profileRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${tokenData.access_token}`, 'User-Agent': 'jwt-learning-app' }
    });
    const profile = await profileRes.json();

    // GitHub only includes email in /user if the user made it public,
    // so fall back to the dedicated emails endpoint.
    let email = profile.email;
    if (!email) {
      const emailsRes = await fetch('https://api.github.com/user/emails', {
        headers: { Authorization: `Bearer ${tokenData.access_token}`, 'User-Agent': 'jwt-learning-app' }
      });
      const emails = await emailsRes.json();
      const primary = Array.isArray(emails) ? (emails.find(e => e.primary) || emails[0]) : null;
      email = primary ? primary.email : null;
    }
    if (!email) return res.redirect(`${process.env.FRONTEND_URL}?error=github_email_missing`);

    // GitHub gives a single "name" field, not separate first/last — split it as a best effort
    const nameParts = (profile.name || profile.login || 'Friend').split(' ');
    const firstName = nameParts[0];
    const lastName = nameParts.slice(1).join(' ');

    let user = findUserByEmail(email);
    if (!user) {
      user = {
        id: Date.now().toString(),
        firstName,
        lastName,
        email,
        passwordHash: null,
        provider: 'github'
      };
      const users = readUsers();
      users.push(user);
      writeUsers(users);
    }

    issueSession(user, true, res, process.env.FRONTEND_URL);
  } catch (err) {
    console.error('GitHub OAuth error:', err);
    res.redirect(`${process.env.FRONTEND_URL}?error=github_auth_failed`);
  }
});

// =================================================================
// SECTION 6: SESSION CHECK, REFRESH, LOGOUT
// =================================================================
app.get('/api/me', authenticateToken, (req, res) => {
  const user = findUserByEmail(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ firstName: user.firstName, lastName: user.lastName, email: user.email });
});

app.post('/api/refresh', (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken || !validRefreshTokens.has(refreshToken)) {
    return res.status(401).json({ error: 'No valid refresh token, please log in again' });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, payload) => {
    if (err) {
      validRefreshTokens.delete(refreshToken);
      return res.status(401).json({ error: 'Refresh token expired, please log in again' });
    }
    const newAccessToken = generateAccessToken(payload.sub);
    res.cookie('access_token', newAccessToken, {
      httpOnly: true, secure: true, sameSite: 'none', maxAge: 20 * 60 * 1000
    });
    res.json({ message: 'Access token refreshed' });
  });
});

app.post('/api/logout', (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (refreshToken) validRefreshTokens.delete(refreshToken);
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.json({ message: 'Logged out' });
});

// Export for Vercel serverless — do not call app.listen()
module.exports = app;