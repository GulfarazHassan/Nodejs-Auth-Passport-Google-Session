import https from 'https';
import fs from 'fs';
import path from 'path';
import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import passport from 'passport';
import cookieSession from 'cookie-session';
import { Strategy } from 'passport-google-oauth20';
dotenv.config();

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: 'https://localhost:3000/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

const verifyCallback = (accessToken, refreshToken, profile, done) => {
  done(null, profile);
};

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Read the session from cookie
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

const app = express();

// It gives security layer
app.use(helmet());

app.use(
  cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Serving static assets
app.use(express.static('/'));

const checkLoggedIn = (req, res, next) => {
  const loggedIn = req.isAuthenticated() && req.user;
  if (!loggedIn) {
    return res.status(401).json({ message: 'User must log in !' });
  }
  next();
};

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }),
  (req, res) => {
    console.log('Google called us back!');
  }
);

app.get('/auth/logout', (req, res) => {
  req.logout(); // Remove req.user & clear any login session
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('Express server is running');
});

app.get('/failure', checkLoggedIn, (req, res) => {
  return res.send('Failure in google oAuth');
});

app.get('*', (req, res) => {
  return res.sendFile(path.resolve('public', 'index.html'));
});

https
  .createServer(
    {
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
    },
    app
  )
  .listen(3000, () => {
    console.log('App is running on port 3000');
  });
