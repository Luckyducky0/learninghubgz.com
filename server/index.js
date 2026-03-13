const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const SESSION_TTL_MS = 60 * 1000;

const defaultPins = [
  "1029","2741","3906","4178","5283",
  "6094","7315","8462","9027","1138",
  "2469","3571","4680","5792","6803",
  "7914","8046","9175","0384","6529"
];

const pinList = (process.env.PIN_LIST || "").split(",").map((p) => p.trim()).filter(Boolean);
const allowedPins = new Set(pinList.length ? pinList : defaultPins);

const sessionsByPin = new Map();
const sessionsByToken = new Map();

function now() {
  return Date.now();
}

function isExpired(session) {
  return !session || session.expiresAt <= now();
}

function cleanupExpired() {
  for (const [pin, session] of sessionsByPin.entries()) {
    if (isExpired(session)) {
      sessionsByPin.delete(pin);
      if (session && session.token) sessionsByToken.delete(session.token);
    }
  }
}

function createSession(pin) {
  const token = `tok_${now()}_${Math.random().toString(16).slice(2)}`;
  const session = { token, pin, expiresAt: now() + SESSION_TTL_MS };
  sessionsByPin.set(pin, session);
  sessionsByToken.set(token, session);
  return session;
}

function refreshSession(session) {
  session.expiresAt = now() + SESSION_TTL_MS;
  sessionsByPin.set(session.pin, session);
  sessionsByToken.set(session.token, session);
  return session;
}

setInterval(cleanupExpired, 15000);

app.get("/", (_req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

app.post("/login", (req, res) => {
  const pin = String(req.body?.pin || "").trim();
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ message: "PIN must be 4 digits." });
  }
  if (!allowedPins.has(pin)) {
    return res.status(401).json({ message: "Incorrect PIN." });
  }

  cleanupExpired();
  const existing = sessionsByPin.get(pin);
  if (existing && !isExpired(existing)) {
    return res.status(409).json({ message: "Another player is already logged in." });
  }

  const session = createSession(pin);
  return res.json({ token: session.token, expiresAt: session.expiresAt, ttlMs: SESSION_TTL_MS });
});

app.post("/validate", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = sessionsByToken.get(token);
  if (!session || isExpired(session)) {
    return res.status(401).json({ valid: false, message: "Session expired." });
  }

  refreshSession(session);
  return res.json({ valid: true, expiresAt: session.expiresAt, ttlMs: SESSION_TTL_MS });
});

app.post("/ping", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = sessionsByToken.get(token);
  if (!session || isExpired(session)) {
    return res.status(401).json({ message: "Session expired." });
  }

  refreshSession(session);
  return res.json({ ok: true, expiresAt: session.expiresAt, ttlMs: SESSION_TTL_MS });
});

app.post("/logout", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = sessionsByToken.get(token);
  if (session) {
    sessionsByToken.delete(token);
    sessionsByPin.delete(session.pin);
  }
  return res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Game hub auth server running on port ${port}`);
});
