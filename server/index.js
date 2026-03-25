const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const SESSION_TTL_MS = 60 * 1000;
const ADMIN_TTL_MS = 60 * 1000;
const ADMIN_PIN = process.env.ADMIN_PIN || "1039";

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
const adminSessions = new Map();
const chatMessages = [];

const MAX_CHAT_MESSAGES = 200;
const MAX_CHAT_LENGTH = 200;

const aliasAdjectives = [
  "Neon", "Pixel", "Turbo", "Nova", "Arcade", "Rocket", "Vapor", "Cosmic",
  "Glitch", "Laser", "Meteor", "Retro", "Flux", "Hyper", "Shadow", "Spark"
];

const aliasNouns = [
  "Fox", "Wolf", "Hawk", "Bear", "Lynx", "Otter", "Viper", "Panda",
  "Tiger", "Falcon", "Comet", "Ranger", "Pilot", "Runner", "Specter", "Drift"
];

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
  for (const [token, session] of adminSessions.entries()) {
    if (isExpired(session)) {
      adminSessions.delete(token);
    }
  }
}

function createSession(pin) {
  const token = `tok_${now()}_${Math.random().toString(16).slice(2)}`;
  const hash = token.split("").reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  const alias = `${aliasAdjectives[hash % aliasAdjectives.length]}-${aliasNouns[(hash >> 3) % aliasNouns.length]}-${(hash % 90) + 10}`;
  const session = { token, pin, alias, expiresAt: now() + SESSION_TTL_MS };
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

function createAdminSession() {
  const token = `adm_${now()}_${Math.random().toString(16).slice(2)}`;
  const session = { token, expiresAt: now() + ADMIN_TTL_MS };
  adminSessions.set(token, session);
  return session;
}

function refreshAdminSession(session) {
  session.expiresAt = now() + ADMIN_TTL_MS;
  adminSessions.set(session.token, session);
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

app.post("/admin/login", (req, res) => {
  const pin = String(req.body?.pin || "").trim();
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ message: "PIN must be 4 digits." });
  }
  if (pin !== ADMIN_PIN) {
    return res.status(401).json({ message: "Incorrect admin PIN." });
  }

  cleanupExpired();
  const session = createAdminSession();
  return res.json({ token: session.token, expiresAt: session.expiresAt, ttlMs: ADMIN_TTL_MS });
});

app.post("/admin/ping", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = adminSessions.get(token);
  if (!session || isExpired(session)) {
    return res.status(401).json({ message: "Admin session expired." });
  }

  refreshAdminSession(session);
  return res.json({ ok: true, expiresAt: session.expiresAt, ttlMs: ADMIN_TTL_MS });
});

app.post("/admin/kick", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = adminSessions.get(token);
  if (!session || isExpired(session)) {
    return res.status(401).json({ message: "Admin session expired." });
  }

  refreshAdminSession(session);
  const kicked = sessionsByToken.size;
  sessionsByToken.clear();
  sessionsByPin.clear();
  return res.json({ ok: true, kicked });
});

app.post("/chat/pull", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = sessionsByToken.get(token);
  if (!session || isExpired(session)) {
    return res.status(401).json({ message: "Session expired." });
  }

  refreshSession(session);
  const since = Number(req.body?.since || 0);
  const messages = chatMessages.filter((msg) => msg.time > since);
  return res.json({ messages, serverTime: now() });
});

app.post("/chat/send", (req, res) => {
  const token = String(req.body?.token || "").trim();
  if (!token) return res.status(400).json({ message: "Missing token." });

  const session = sessionsByToken.get(token);
  if (!session || isExpired(session)) {
    return res.status(401).json({ message: "Session expired." });
  }

  const raw = String(req.body?.text || "").trim();
  if (!raw) return res.status(400).json({ message: "Message required." });
  const text = raw.slice(0, MAX_CHAT_LENGTH);

  refreshSession(session);
  const message = {
    id: `msg_${now()}_${Math.random().toString(16).slice(2)}`,
    text,
    time: now(),
    from: session.alias || "Player"
  };

  chatMessages.push(message);
  if (chatMessages.length > MAX_CHAT_MESSAGES) {
    chatMessages.splice(0, chatMessages.length - MAX_CHAT_MESSAGES);
  }

  return res.json({ ok: true, message });
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`Game hub auth server running on port ${port}`);
});
