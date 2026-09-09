require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const publicDir = path.join(__dirname, "..", "public");
const fallbackFile = path.join(__dirname, "data", "users.json");

app.use(cors());
app.use(express.json({ limit: "1mb" }));

let useMongo = Boolean(process.env.MONGODB_URI);
let User;

if (useMongo) {
  const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: "" },
    discoverySource: { type: String, default: "" },
    socials: {
      instagram: { type: Boolean, default: false },
      facebook: { type: Boolean, default: false },
      tiktok: { type: Boolean, default: false }
    },
    notifications: { type: Boolean, default: false },
    emailVerified: { type: Boolean, default: false },
    verificationCodeHash: String,
    verificationExpiresAt: Date,
    onboardingCompleted: { type: Boolean, default: false }
  }, { timestamps: true });

  User = mongoose.model("User", userSchema);

  mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("MongoDB connected"))
    .catch(err => {
      console.error("MongoDB connection failed:", err.message);
      useMongo = false;
    });
}

function ensureFallback() {
  if (!fs.existsSync(fallbackFile)) fs.writeFileSync(fallbackFile, "[]");
}
function readUsers() {
  ensureFallback();
  return JSON.parse(fs.readFileSync(fallbackFile, "utf8"));
}
function writeUsers(users) {
  ensureFallback();
  fs.writeFileSync(fallbackFile, JSON.stringify(users, null, 2));
}
function normalizeEmail(email) { return String(email || "").trim().toLowerCase(); }
function normalizeUsername(username) { return String(username || "").trim().toLowerCase(); }
function hashCode(code) { return crypto.createHash("sha256").update(String(code)).digest("hex"); }
function tokenFor(user) {
  return jwt.sign({ id: String(user._id || user.id), username: user.username }, JWT_SECRET, { expiresIn: "7d" });
}
function safeUser(user) {
  return {
    id: String(user._id || user.id),
    name: user.name,
    username: user.username,
    email: user.email,
    phone: user.phone,
    role: user.role || "",
    discoverySource: user.discoverySource || "",
    socials: user.socials || { instagram: false, facebook: false, tiktok: false },
    notifications: Boolean(user.notifications),
    emailVerified: Boolean(user.emailVerified),
    onboardingCompleted: Boolean(user.onboardingCompleted)
  };
}
async function findUserByEmail(email) {
  email = normalizeEmail(email);
  if (useMongo) return User.findOne({ email });
  return readUsers().find(u => u.email === email);
}
async function findUserByUsername(username) {
  username = normalizeUsername(username);
  if (useMongo) return User.findOne({ username });
  return readUsers().find(u => u.username === username);
}
async function findUserById(id) {
  if (useMongo) return User.findById(id);
  return readUsers().find(u => String(u.id) === String(id));
}
async function saveUser(user) {
  if (useMongo) return user.save();
  const users = readUsers();
  const index = users.findIndex(u => String(u.id) === String(user.id));
  if (index >= 0) users[index] = user;
  else users.push(user);
  writeUsers(users);
  return user;
}

async function sendVerificationEmail(to, name, code) {
  const key = process.env.MAILJET_API_KEY;
  const secret = process.env.MAILJET_SECRET_KEY;
  const sender = process.env.MAILJET_SENDER_EMAIL || "creovah@gmail.com";
  const senderName = process.env.MAILJET_SENDER_NAME || "creovah";

  if (!key || !secret) {
    if (process.env.NODE_ENV === "production") throw new Error("Mailjet is not configured");
    console.log(`[DEV] Verification code for ${to}: ${code}`);
    return;
  }

  const auth = Buffer.from(`${key}:${secret}`).toString("base64");
  const response = await fetch("https://api.mailjet.com/v3.1/send", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Basic ${auth}` },
    body: JSON.stringify({
      Messages: [{
        From: { Email: sender, Name: senderName },
        To: [{ Email: to, Name: name }],
        Subject: "Your Creovah verification code",
        TextPart: `Hi ${name}, your Creovah verification code is ${code}. It expires in 10 minutes.`,
        HTMLPart: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:32px"><h1 style="margin:0 0 16px">creovah</h1><p>Hi ${name},</p><p>Use this code to verify your email:</p><div style="font-size:34px;font-weight:700;letter-spacing:8px;margin:24px 0">${code}</div><p>This code expires in 10 minutes.</p></div>`
      }]
    })
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Mailjet error: ${body}`);
  }
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Authentication required." });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Session expired. Please sign in again." });
  }
}

app.get("/api/health", (req, res) => res.json({ ok: true, service: "creovah-api", database: useMongo ? "mongodb" : "json-fallback" }));

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, username, email, phone, password } = req.body;
    const cleanName = String(name || "").trim();
    const cleanUsername = normalizeUsername(username);
    const cleanEmail = normalizeEmail(email);
    const cleanPhone = String(phone || "").trim();

    if (!cleanName || !cleanUsername || !cleanEmail || !cleanPhone || !password)
      return res.status(400).json({ message: "Please complete every field." });
    if (!/^[a-z0-9_]{3,24}$/.test(cleanUsername))
      return res.status(400).json({ message: "Username must be 3–24 characters using letters, numbers or underscores." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail))
      return res.status(400).json({ message: "Enter a valid email address." });
    if (String(password).length < 8)
      return res.status(400).json({ message: "Password must be at least 8 characters." });

    if (await findUserByEmail(cleanEmail)) return res.status(409).json({ message: "An account with that email already exists." });
    if (await findUserByUsername(cleanUsername)) return res.status(409).json({ message: "That username is already taken." });

    const code = String(crypto.randomInt(100000, 1000000));
    const userData = {
      name: cleanName,
      username: cleanUsername,
      email: cleanEmail,
      phone: cleanPhone,
      passwordHash: await bcrypt.hash(password, 12),
      role: "",
      discoverySource: "",
      socials: { instagram: false, facebook: false, tiktok: false },
      notifications: false,
      emailVerified: false,
      verificationCodeHash: hashCode(code),
      verificationExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
      onboardingCompleted: false
    };

    let user;
    if (useMongo) user = new User(userData);
    else user = { ...userData, id: crypto.randomUUID(), createdAt: new Date().toISOString() };

    await saveUser(user);
    await sendVerificationEmail(cleanEmail, cleanName, code);

    res.status(201).json({ message: "Account created. Check your email for the verification code.", userId: String(user._id || user.id), devVerificationCode: process.env.NODE_ENV === "production" ? undefined : code });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message || "Unable to create your account right now." });
  }
});

app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const { userId, code } = req.body;
    const user = await findUserById(userId);
    if (!user) return res.status(404).json({ message: "Account not found." });
    if (user.emailVerified) return res.json({ token: tokenFor(user), user: safeUser(user) });
    if (!user.verificationExpiresAt || new Date(user.verificationExpiresAt).getTime() < Date.now())
      return res.status(400).json({ message: "That code has expired. Request a new one." });
    if (hashCode(code) !== user.verificationCodeHash)
      return res.status(400).json({ message: "That code is incorrect." });

    user.emailVerified = true;
    user.verificationCodeHash = undefined;
    user.verificationExpiresAt = undefined;
    await saveUser(user);

    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    res.status(500).json({ message: "Unable to verify your email." });
  }
});

app.post("/api/auth/resend-code", async (req, res) => {
  try {
    const user = await findUserById(req.body.userId);
    if (!user) return res.status(404).json({ message: "Account not found." });
    if (user.emailVerified) return res.status(400).json({ message: "Email is already verified." });

    const code = String(crypto.randomInt(100000, 1000000));
    user.verificationCodeHash = hashCode(code);
    user.verificationExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await saveUser(user);
    await sendVerificationEmail(user.email, user.name, code);
    res.json({ message: "A new verification code has been sent.", devVerificationCode: process.env.NODE_ENV === "production" ? undefined : code });
  } catch (error) {
    res.status(500).json({ message: error.message || "Unable to resend the code." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      return res.status(401).json({ message: "Email or password is incorrect." });
    if (!user.emailVerified) return res.status(403).json({ message: "Please verify your email before signing in.", userId: String(user._id || user.id) });
    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch {
    res.status(500).json({ message: "Unable to sign in right now." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const user = await findUserById(req.auth.id);
  if (!user) return res.status(404).json({ message: "Account not found." });
  res.json({ user: safeUser(user) });
});

app.patch("/api/onboarding", auth, async (req, res) => {
  try {
    const user = await findUserById(req.auth.id);
    if (!user) return res.status(404).json({ message: "Account not found." });

    const allowedRoles = ["influencer", "creator", "developer", "business", "agency", "marketer", "student", "other"];
    const allowedSources = ["instagram", "tiktok", "facebook", "google", "friend", "search", "other"];
    if (req.body.role && !allowedRoles.includes(req.body.role)) return res.status(400).json({ message: "Invalid role." });
    if (req.body.discoverySource && !allowedSources.includes(req.body.discoverySource)) return res.status(400).json({ message: "Invalid discovery source." });

    if (req.body.role) user.role = req.body.role;
    if (req.body.discoverySource) user.discoverySource = req.body.discoverySource;
    if (req.body.socials) user.socials = { ...user.socials, ...req.body.socials };
    if (typeof req.body.notifications === "boolean") user.notifications = req.body.notifications;
    if (req.body.complete === true) user.onboardingCompleted = true;

    await saveUser(user);
    res.json({ user: safeUser(user) });
  } catch {
    res.status(500).json({ message: "Unable to save your onboarding progress." });
  }
});

app.use(express.static(publicDir));
app.get("*", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

app.listen(PORT, "0.0.0.0", () => console.log(`Creovah running on port ${PORT}`));
