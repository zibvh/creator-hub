require("dotenv").config();

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "creatorhub-dev-secret-change-me";
const FRONTEND_DIR = path.join(__dirname, "..", "public");
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  username: { type: String, required: true, lowercase: true, trim: true, unique: true, index: true },
  email: { type: String, required: true, lowercase: true, trim: true, unique: true, index: true },
  phone: { type: String, required: true, trim: true },
  passwordHash: { type: String, required: true },
  role: String,
  discoverySource: String,
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

const User = mongoose.model("User", userSchema);

let mongoReady = false;

async function connectMongo() {
  if (!process.env.MONGODB_URI) {
    console.warn("[CreatorHub] MONGODB_URI not set. Using JSON fallback for local development.");
    return;
  }
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    mongoReady = true;
    console.log("[CreatorHub] MongoDB connected.");
  } catch (error) {
    console.error("[CreatorHub] MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, "utf8")); }
  catch { return []; }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function safeUser(user) {
  if (!user) return null;
  const obj = user.toObject ? user.toObject() : { ...user };
  delete obj.passwordHash;
  delete obj.verificationCodeHash;
  delete obj.verificationExpiresAt;
  return obj;
}

function tokenFor(user) {
  return jwt.sign({ id: String(user._id || user.id), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Authentication required." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired session." });
  }
}

async function findUserById(id) {
  if (mongoReady) return User.findById(id);
  return readUsers().find(u => u.id === id) || null;
}

async function findUserByEmail(email) {
  if (mongoReady) return User.findOne({ email });
  return readUsers().find(u => u.email === email) || null;
}

async function findUserByUsername(username) {
  if (mongoReady) return User.findOne({ username });
  return readUsers().find(u => u.username === username) || null;
}

async function sendVerificationEmail(user, code) {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_SENDER_EMAIL) {
    console.log(`[CreatorHub] Verification code for ${user.email}: ${code}`);
    return { sent: false, devCode: process.env.NODE_ENV === "production" ? undefined : code };
  }

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "accept": "application/json",
      "api-key": process.env.BREVO_API_KEY,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: process.env.BREVO_SENDER_NAME || "CreatorHub",
        email: process.env.BREVO_SENDER_EMAIL
      },
      to: [{ email: user.email, name: user.name }],
      subject: "Your CreatorHub verification code",
      htmlContent: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Verify your CreatorHub account</h2>
          <p>Your verification code is:</p>
          <p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p>
          <p>This code expires in 10 minutes.</p>
        </div>`
    })
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Brevo email failed: ${text}`);
  }
  return { sent: true };
}

function createCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

app.get("/api/health", async (_req, res) => {
  res.json({ ok: true, service: "creatorhub-api", database: mongoReady ? "mongodb" : "json-dev" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, username, email, phone, password, confirmPassword } = req.body || {};
    if (!name || !username || !email || !phone || !password) {
      return res.status(400).json({ message: "Name, username, email, phone and password are required." });
    }
    if (password.length < 8) return res.status(400).json({ message: "Password must be at least 8 characters." });
    if (password !== confirmPassword) return res.status(400).json({ message: "Passwords do not match." });

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedUsername = String(username).trim().toLowerCase();

    if (await findUserByEmail(normalizedEmail)) {
      return res.status(409).json({ message: "An account with that email already exists." });
    }
    if (await findUserByUsername(normalizedUsername)) {
      return res.status(409).json({ message: "That username is already taken." });
    }

    const code = createCode();
    const passwordHash = await bcrypt.hash(password, 12);
    const verificationCodeHash = hashCode(code);

    let user;
    if (mongoReady) {
      user = await User.create({
        name: String(name).trim(),
        username: normalizedUsername,
        email: normalizedEmail,
        phone: String(phone).trim(),
        passwordHash,
        verificationCodeHash,
        verificationExpiresAt: new Date(Date.now() + 10 * 60 * 1000)
      });
    } else {
      user = {
        id: crypto.randomUUID(),
        name: String(name).trim(),
        username: normalizedUsername,
        email: normalizedEmail,
        phone: String(phone).trim(),
        passwordHash,
        verificationCodeHash,
        verificationExpiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        role: null,
        discoverySource: null,
        socials: { instagram: false, facebook: false, tiktok: false },
        notifications: false,
        emailVerified: false,
        onboardingCompleted: false,
        createdAt: new Date().toISOString()
      };
      const users = readUsers();
      users.push(user);
      writeUsers(users);
    }

    const emailResult = await sendVerificationEmail(user, code);
    res.status(201).json({
      message: "Account created. Check your email for the verification code.",
      userId: String(user._id || user.id),
      devVerificationCode: emailResult.devCode
    });
  } catch (error) {
    console.error("[register]", error);
    res.status(500).json({ message: "Could not create your account right now." });
  }
});

app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const { userId, code } = req.body || {};
    const user = await findUserById(userId);
    if (!user) return res.status(404).json({ message: "Account not found." });
    if (user.emailVerified) return res.json({ message: "Email already verified.", token: tokenFor(user), user: safeUser(user) });

    const expires = user.verificationExpiresAt ? new Date(user.verificationExpiresAt) : new Date(0);
    if (expires < new Date()) return res.status(400).json({ message: "That code has expired. Request a new one." });

    const valid = hashCode(code) === user.verificationCodeHash;
    if (!valid) return res.status(400).json({ message: "Incorrect verification code." });

    user.emailVerified = true;
    user.verificationCodeHash = null;
    user.verificationExpiresAt = null;

    if (mongoReady) await user.save();
    else { const users = readUsers(); const i = users.findIndex(u => u.id === user.id); users[i] = user; writeUsers(users); }

    res.json({ message: "Email verified successfully.", token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    console.error("[verify-email]", error);
    res.status(500).json({ message: "Could not verify your email right now." });
  }
});

app.post("/api/auth/resend-code", async (req, res) => {
  try {
    const { userId } = req.body || {};
    const user = await findUserById(userId);
    if (!user) return res.status(404).json({ message: "Account not found." });
    if (user.emailVerified) return res.status(400).json({ message: "Email is already verified." });

    const code = createCode();
    user.verificationCodeHash = hashCode(code);
    user.verificationExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    if (mongoReady) await user.save();
    else { const users = readUsers(); const i = users.findIndex(u => u.id === user.id); users[i] = user; writeUsers(users); }

    const result = await sendVerificationEmail(user, code);
    res.json({ message: "A new verification code has been sent.", devVerificationCode: result.devCode });
  } catch (error) {
    console.error("[resend-code]", error);
    res.status(500).json({ message: "Could not resend the verification code." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await findUserByEmail(String(email || "").trim().toLowerCase());
    if (!user || !(await bcrypt.compare(password || "", user.passwordHash))) {
      return res.status(401).json({ message: "Invalid email or password." });
    }
    if (!user.emailVerified) return res.status(403).json({ message: "Please verify your email first.", userId: String(user._id || user.id) });

    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    console.error("[login]", error);
    res.status(500).json({ message: "Could not sign you in right now." });
  }
});

app.post("/api/onboarding", auth, async (req, res) => {
  try {
    const { role, discoverySource, socials, notifications } = req.body || {};
    const user = await findUserById(req.user.id);
    if (!user) return res.status(404).json({ message: "Account not found." });

    user.role = role || user.role;
    user.discoverySource = discoverySource || user.discoverySource;
    user.socials = {
      instagram: Boolean(socials?.instagram),
      facebook: Boolean(socials?.facebook),
      tiktok: Boolean(socials?.tiktok)
    };
    user.notifications = Boolean(notifications);
    user.onboardingCompleted = true;

    if (mongoReady) await user.save();
    else { const users = readUsers(); const i = users.findIndex(u => u.id === user.id); users[i] = user; writeUsers(users); }

    res.json({ message: "Onboarding saved.", user: safeUser(user) });
  } catch (error) {
    console.error("[onboarding]", error);
    res.status(500).json({ message: "Could not save onboarding." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const user = await findUserById(req.user.id);
  if (!user) return res.status(404).json({ message: "Account not found." });
  res.json({ user: safeUser(user) });
});

app.use(express.static(FRONTEND_DIR));
app.get("*splat", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

connectMongo().then(() => {
  app.listen(PORT, "0.0.0.0", () => console.log(`CreatorHub running on port ${PORT}`));
});
