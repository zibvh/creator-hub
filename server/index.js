require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const publicDir = path.join(__dirname, "..", "public");
const APP_BASE_URL = process.env.APP_BASE_URL || "https://creovah.onrender.com";

app.use(cors());
app.use(express.json({ limit: "1mb" }));

if (!process.env.MONGODB_URI) {
  console.error("MONGODB_URI is not set. This server requires MongoDB.");
}

// --- Token encryption (AES-256-GCM) so OAuth access tokens are never stored as plaintext ---
const RAW_ENC_KEY = process.env.TOKEN_ENCRYPTION_KEY || "";
const ENC_KEY = RAW_ENC_KEY ? crypto.createHash("sha256").update(RAW_ENC_KEY).digest() : null;
function encryptToken(plainText) {
  if (!ENC_KEY) throw new Error("TOKEN_ENCRYPTION_KEY is not set.");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv.toString("base64"), authTag.toString("base64"), encrypted.toString("base64")].join(".");
}
function decryptToken(packed) {
  if (!ENC_KEY) throw new Error("TOKEN_ENCRYPTION_KEY is not set.");
  const [ivB64, tagB64, dataB64] = String(packed).split(".");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, "base64")), decipher.final()]).toString("utf8");
}

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
  connections: {
    instagram: {
      connected: { type: Boolean, default: false },
      igBusinessAccountId: String,
      igUsername: String,
      pageId: String,
      accessTokenEncrypted: String,
      tokenExpiresAt: Date
    },
    facebook: {
      connected: { type: Boolean, default: false },
      fbUserId: String,
      pageId: String,
      pageName: String,
      accessTokenEncrypted: String,
      tokenExpiresAt: Date
    }
  },
  notifications: { type: Boolean, default: false },
  onboardingCompleted: { type: Boolean, default: false },
  deletionRequested: { type: Boolean, default: false },
  deletionRequestedAt: Date
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection failed:", err.message));

function normalizeEmail(email) { return String(email || "").trim().toLowerCase(); }
function normalizeUsername(username) { return String(username || "").trim().toLowerCase(); }
function tokenFor(user) {
  return jwt.sign({ id: String(user._id || user.id), username: user.username }, JWT_SECRET, { expiresIn: "7d" });
}
function safeUser(user) {
  const conn = user.connections || {};
  return {
    id: String(user._id || user.id),
    name: user.name,
    username: user.username,
    email: user.email,
    phone: user.phone,
    role: user.role || "",
    discoverySource: user.discoverySource || "",
    socials: user.socials || { instagram: false, facebook: false, tiktok: false },
    connections: {
      instagram: {
        connected: Boolean(conn.instagram && conn.instagram.connected),
        igUsername: conn.instagram ? conn.instagram.igUsername || "" : ""
      },
      facebook: {
        connected: Boolean(conn.facebook && conn.facebook.connected),
        pageName: conn.facebook ? conn.facebook.pageName || "" : ""
      }
    },
    notifications: Boolean(user.notifications),
    onboardingCompleted: Boolean(user.onboardingCompleted),
    deletionRequested: Boolean(user.deletionRequested)
  };
}
async function findUserByEmail(email) {
  email = normalizeEmail(email);
  return User.findOne({ email });
}
async function findUserByUsername(username) {
  username = normalizeUsername(username);
  return User.findOne({ username });
}
async function findUserById(id) {
  return User.findById(id);
}
async function findUserByFbUserId(fbUserId) {
  return User.findOne({ "connections.facebook.fbUserId": String(fbUserId) });
}
async function saveUser(user) {
  return user.save();
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

app.get("/api/health", (req, res) => res.json({ ok: true, service: "creovah-api", database: "mongodb", mongoConnected: mongoose.connection.readyState === 1 }));

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
      onboardingCompleted: false
    };

    const user = new User(userData);
    await saveUser(user);

    res.status(201).json({ message: "Account created.", token: tokenFor(user), user: safeUser(user) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message || "Unable to create your account right now." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      return res.status(401).json({ message: "Email or password is incorrect." });
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
    if (typeof req.body.notifications === "boolean") user.notifications = req.body.notifications;
    if (req.body.complete === true) user.onboardingCompleted = true;

    await saveUser(user);
    res.json({ user: safeUser(user) });
  } catch {
    res.status(500).json({ message: "Unable to save your onboarding progress." });
  }
});

// --- Facebook / Instagram OAuth connect flow ---
// Instagram Business/Creator accounts are connected via Facebook Login, then
// resolved to an Instagram Business Account ID through the chosen Page.
const FB_APP_ID = process.env.FB_APP_ID;
const FB_APP_SECRET = process.env.FB_APP_SECRET;
const FB_REDIRECT_URI = process.env.FB_REDIRECT_URI || `${APP_BASE_URL}/api/connections/facebook/callback`;
const FB_GRAPH_VERSION = "v21.0";
const FB_SCOPES = [
  "pages_show_list",
  "pages_read_engagement",
  "pages_manage_posts",
  "instagram_basic",
  "instagram_content_publish",
  "business_management"
].join(",");

// Short-lived, in-memory map of OAuth state -> userId, so we know who to attach
// the connection to when Facebook redirects back. State expires in 10 minutes.
const pendingOAuthStates = new Map();
function createOAuthState(userId) {
  const state = crypto.randomBytes(16).toString("hex");
  pendingOAuthStates.set(state, { userId, expiresAt: Date.now() + 10 * 60 * 1000 });
  return state;
}
function consumeOAuthState(state) {
  const entry = pendingOAuthStates.get(state);
  pendingOAuthStates.delete(state);
  if (!entry || entry.expiresAt < Date.now()) return null;
  return entry.userId;
}

// GET so it can be used directly as a link/redirect target from the dashboard,
// authenticated via a short-lived token query param instead of a header.
app.get("/api/connections/facebook/start", async (req, res) => {
  try {
    if (!FB_APP_ID || !FB_APP_SECRET) return res.status(500).json({ message: "Facebook app is not configured on the server yet." });
    const token = String(req.query.token || "");
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ message: "Session expired. Please sign in again." }); }

    const state = createOAuthState(decoded.id);
    const params = new URLSearchParams({
      client_id: FB_APP_ID,
      redirect_uri: FB_REDIRECT_URI,
      scope: FB_SCOPES,
      response_type: "code",
      state
    });
    res.redirect(`https://www.facebook.com/${FB_GRAPH_VERSION}/dialog/oauth?${params.toString()}`);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Unable to start the Facebook connection." });
  }
});

app.get("/api/connections/facebook/callback", async (req, res) => {
  const redirectToDashboard = (status, reason) => res.redirect(`/dashboard.html?connect=${status}${reason ? `&reason=${encodeURIComponent(reason)}` : ""}`);
  try {
    const { code, state, error: oauthError } = req.query;
    if (oauthError) return redirectToDashboard("error", "denied");
    const userId = consumeOAuthState(state);
    if (!userId) return redirectToDashboard("error", "session-expired");

    const user = await findUserById(userId);
    if (!user) return redirectToDashboard("error", "account-not-found");

    // Step 1: exchange code for a short-lived user access token
    const tokenParams = new URLSearchParams({
      client_id: FB_APP_ID,
      client_secret: FB_APP_SECRET,
      redirect_uri: FB_REDIRECT_URI,
      code: String(code)
    });
    const tokenResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/oauth/access_token?${tokenParams.toString()}`);
    const tokenData = await tokenResp.json();
    if (!tokenResp.ok || !tokenData.access_token) throw new Error(tokenData.error?.message || "Token exchange failed.");

    // Step 2: exchange for a long-lived token (~60 days)
    const longLivedParams = new URLSearchParams({
      grant_type: "fb_exchange_token",
      client_id: FB_APP_ID,
      client_secret: FB_APP_SECRET,
      fb_exchange_token: tokenData.access_token
    });
    const longLivedResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/oauth/access_token?${longLivedParams.toString()}`);
    const longLivedData = await longLivedResp.json();
    if (!longLivedResp.ok || !longLivedData.access_token) throw new Error(longLivedData.error?.message || "Long-lived token exchange failed.");
    const userAccessToken = longLivedData.access_token;
    const expiresAt = new Date(Date.now() + (longLivedData.expires_in || 60 * 24 * 60 * 60) * 1000);

    // Fetch the Facebook user's own Graph ID so we can match Meta's automated
    // Data Deletion Callback (which only gives us this ID) back to this account.
    const meResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/me?fields=id&access_token=${encodeURIComponent(userAccessToken)}`);
    const meData = await meResp.json();
    const fbUserId = meData.id || "";

    // Step 3: list the Pages this user manages, with a Page access token for each
    const pagesResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/me/accounts?access_token=${encodeURIComponent(userAccessToken)}`);
    const pagesData = await pagesResp.json();
    if (!pagesResp.ok) throw new Error(pagesData.error?.message || "Could not list Facebook Pages.");
    const page = (pagesData.data || [])[0];
    if (!page) return redirectToDashboard("error", "no-pages-found");

    // Facebook connection uses the Page's own access token
    user.connections = user.connections || {};
    user.connections.facebook = {
      connected: true,
      fbUserId,
      pageId: page.id,
      pageName: page.name,
      accessTokenEncrypted: encryptToken(page.access_token),
      tokenExpiresAt: expiresAt
    };
    user.socials = { ...user.socials, facebook: true };

    // Step 4: resolve the Instagram Business Account linked to that Page, if any
    const igResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/${page.id}?fields=instagram_business_account&access_token=${encodeURIComponent(page.access_token)}`);
    const igData = await igResp.json();
    const igAccountId = igData.instagram_business_account?.id;

    if (igAccountId) {
      const igProfileResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/${igAccountId}?fields=username&access_token=${encodeURIComponent(page.access_token)}`);
      const igProfile = await igProfileResp.json();
      user.connections.instagram = {
        connected: true,
        igBusinessAccountId: igAccountId,
        igUsername: igProfile.username || "",
        pageId: page.id,
        accessTokenEncrypted: encryptToken(page.access_token),
        tokenExpiresAt: expiresAt
      };
      user.socials = { ...user.socials, instagram: true };
    }

    await saveUser(user);
    return redirectToDashboard(igAccountId ? "instagram-success" : "facebook-only-success");
  } catch (error) {
    console.error("Facebook OAuth callback error:", error.message);
    return redirectToDashboard("error", "unexpected");
  }
});

app.post("/api/connections/:platform/disconnect", auth, async (req, res) => {
  try {
    const platform = req.params.platform;
    if (!["instagram", "facebook"].includes(platform)) return res.status(400).json({ message: "Unknown platform." });
    const user = await findUserById(req.auth.id);
    if (!user) return res.status(404).json({ message: "Account not found." });

    user.connections = user.connections || {};
    user.connections[platform] = { connected: false };
    user.socials = { ...user.socials, [platform]: false };
    await saveUser(user);
    res.json({ user: safeUser(user) });
  } catch {
    res.status(500).json({ message: "Unable to disconnect right now." });
  }
});

app.post("/api/account/request-deletion", auth, async (req, res) => {
  try {
    const user = await findUserById(req.auth.id);
    if (!user) return res.status(404).json({ message: "Account not found." });

    // Immediately strip stored OAuth tokens and connection data — no reason to
    // keep that once deletion has been requested, even before full purge.
    user.connections = {
      instagram: { connected: false },
      facebook: { connected: false }
    };
    user.socials = { instagram: false, facebook: false, tiktok: false };
    user.deletionRequested = true;
    user.deletionRequestedAt = new Date();

    await saveUser(user);
    res.json({ message: "Your data deletion request has been received.", user: safeUser(user) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Unable to submit your deletion request right now." });
  }
});

// --- Meta's automated Data Deletion Request Callback ---
// Fires when a user removes the app or requests deletion from Facebook's own
// privacy settings (separate from the in-app "Request data deletion" button
// above). Meta sends a signed_request identifying the Facebook user; we look
// up any Creovah account connected via that Facebook Page/Instagram account,
// strip its connection data, and return a status URL + confirmation code.
function base64UrlDecode(input) {
  return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function parseSignedRequest(signedRequest, appSecret) {
  const [encodedSig, encodedPayload] = String(signedRequest).split(".");
  if (!encodedSig || !encodedPayload) return null;
  const expectedSig = crypto.createHmac("sha256", appSecret).update(encodedPayload).digest();
  const providedSig = base64UrlDecode(encodedSig);
  if (expectedSig.length !== providedSig.length || !crypto.timingSafeEqual(expectedSig, providedSig)) return null;
  return JSON.parse(base64UrlDecode(encodedPayload).toString("utf8"));
}
const deletionConfirmations = new Map();

app.post("/api/connections/facebook/data-deletion-callback", express.urlencoded({ extended: true }), async (req, res) => {
  try {
    if (!FB_APP_SECRET) return res.status(500).json({ error: "App not configured." });
    const payload = parseSignedRequest(req.body.signed_request, FB_APP_SECRET);
    if (!payload) return res.status(403).json({ error: "Invalid signed request." });

    const fbUserId = String(payload.user_id);
    const confirmationCode = crypto.randomBytes(12).toString("hex");

    const user = await findUserByFbUserId(fbUserId);
    if (user) {
      user.connections = { instagram: { connected: false }, facebook: { connected: false } };
      user.socials = { ...user.socials, instagram: false, facebook: false };
      await saveUser(user);
    }

    deletionConfirmations.set(confirmationCode, {
      fbUserId,
      matchedUser: Boolean(user),
      requestedAt: new Date().toISOString(),
      status: "completed"
    });

    res.json({
      url: `${APP_BASE_URL}/api/connections/facebook/deletion-status/${confirmationCode}`,
      confirmation_code: confirmationCode
    });
  } catch (error) {
    console.error("Data deletion callback error:", error.message);
    res.status(500).json({ error: "Unable to process deletion request." });
  }
});

app.get("/api/connections/facebook/deletion-status/:code", (req, res) => {
  const record = deletionConfirmations.get(req.params.code);
  if (!record) return res.status(404).send("Deletion request not found.");
  res.send(`<!doctype html><html><body style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:0 20px"><h2>Data deletion status</h2><p>Confirmation code: <code>${req.params.code}</code></p><p>Status: ${record.status}</p><p>Requested at: ${record.requestedAt}</p></body></html>`);
});

app.use(express.static(publicDir));
app.get("*", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

app.listen(PORT, "0.0.0.0", () => console.log(`Creovah running on port ${PORT}`));
