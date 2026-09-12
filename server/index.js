require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const publicDir = path.join(__dirname, "..", "public");
const APP_BASE_URL = process.env.APP_BASE_URL || "https://creovah.onrender.com";

app.use(cors());
app.use(express.json({ limit: "1mb" }));
const mediaUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

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
    tiktok: { type: Boolean, default: false },
    linkedin: { type: Boolean, default: false }
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
    },
    linkedin: {
      connected: { type: Boolean, default: false },
      memberId: String,
      memberUrn: String,
      name: String,
      email: String,
      accessTokenEncrypted: String,
      tokenExpiresAt: Date
    }
  },
  notifications: { type: Boolean, default: false },
  onboardingCompleted: { type: Boolean, default: false },
  deletionRequested: { type: Boolean, default: false },
  deletionRequestedAt: Date,
  disabled: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const contentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 120 },
  body: { type: String, default: "", maxlength: 5000 },
  mediaUrl: { type: String, default: "" },
  mediaUrn: { type: String, default: "" },
  mediaType: { type: String, default: "" },
  mediaAltText: { type: String, default: "", maxlength: 300 },
  platforms: { type: [String], default: [] },
  status: { type: String, enum: ["draft", "scheduled", "published"], default: "draft" },
  scheduledFor: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  publishedAt: { type: Date, default: null }
}, { timestamps: true });

const Content = mongoose.model("Content", contentSchema);

const notificationSchema = new mongoose.Schema({ userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",index:true}, title:{type:String,required:true,trim:true,maxlength:120}, message:{type:String,required:true,trim:true,maxlength:2000}, read:{type:Boolean,default:false}, createdAt:{type:Date,default:Date.now} },{timestamps:true});
const Notification = mongoose.model("Notification", notificationSchema);
const legalSchema = new mongoose.Schema({ key:{type:String,unique:true}, terms:{type:String,default:""}, privacy:{type:String,default:""}, updatedAt:{type:Date,default:Date.now} });
const Legal = mongoose.model("Legal", legalSchema);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection failed:", err.message));

function normalizeEmail(email) { return String(email || "").trim().toLowerCase(); }
function normalizeUsername(username) { return String(username || "").trim().toLowerCase(); }
function tokenFor(user) {
  return jwt.sign({ id: String(user._id || user.id), username: user.username, role: user.role || "" }, JWT_SECRET, { expiresIn: "7d" });
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
    socials: user.socials || { instagram: false, facebook: false, tiktok: false, linkedin: false },
    connections: {
      instagram: {
        connected: Boolean(conn.instagram && conn.instagram.connected),
        igUsername: conn.instagram ? conn.instagram.igUsername || "" : ""
      },
      facebook: {
        connected: Boolean(conn.facebook && conn.facebook.connected),
        pageName: conn.facebook ? conn.facebook.pageName || "" : ""
      },
      linkedin: {
        connected: Boolean(conn.linkedin && conn.linkedin.connected),
        name: conn.linkedin ? conn.linkedin.name || "" : ""
      }
    },
    notifications: Boolean(user.notifications),
    onboardingCompleted: Boolean(user.onboardingCompleted),
    deletionRequested: Boolean(user.deletionRequested),
    disabled: Boolean(user.disabled)
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
    User.findById(req.auth.id).then(user => {
      if (!user) return res.status(401).json({ message: "Account not found." });
      if (user.disabled) return res.status(403).json({ message: "This account has been disabled." });
      next();
    }).catch(() => res.status(401).json({ message: "Authentication required." }));
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

app.get("/api/content", auth, async (req, res) => {
  try {
    const items = await Content.find({ userId: req.auth.id }).sort({ scheduledFor: 1, createdAt: -1 }).limit(100).lean();
    res.json({ items });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Unable to load your content right now." });
  }
});

app.post("/api/linkedin/media", auth, mediaUpload.single("media"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "Choose a photo or video." });
    const user = await findUserById(req.auth.id);
    const conn = user?.connections?.linkedin;
    if (!conn?.connected || !conn.accessTokenEncrypted || !conn.memberUrn) return res.status(400).json({ message: "Connect LinkedIn before uploading media." });
    const mime = String(req.file.mimetype || "").toLowerCase();
    const token = decryptToken(conn.accessTokenEncrypted);
    if (["image/jpeg", "image/png", "image/gif"].includes(mime)) {
      const init = await linkedinFetch("https://api.linkedin.com/rest/images?action=initializeUpload", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ initializeUploadRequest: { owner: conn.memberUrn } }) });
      const value = init.data.value || {};
      if (!value.uploadUrl || !value.image) throw new Error("LinkedIn did not return an image upload URL.");
      const upload = await fetch(value.uploadUrl, { method: "PUT", headers: { "Content-Type": mime }, body: req.file.buffer });
      if (!upload.ok) throw new Error(`LinkedIn image upload failed (${upload.status}).`);
      return res.json({ urn: value.image, mediaType: "image" });
    }
    if (mime === "video/mp4") {
      const init = await linkedinFetch("https://api.linkedin.com/rest/videos?action=initializeUpload", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ initializeUploadRequest: { owner: conn.memberUrn, fileSizeBytes: req.file.size, uploadCaptions: false, uploadThumbnail: false } }) });
      const value = init.data.value || {}; const instructions = value.uploadInstructions || [];
      if (!value.video || !instructions.length) throw new Error("LinkedIn did not return video upload instructions.");
      const partIds = [];
      for (const instruction of instructions) {
        const start = Number(instruction.firstByte || 0); const end = Number(instruction.lastByte ?? req.file.size - 1);
        const chunk = req.file.buffer.subarray(start, Math.min(end + 1, req.file.size));
        const upload = await fetch(instruction.uploadUrl, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: chunk });
        if (!upload.ok) throw new Error(`LinkedIn video upload failed (${upload.status}).`);
        const etag = upload.headers.get("etag"); if (!etag) throw new Error("LinkedIn did not return a video part identifier.");
        partIds.push(etag);
      }
      await linkedinFetch("https://api.linkedin.com/rest/videos?action=finalizeUpload", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ finalizeUploadRequest: { video: value.video, uploadToken: value.uploadToken || "", uploadedPartIds: partIds } }) });
      return res.json({ urn: value.video, mediaType: "video" });
    }
    return res.status(400).json({ message: "Use a JPG, PNG, GIF or MP4 file." });
  } catch (error) { console.error("LinkedIn media upload error:", error); res.status(500).json({ message: error.message || "Unable to upload media to LinkedIn." }); }
});

app.post("/api/content", auth, async (req, res) => {
  try {
    const title = String(req.body.title || "").trim();
    const body = String(req.body.body || "").trim();
    const platforms = Array.isArray(req.body.platforms) ? req.body.platforms.filter(p => ["instagram", "facebook", "tiktok", "linkedin"].includes(p)) : [];
    const requestedStatus = ["draft", "scheduled"].includes(req.body.status) ? req.body.status : "draft";
    const publishNow = Boolean(req.body.publishNow);
    if (!title && !body) return res.status(400).json({ message: "Add a title or some content." });
    if (!platforms.length) return res.status(400).json({ message: "Choose at least one platform." });
    let scheduledFor = null;
    if (requestedStatus === "scheduled") {
      scheduledFor = new Date(req.body.scheduledFor);
      if (Number.isNaN(scheduledFor.getTime())) return res.status(400).json({ message: "Choose a valid date and time." });
      if (scheduledFor <= new Date()) return res.status(400).json({ message: "Scheduled time must be in the future." });
    }
    const item = await Content.create({
      userId: req.auth.id, title: title || "LinkedIn post", body, platforms,
      status: publishNow && platforms.includes("linkedin") ? "draft" : requestedStatus, scheduledFor,
      mediaUrl: String(req.body.mediaUrl || "").trim(),
      mediaUrn: String(req.body.mediaUrn || "").trim(),
      mediaType: String(req.body.mediaType || "").trim(),
      mediaAltText: String(req.body.mediaAltText || "").trim()
    });

    if (platforms.includes("linkedin")) {
      const user = await findUserById(req.auth.id);
      if (!user?.connections?.linkedin?.connected) {
        await Content.deleteOne({ _id: item._id });
        return res.status(400).json({ message: "Connect LinkedIn before publishing or scheduling LinkedIn content." });
      }
      if (item.mediaUrl && !item.mediaUrn) {
        const media = await prepareLinkedInImage(user, item.mediaUrl);
        item.mediaUrn = media.urn;
        item.mediaType = "image";
        await item.save();
      }
      if (publishNow) {
        await publishLinkedInContent(user, item);
        item.status = "published";
        item.publishedAt = new Date();
        item.scheduledFor = null;
        await item.save();
      }
    }
    res.status(201).json({ item });
  } catch (error) {
    console.error("Content save/publish error:", error);
    res.status(500).json({ message: error.message || "Unable to save this content right now." });
  }
});

app.delete("/api/content/:id", auth, async (req, res) => {
  try {
    const item = await Content.findOneAndDelete({ _id: req.params.id, userId: req.auth.id });
    if (!item) return res.status(404).json({ message: "Content not found." });
    res.json({ message: "Content deleted." });
  } catch {
    res.status(500).json({ message: "Unable to delete this content right now." });
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

// --- LinkedIn OAuth + publishing ---
const LINKEDIN_CLIENT_ID = process.env.LINKEDIN_CLIENT_ID;
const LINKEDIN_CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const LINKEDIN_REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI || `${APP_BASE_URL}/api/connections/linkedin/callback`;
const LINKEDIN_VERSION = process.env.LINKEDIN_VERSION || "202608";
const LINKEDIN_SCOPES = "openid profile email w_member_social";

async function linkedinFetch(url, options = {}) {
  const headers = {
    "Linkedin-Version": LINKEDIN_VERSION,
    "X-Restli-Protocol-Version": "2.0.0",
    ...(options.headers || {})
  };
  const response = await fetch(url, { ...options, headers });
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!response.ok) {
    const detail = data.message || data.error_description || data.error || data.raw || `LinkedIn request failed (${response.status}).`;
    throw new Error(String(detail));
  }
  return { response, data };
}

app.get("/api/connections/linkedin/start", auth, (req, res) => {
  try {
    if (!LINKEDIN_CLIENT_ID || !LINKEDIN_CLIENT_SECRET) return res.status(500).json({ message: "LinkedIn connection is not configured on the server yet." });
    const state = createOAuthState(req.auth.id, "linkedin");
    const params = new URLSearchParams({
      response_type: "code",
      client_id: LINKEDIN_CLIENT_ID,
      redirect_uri: LINKEDIN_REDIRECT_URI,
      state,
      scope: LINKEDIN_SCOPES
    });
    res.json({ url: `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}` });
  } catch (error) {
    console.error("LinkedIn OAuth start error:", error);
    res.status(500).json({ message: "Unable to start the LinkedIn connection." });
  }
});

async function exchangeLinkedInCode(code) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: String(code),
    client_id: LINKEDIN_CLIENT_ID,
    client_secret: LINKEDIN_CLIENT_SECRET,
    redirect_uri: LINKEDIN_REDIRECT_URI
  });
  const response = await fetch("https://www.linkedin.com/oauth/v2/accessToken", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(data.error_description || data.message || "LinkedIn token exchange failed.");
  return { accessToken: data.access_token, expiresAt: data.expires_in ? new Date(Date.now() + Number(data.expires_in) * 1000) : null };
}

async function completeLinkedInConnection(userId, code) {
  const user = await findUserById(userId);
  if (!user) throw new Error("Account not found.");
  const { accessToken, expiresAt } = await exchangeLinkedInCode(code);
  const profileResp = await fetch("https://api.linkedin.com/v2/userinfo", { headers: { Authorization: `Bearer ${accessToken}` } });
  const profile = await profileResp.json().catch(() => ({}));
  if (!profileResp.ok || !profile.sub) throw new Error(profile.message || profile.error || "Could not read the connected LinkedIn profile.");
  const memberUrn = `urn:li:person:${profile.sub}`;
  user.connections = user.connections || {};
  user.connections.linkedin = {
    connected: true,
    memberId: profile.sub,
    memberUrn,
    name: profile.name || [profile.given_name, profile.family_name].filter(Boolean).join(" "),
    email: profile.email || "",
    accessTokenEncrypted: encryptToken(accessToken),
    tokenExpiresAt: expiresAt
  };
  user.socials = { ...user.socials, linkedin: true };
  await saveUser(user);
  return { name: user.connections.linkedin.name || "LinkedIn" };
}

app.get("/api/connections/linkedin/callback", async (req, res) => {
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status });
    if (reason) params.set("reason", reason);
    if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`/dashboard.html?${params.toString()}`);
  };
  try {
    const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
    const pending = state ? consumeOAuthState(String(state)) : null;
    if (oauthError) return redirectToDashboard("error", "denied", oauthDescription || oauthError);
    if (!code || !pending || pending.platform !== "linkedin") return redirectToDashboard("error", "session-expired");
    const result = await completeLinkedInConnection(pending.userId, String(code));
    return redirectToDashboard("linkedin-success", null, `${result.name} connected.`);
  } catch (error) {
    console.error("LinkedIn OAuth callback error:", error.message);
    return redirectToDashboard("error", "unexpected", error.message || "LinkedIn returned an unexpected error while connecting your account.");
  }
});

async function prepareLinkedInImage(user, mediaUrl) {
  if (!/^https:\/\//i.test(mediaUrl)) throw new Error("LinkedIn media must use an HTTPS image URL.");
  const conn = user.connections?.linkedin;
  if (!conn?.connected || !conn.accessTokenEncrypted || !conn.memberUrn) throw new Error("LinkedIn is not connected.");
  const token = decryptToken(conn.accessTokenEncrypted);
  const source = await fetch(mediaUrl, { redirect: "follow" });
  if (!source.ok) throw new Error("Could not fetch the image URL.");
  const contentType = (source.headers.get("content-type") || "").split(";")[0].toLowerCase();
  if (!["image/jpeg", "image/png", "image/gif"].includes(contentType)) throw new Error("LinkedIn v1 supports JPG, PNG, or GIF image URLs only.");
  const length = Number(source.headers.get("content-length") || 0);
  if (length > 10 * 1024 * 1024) throw new Error("Image is too large. Keep it under 10 MB.");
  const buffer = Buffer.from(await source.arrayBuffer());
  if (buffer.length > 10 * 1024 * 1024) throw new Error("Image is too large. Keep it under 10 MB.");

  const init = await linkedinFetch("https://api.linkedin.com/rest/images?action=initializeUpload", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ initializeUploadRequest: { owner: conn.memberUrn } })
  });
  const value = init.data.value || {};
  if (!value.uploadUrl || !value.image) throw new Error("LinkedIn did not return an image upload URL.");
  const upload = await fetch(value.uploadUrl, { method: "PUT", headers: { "Content-Type": contentType }, body: buffer });
  if (!upload.ok) throw new Error(`LinkedIn image upload failed (${upload.status}).`);
  return { urn: value.image, contentType };
}

async function publishLinkedInContent(user, item) {
  const conn = user.connections?.linkedin;
  if (!conn?.connected || !conn.accessTokenEncrypted || !conn.memberUrn) throw new Error("LinkedIn is not connected.");
  const token = decryptToken(conn.accessTokenEncrypted);
  const content = {
    author: conn.memberUrn,
    commentary: item.body || item.title || "",
    visibility: "PUBLIC",
    distribution: { feedDistribution: "MAIN_FEED", targetEntities: [], thirdPartyDistributionChannels: [] },
    lifecycleState: "PUBLISHED",
    isReshareDisabledByAuthor: false
  };
  if (item.mediaUrn) {
    content.content = { media: { id: item.mediaUrn, ...(item.title ? { title: item.title } : {}), ...(item.mediaAltText ? { altText: item.mediaAltText } : {}) } };
  }
  const { response } = await linkedinFetch("https://api.linkedin.com/rest/posts", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(content)
  });
  return response.headers.get("x-restli-id") || "";
}

// Publish due LinkedIn schedules. The job is intentionally small and idempotent:
// each item is marked published only after LinkedIn returns success.
let schedulerBusy = false;
async function processLinkedInSchedules() {
  if (schedulerBusy || mongoose.connection.readyState !== 1) return;
  schedulerBusy = true;
  try {
    const due = await Content.find({ platforms: "linkedin", status: "scheduled", scheduledFor: { $lte: new Date() } }).limit(10);
    for (const item of due) {
      try {
        const user = await findUserById(item.userId);
        if (!user) throw new Error("Account not found.");
        await publishLinkedInContent(user, item);
        item.status = "published";
        item.publishedAt = new Date();
        await item.save();
      } catch (error) {
        console.error(`LinkedIn scheduled post ${item._id} failed:`, error.message);
      }
    }
  } catch (error) {
    console.error("LinkedIn scheduler error:", error.message);
  } finally { schedulerBusy = false; }
}
setInterval(processLinkedInSchedules, 60 * 1000);


app.get("/api/account/export", auth, async (req,res)=>{
  try {
    const user=await findUserById(req.auth.id); if(!user)return res.status(404).json({message:"Account not found."});
    const content=await Content.find({userId:req.auth.id}).select("-__v").lean();
    const notifications=await Notification.find({userId:req.auth.id}).select("-__v").lean();
    const exported={account:{id:String(user._id),name:user.name,username:user.username,email:user.email,phone:user.phone,role:user.role||"",discoverySource:user.discoverySource||"",createdAt:user.createdAt},connections:safeUser(user).connections,content,notifications};
    res.json(exported);
  } catch { res.status(500).json({message:"Unable to export your data right now."}); }
});

app.post("/api/account/change-password", auth, async (req,res)=>{
  try {
    const user=await findUserById(req.auth.id), current=String(req.body.currentPassword||""), next=String(req.body.newPassword||"");
    if(!user)return res.status(404).json({message:"Account not found."});
    if(!current||!next)return res.status(400).json({message:"Enter your current and new password."});
    if(next.length<8)return res.status(400).json({message:"New password must be at least 8 characters."});
    if(!(await bcrypt.compare(current,user.passwordHash)))return res.status(400).json({message:"Current password is incorrect."});
    user.passwordHash=await bcrypt.hash(next,12); await user.save(); res.json({message:"Password changed."});
  } catch { res.status(500).json({message:"Unable to change your password right now."}); }
});
async function adminOnly(req,res,next){
  try { const user=await User.findById(req.auth.id).select("role disabled"); if(!user||user.disabled||user.role!=="admin") return res.status(403).json({message:"Admin access required."}); next(); }
  catch { return res.status(403).json({message:"Admin access required."}); }
}
app.get("/api/admin/users",auth,adminOnly,async(req,res)=>{
  const users=await User.find({}).sort({createdAt:-1}).lean();
  const content=await Content.find({}).sort({createdAt:-1}).lean();
  const adminUsers=users.map(u=>({
    ...safeUser(u), createdAt:u.createdAt, updatedAt:u.updatedAt,
    discoverySource:u.discoverySource||"",
    connections:{
      facebook:{connected:Boolean(u.connections?.facebook?.connected),pageId:u.connections?.facebook?.pageId||"",pageName:u.connections?.facebook?.pageName||""},
      instagram:{connected:Boolean(u.connections?.instagram?.connected),igBusinessAccountId:u.connections?.instagram?.igBusinessAccountId||"",igUsername:u.connections?.instagram?.igUsername||"",pageId:u.connections?.instagram?.pageId||""},
      linkedin:{connected:Boolean(u.connections?.linkedin?.connected),memberId:u.connections?.linkedin?.memberId||"",memberUrn:u.connections?.linkedin?.memberUrn||"",name:u.connections?.linkedin?.name||"",email:u.connections?.linkedin?.email||""}
    }
  }));
  res.json({users:adminUsers,content});
});
app.patch("/api/admin/users/:id",auth,adminOnly,async(req,res)=>{
  const user=await User.findById(req.params.id); if(!user)return res.status(404).json({message:"User not found."});
  if(String(user._id)===String(req.auth.id)&&req.body.disabled===true)return res.status(400).json({message:"You cannot disable your own admin account."});
  if(typeof req.body.disabled==="boolean")user.disabled=req.body.disabled;
  await user.save(); res.json({user:safeUser(user)});
});
app.delete("/api/admin/users/:id",auth,adminOnly,async(req,res)=>{
  if(String(req.params.id)===String(req.auth.id))return res.status(400).json({message:"You cannot delete your own admin account."});
  const user=await User.findByIdAndDelete(req.params.id); if(!user)return res.status(404).json({message:"User not found."});
  await Content.deleteMany({userId:req.params.id}); await Notification.deleteMany({userId:req.params.id}); res.json({message:"User deleted."});
});
app.post("/api/admin/notifications",auth,adminOnly,async(req,res)=>{
  const title=String(req.body.title||"").trim(), message=String(req.body.message||"").trim();
  if(!title||!message)return res.status(400).json({message:"Title and message are required."});
  let users;
  if(req.body.all===true)users=await User.find({}, "_id").lean();
  else users=await User.find({_id:{$in:Array.isArray(req.body.userIds)?req.body.userIds:[]}}, "_id").lean();
  if(!users.length)return res.status(400).json({message:"Choose at least one user."});
  await Notification.insertMany(users.map(u=>({userId:u._id,title,message})));
  res.json({message:`Notification sent to ${users.length} user${users.length===1?"":"s"}.`,count:users.length});
});
app.get("/api/notifications",auth,async(req,res)=>res.json({items:await Notification.find({userId:req.auth.id}).sort({createdAt:-1}).limit(50).lean()}));
app.post("/api/notifications/:id/read",auth,async(req,res)=>{await Notification.updateOne({_id:req.params.id,userId:req.auth.id},{$set:{read:true}});res.json({ok:true});});
app.get("/api/legal",async(req,res)=>{const legal=await Legal.findOne({key:"site"}).lean();res.json({legal:legal||{terms:"",privacy:""}});});
app.post("/api/admin/legal",auth,adminOnly,async(req,res)=>{const legal=await Legal.findOneAndUpdate({key:"site"},{key:"site",terms:String(req.body.terms||""),privacy:String(req.body.privacy||""),updatedAt:new Date()},{upsert:true,new:true});res.json({legal});});

// --- Facebook / Instagram OAuth connect flows ---
// Facebook and Instagram are intentionally separate connections. For the current
// rollout, Facebook is the only Meta connection being configured. Instagram stays
// independent and is enabled later with its own configuration ID.
const FB_APP_ID = process.env.FB_APP_ID;
const FB_APP_SECRET = process.env.FB_APP_SECRET;
const FB_CONFIG_ID = process.env.FB_CONFIG_ID || "1528947972253797";
const INSTAGRAM_CONFIG_ID = process.env.INSTAGRAM_CONFIG_ID;
const FB_REDIRECT_URI = process.env.FB_REDIRECT_URI || `${APP_BASE_URL}/api/connections/facebook/callback`;
const FB_GRAPH_VERSION = "v21.0";

// Short-lived, in-memory map of OAuth state -> user/platform. State expires in
// 10 minutes and is consumed once, preventing a callback from being replayed.
const pendingOAuthStates = new Map();
function createOAuthState(userId, platform) {
  const state = crypto.randomBytes(16).toString("hex");
  pendingOAuthStates.set(state, {
    userId: String(userId),
    platform,
    expiresAt: Date.now() + 10 * 60 * 1000
  });
  return state;
}
function consumeOAuthState(state) {
  const entry = pendingOAuthStates.get(state);
  pendingOAuthStates.delete(state);
  if (!entry || entry.expiresAt < Date.now()) return null;
  return entry;
}

function buildMetaOAuthUrl(configId, state) {
  const params = new URLSearchParams({
    client_id: FB_APP_ID,
    redirect_uri: FB_REDIRECT_URI,
    config_id: configId,
    response_type: "code",
    state
  });
  return `https://www.facebook.com/${FB_GRAPH_VERSION}/dialog/oauth?${params.toString()}`;
}

// Start Facebook-only Login for Business. FB_CONFIG_ID is the working Meta
// Login for Business configuration supplied for the current Facebook rollout.
app.get("/api/connections/facebook/start", auth, (req, res) => {
  try {
    if (!FB_APP_ID || !FB_APP_SECRET || !FB_CONFIG_ID) {
      return res.status(500).json({ message: "Facebook connection is not configured on the server yet." });
    }
    const state = createOAuthState(req.auth.id, "facebook");
    res.json({ url: buildMetaOAuthUrl(FB_CONFIG_ID, state) });
  } catch (error) {
    console.error("Facebook OAuth start error:", error);
    res.status(500).json({ message: "Unable to start the Facebook connection." });
  }
});

// Instagram remains a separate future flow. Do not reuse the Facebook config for it.
app.get("/api/connections/instagram/start", auth, (req, res) => {
  try {
    if (!FB_APP_ID || !FB_APP_SECRET || !INSTAGRAM_CONFIG_ID) {
      return res.status(500).json({ message: "Instagram connection is not configured on the server yet." });
    }
    const state = createOAuthState(req.auth.id, "instagram");
    res.json({ url: buildMetaOAuthUrl(INSTAGRAM_CONFIG_ID, state) });
  } catch (error) {
    console.error("Instagram OAuth start error:", error);
    res.status(500).json({ message: "Unable to start the Instagram connection." });
  }
});

async function exchangeMetaCode(code) {
  const tokenParams = new URLSearchParams({
    client_id: FB_APP_ID,
    client_secret: FB_APP_SECRET,
    redirect_uri: FB_REDIRECT_URI,
    code: String(code)
  });
  const tokenResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/oauth/access_token?${tokenParams.toString()}`);
  const tokenData = await tokenResp.json();
  if (!tokenResp.ok || !tokenData.access_token) {
    throw new Error(tokenData.error?.message || "Meta token exchange failed.");
  }
  return {
    accessToken: tokenData.access_token,
    expiresAt: tokenData.expires_in
      ? new Date(Date.now() + Number(tokenData.expires_in) * 1000)
      : null
  };
}

async function completeFacebookConnection(userId, code) {
  const user = await findUserById(userId);
  if (!user) throw new Error("Account not found.");

  const { accessToken, expiresAt } = await exchangeMetaCode(code);
  const meResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/me?fields=id&access_token=${encodeURIComponent(accessToken)}`);
  const meData = await meResp.json();
  if (!meResp.ok) throw new Error(meData.error?.message || "Could not read the connected Facebook account.");

  const pagesResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/me/accounts?access_token=${encodeURIComponent(accessToken)}`);
  const pagesData = await pagesResp.json();
  if (!pagesResp.ok) throw new Error(pagesData.error?.message || "Could not list Facebook Pages.");

  const page = (pagesData.data || [])[0];
  if (!page) throw new Error("No Facebook Pages were granted to this connection.");

  const pageToken = page.access_token || accessToken;
  user.connections = user.connections || {};
  user.connections.facebook = {
    connected: true,
    fbUserId: meData.id || "",
    pageId: page.id,
    pageName: page.name || "",
    accessTokenEncrypted: encryptToken(pageToken),
    tokenExpiresAt: expiresAt
  };
  user.socials = { ...user.socials, facebook: true };
  await saveUser(user);
  return { pageName: page.name || "" };
}

async function completeInstagramConnection(userId, code) {
  const user = await findUserById(userId);
  if (!user) throw new Error("Account not found.");

  const { accessToken, expiresAt } = await exchangeMetaCode(code);
  const pagesResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/me/accounts?access_token=${encodeURIComponent(accessToken)}`);
  const pagesData = await pagesResp.json();
  if (!pagesResp.ok) throw new Error(pagesData.error?.message || "Could not list the Pages available to Instagram.");

  let selected = null;
  let igProfile = null;
  for (const page of pagesData.data || []) {
    const pageToken = page.access_token || accessToken;
    const igResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/${page.id}?fields=instagram_business_account&access_token=${encodeURIComponent(pageToken)}`);
    const igData = await igResp.json();
    if (!igResp.ok) continue;
    const igId = igData.instagram_business_account?.id;
    if (!igId) continue;

    const profileResp = await fetch(`https://graph.facebook.com/${FB_GRAPH_VERSION}/${igId}?fields=username&access_token=${encodeURIComponent(pageToken)}`);
    const profileData = await profileResp.json();
    if (!profileResp.ok) continue;

    selected = { page, pageToken, igId };
    igProfile = profileData;
    break;
  }

  if (!selected) throw new Error("No Instagram Business or Creator account was found on the Pages granted to this connection.");

  user.connections = user.connections || {};
  user.connections.instagram = {
    connected: true,
    igBusinessAccountId: selected.igId,
    igUsername: igProfile.username || "",
    pageId: selected.page.id,
    accessTokenEncrypted: encryptToken(selected.pageToken),
    tokenExpiresAt: expiresAt
  };
  user.socials = { ...user.socials, instagram: true };
  await saveUser(user);
  return { igUsername: igProfile.username || "" };
}

// Both providers return to the same callback URI. The signed-in platform is
// recovered from the one-time OAuth state, so Facebook never silently creates
// an Instagram connection and Instagram never marks Facebook connected.

// Facebook uses the server-side Login for Business redirect flow below.
// The browser SDK exchange route was intentionally removed so there is only
// one canonical Facebook OAuth path and one state/callback implementation.

app.get("/api/connections/facebook/callback", async (req, res) => {
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status });
    if (reason) params.set("reason", reason);
    if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`/dashboard.html?${params.toString()}`);
  };

  try {
    const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
    const pending = state ? consumeOAuthState(String(state)) : null;
    if (oauthError) return redirectToDashboard("error", "denied", oauthDescription || oauthError);
    if (!code || !pending) return redirectToDashboard("error", "session-expired");

    if (pending.platform === "facebook") {
      const result = await completeFacebookConnection(pending.userId, String(code));
      return redirectToDashboard("facebook-success", null, result.pageName ? `${result.pageName} connected.` : "Facebook connected successfully.");
    }
    if (pending.platform === "instagram") {
      const result = await completeInstagramConnection(pending.userId, String(code));
      return redirectToDashboard("instagram-success", null, result.igUsername ? `@${result.igUsername} connected.` : "Instagram connected successfully.");
    }
    return redirectToDashboard("error", "unexpected", "Unknown connection type.");
  } catch (error) {
    console.error("Meta OAuth callback error:", error.message);
    return redirectToDashboard("error", "unexpected", error.message || "Meta returned an unexpected error while connecting your account.");
  }
});

app.post("/api/connections/:platform/disconnect", auth, async (req, res) => {
  try {
    const platform = req.params.platform;
    if (!["instagram", "facebook", "linkedin"].includes(platform)) return res.status(400).json({ message: "Unknown platform." });
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
