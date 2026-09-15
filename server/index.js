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
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || "";
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || "";
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || "";

app.use(cors());
app.use(express.json({ limit: "1mb" }));
const mediaUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024, files: 35 } });

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
  role: { type: String, enum: ["user", "admin"], default: "user" },
  profileType: { type: String, default: "" },
  discoverySource: { type: String, default: "" },
  socials: {
    instagram: { type: Boolean, default: false },
    facebook: { type: Boolean, default: false },
    tiktok: { type: Boolean, default: false },
    linkedin: { type: Boolean, default: false },
    x: { type: Boolean, default: false },
    youtube: { type: Boolean, default: false }
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
    },
    x: {
      connected: { type: Boolean, default: false },
      userId: String,
      username: String,
      name: String,
      accessTokenEncrypted: String,
      refreshTokenEncrypted: String,
      tokenExpiresAt: Date,
      refreshTokenExpiresAt: Date
    },
    tiktok: {
      connected: { type: Boolean, default: false },
      openId: String,
      username: String,
      name: String,
      accessTokenEncrypted: String,
      refreshTokenEncrypted: String,
      tokenExpiresAt: Date,
      refreshTokenExpiresAt: Date
    },
    youtube: {
      connected: { type: Boolean, default: false },
      channelId: String,
      channelTitle: String,
      accessTokenEncrypted: String,
      refreshTokenEncrypted: String,
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
  title: { type: String, default: "", trim: true, maxlength: 120 },
  body: { type: String, default: "", maxlength: 5000 },
  mediaUrl: { type: String, default: "" },
  mediaUrn: { type: String, default: "" },
  mediaType: { type: String, default: "" },
  mediaAltText: { type: String, default: "", maxlength: 300 },
  mediaAssets: { type: [mongoose.Schema.Types.Mixed], default: [] },
  // Optional per-platform content overrides, e.g. { linkedin: { body: "..." }, tiktok: { mediaAssets: [...] } }.
  // A platform key is only present if the user chose to customize that platform; only the fields
  // they opted into (body and/or mediaAssets) are present. Anything absent falls back to the shared body/mediaAssets above.
  perPlatformOverrides: { type: mongoose.Schema.Types.Mixed, default: undefined },
  // TikTok-only posting settings (privacy level, comments/duet/stitch, branded/AI content disclosure).
  // Not applicable to and never used by any other platform.
  tiktokSettings: { type: mongoose.Schema.Types.Mixed, default: undefined },
  externalPostUrn: { type: String, default: "" },
  publishErrors: { type: [mongoose.Schema.Types.Mixed], default: [] },
  externalPosts: {
    linkedin: { type: String, default: "" },
    x: { type: String, default: "" },
    tiktok: { type: String, default: "" }
  },
  platforms: { type: [String], default: [] },
  status: { type: String, enum: ["draft", "scheduled", "published"], default: "draft" },
  scheduledFor: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  publishedAt: { type: Date, default: null }
}, { timestamps: true });

const Content = mongoose.model("Content", contentSchema);

const notificationSchema = new mongoose.Schema({ userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",index:true}, title:{type:String,required:true,trim:true,maxlength:120}, message:{type:String,required:true,trim:true,maxlength:2000}, read:{type:Boolean,default:false}, createdAt:{type:Date,default:Date.now} },{timestamps:true});
const Notification = mongoose.model("Notification", notificationSchema);

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
    role: user.role === "admin" ? "admin" : "user",
    profileType: user.profileType || "",
    discoverySource: user.discoverySource || "",
    socials: user.socials || { instagram: false, facebook: false, tiktok: false, linkedin: false, x: false },
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
      },
      x: {
        connected: Boolean(conn.x && conn.x.connected),
        name: conn.x ? conn.x.name || "" : "",
        username: conn.x ? conn.x.username || "" : ""
      },
      tiktok: {
        connected: Boolean(conn.tiktok && conn.tiktok.connected),
        name: conn.tiktok ? conn.tiktok.name || "" : "",
        username: conn.tiktok ? conn.tiktok.username || "" : ""
      },
      youtube: {
        connected: Boolean(conn.youtube && conn.youtube.connected),
        channelId: conn.youtube ? conn.youtube.channelId || "" : "",
        channelTitle: conn.youtube ? conn.youtube.channelTitle || "" : ""
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
      role: "user",
      profileType: "",
      discoverySource: "",
      socials: { instagram: false, facebook: false, tiktok: false, linkedin: false, x: false, youtube: false },
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
    if (user.disabled) return res.status(403).json({ message: "This account has been disabled." });
    if (user.role === "admin") return res.status(403).json({ message: "Use the admin sign-in page for this account." });
    if (user.role !== "user") { user.role = "user"; await user.save(); }
    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch {
    res.status(500).json({ message: "Unable to sign in right now." });
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      return res.status(401).json({ message: "Email or password is incorrect." });
    if (user.disabled) return res.status(403).json({ message: "This account has been disabled." });
    if (user.role !== "admin") return res.status(403).json({ message: "This account does not have admin access." });
    res.json({ token: tokenFor(user), user: safeUser(user) });
  } catch {
    res.status(500).json({ message: "Unable to sign in right now." });
  }
});


function cloudinaryReady() {
  return Boolean(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET);
}
function cloudinarySignature(params) {
  const canonical = Object.keys(params).sort().filter(k => params[k] !== undefined && params[k] !== null && params[k] !== "")
    .map(k => `${k}=${params[k]}`).join("&");
  return crypto.createHash("sha1").update(canonical + CLOUDINARY_API_SECRET).digest("hex");
}
async function uploadToCloudinary(file, userId) {
  if (!cloudinaryReady()) throw new Error("Cloudinary is not configured yet. Add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET in Render.");
  const timestamp = Math.floor(Date.now() / 1000);
  const folder = `creovah/${String(userId)}`;
  const signature = cloudinarySignature({ folder, timestamp });
  const form = new FormData();
  form.append("file", new Blob([file.buffer], { type: file.mimetype || "application/octet-stream" }), file.originalname || "media");
  form.append("api_key", CLOUDINARY_API_KEY);
  form.append("timestamp", String(timestamp));
  form.append("folder", folder);
  form.append("signature", signature);
  const response = await fetch(`https://api.cloudinary.com/v1_1/${encodeURIComponent(CLOUDINARY_CLOUD_NAME)}/auto/upload`, { method: "POST", body: form });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.secure_url) throw new Error(data?.error?.message || `Cloudinary upload failed (${response.status}).`);
  return {
    publicId: data.public_id || "", secureUrl: data.secure_url, resourceType: data.resource_type || "auto",
    format: data.format || "", bytes: Number(data.bytes || file.size || 0), width: Number(data.width || 0), height: Number(data.height || 0),
    duration: Number(data.duration || 0), originalName: file.originalname || "media", mimeType: file.mimetype || ""
  };
}
function mediaProxyToken(asset) {
  const payload = Buffer.from(JSON.stringify({ url: asset.secureUrl, exp: Date.now() + 60 * 60 * 1000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function mediaProxyUrl(asset) { return `${APP_BASE_URL}/api/media/public/${mediaProxyToken(asset)}`; }
app.get("/api/media/public/:token", async (req, res) => {
  try {
    const [payload, sig] = String(req.params.token || "").split(".");
    if (!payload || !sig) return res.status(404).end();
    const expected = crypto.createHmac("sha256", JWT_SECRET).update(payload).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return res.status(403).end();
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.url || Number(data.exp) < Date.now() || !/^https:\/\//i.test(data.url)) return res.status(404).end();
    const upstream = await fetch(data.url, { redirect: "follow" });
    if (!upstream.ok) return res.status(upstream.status).end();
    res.setHeader("Content-Type", upstream.headers.get("content-type") || "application/octet-stream");
    res.setHeader("Cache-Control", "public, max-age=300");
    if (upstream.headers.get("content-length")) res.setHeader("Content-Length", upstream.headers.get("content-length"));
    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.end(buffer);
  } catch { res.status(404).end(); }
});

app.post("/api/media/upload", auth, mediaUpload.array("media", 35), async (req, res) => {
  try {
    const files = Array.isArray(req.files) ? req.files : [];
    if (!files.length) return res.status(400).json({ message: "Choose at least one photo or video." });
    const allowed = new Set(["image/jpeg","image/png","image/gif","image/webp","video/mp4","video/quicktime","video/webm"]);
    for (const file of files) {
      if (!allowed.has(String(file.mimetype || "").toLowerCase())) return res.status(400).json({ message: `${file.originalname || "This file"} is not a supported photo or video format.` });
      if (file.size > 200 * 1024 * 1024) return res.status(400).json({ message: `${file.originalname || "This file"} is larger than 200 MB.` });
    }
    const assets = [];
    for (const file of files) assets.push(await uploadToCloudinary(file, req.auth.id));
    res.json({ assets });
  } catch (error) {
    console.error("Cloudinary media upload error:", error);
    res.status(500).json({ message: error.message || "Unable to save your media right now." });
  }
});

// Real API constraints per platform, enforced here on the server so they can never be bypassed by
// the client (a modified request body, a stale UI, or a bug in the composer's own validation).
// Sizes in bytes. maxImages/maxVideos: 0 means that media type is not accepted at all.
const PLATFORM_RULES = {
  linkedin: { name: "LinkedIn", maxText: 3000, maxImages: 1, maxVideos: 1, mixedMedia: false, mediaRequired: false, maxImageBytes: 10 * 1024 * 1024, maxVideoBytes: 5 * 1024 * 1024 * 1024, imageTypes: ["image/jpeg", "image/png", "image/gif"], videoTypes: ["video/mp4"] },
  x: { name: "X", maxText: 280, maxImages: 4, maxVideos: 1, mixedMedia: false, mediaRequired: false, maxImageBytes: 5 * 1024 * 1024, maxVideoBytes: 512 * 1024 * 1024, imageTypes: ["image/jpeg", "image/png", "image/gif", "image/webp"], videoTypes: ["video/mp4", "video/quicktime", "video/webm"] },
  instagram: { name: "Instagram", maxText: 2200, maxImages: 10, maxVideos: 1, mixedMedia: false, mediaRequired: true, maxImageBytes: 30 * 1024 * 1024, maxVideoBytes: 4 * 1024 * 1024 * 1024, imageTypes: ["image/jpeg", "image/png"], videoTypes: ["video/mp4", "video/quicktime"] },
  facebook: { name: "Facebook", maxText: 63206, maxImages: 10, maxVideos: 1, mixedMedia: false, mediaRequired: false, maxImageBytes: 30 * 1024 * 1024, maxVideoBytes: 10 * 1024 * 1024 * 1024, imageTypes: ["image/jpeg", "image/png", "image/gif", "image/webp"], videoTypes: ["video/mp4", "video/quicktime"] },
  tiktok: { name: "TikTok", maxText: 4000, maxImages: 35, maxVideos: 1, mixedMedia: false, mediaRequired: true, maxImageBytes: 20 * 1024 * 1024, maxVideoBytes: 4 * 1024 * 1024 * 1024, imageTypes: ["image/jpeg", "image/png", "image/webp"], videoTypes: ["video/mp4", "video/quicktime", "video/webm"] },
  youtube: { name: "YouTube", maxText: 5000, maxImages: 0, maxVideos: 1, mixedMedia: false, mediaRequired: true, maxImageBytes: 0, maxVideoBytes: 128 * 1024 * 1024 * 1024, imageTypes: [], videoTypes: ["video/mp4", "video/quicktime", "video/webm", "video/x-msvideo", "video/x-matroska"] }
};

// Builds one error, and — when the post targets more than one platform — appends a pointer at
// "Customize per platform" so the user has a concrete way to fix a conflict that only exists
// because the same content is being sent to platforms with different rules.
function platformError(platform, message, platformCount) {
  const suffix = platformCount > 1 ? " Use \"Customize per platform\" to give this platform its own content." : "";
  return { platform, message: message + suffix };
}

function validateContentForPlatforms({ platforms, body, mediaAssets, action, tiktokSettings, perPlatformOverrides }) {
  const errors = [];
  const platformCount = platforms.length;
  for (const platform of platforms) {
    const rule = PLATFORM_RULES[platform]; if (!rule) continue;
    const override = perPlatformOverrides && perPlatformOverrides[platform];
    const text = String((override && override.body !== undefined ? override.body : body) || "");
    const assets = Array.isArray(override && override.mediaAssets !== undefined ? override.mediaAssets : mediaAssets) ? (override && override.mediaAssets !== undefined ? override.mediaAssets : mediaAssets) : [];
    const images = assets.filter(a => String(a?.mimeType || "").startsWith("image/") || String(a?.resourceType || "") === "image");
    const videos = assets.filter(a => String(a?.mimeType || "").startsWith("video/") || String(a?.resourceType || "") === "video");
    const err = (message) => errors.push(platformError(platform, message, platformCount));

    if (text.length > rule.maxText) err(`${rule.name} allows up to ${rule.maxText.toLocaleString()} characters. Your post has ${text.length.toLocaleString()}.`);
    if (rule.mediaRequired && !assets.length) err(`${rule.name} requires a photo or video for this post.`);

    if (rule.maxImages === 0 && images.length) {
      err(`${rule.name} does not accept photos — it only accepts video uploads.`);
    } else if (images.length > rule.maxImages) {
      err(`${rule.name} allows up to ${rule.maxImages} photo${rule.maxImages === 1 ? "" : "s"} in one post.`);
    }
    if (rule.maxVideos === 0 && videos.length) {
      err(`${rule.name} does not accept video uploads.`);
    } else if (videos.length > rule.maxVideos) {
      err(`${rule.name} allows ${rule.maxVideos === 1 ? "one video" : `${rule.maxVideos} videos`} in one post.`);
    }
    if (!rule.mixedMedia && images.length && videos.length) err(`${rule.name} posts must contain photos or one video, not a mixture of both.`);

    const badImageType = images.find(a => rule.imageTypes.length && !rule.imageTypes.includes(String(a?.mimeType || "").toLowerCase()));
    if (badImageType) err(`${rule.name} only accepts ${rule.imageTypes.map(t => t.split("/")[1].toUpperCase()).join(", ")} images.`);
    const badVideoType = videos.find(a => rule.videoTypes.length && !rule.videoTypes.includes(String(a?.mimeType || "").toLowerCase()));
    if (badVideoType) err(`${rule.name} only accepts ${rule.videoTypes.map(t => t.split("/")[1].toUpperCase()).join(", ")} video files.`);

    const oversizedImage = images.find(a => Number(a?.bytes || 0) > rule.maxImageBytes);
    if (oversizedImage) err(`Each ${rule.name} photo must be ${(rule.maxImageBytes / (1024 * 1024)).toFixed(0)} MB or smaller.`);
    const oversizedVideo = videos.find(a => Number(a?.bytes || 0) > rule.maxVideoBytes);
    if (oversizedVideo) {
      const limitGb = rule.maxVideoBytes / (1024 * 1024 * 1024);
      err(`${rule.name} videos must be ${limitGb >= 1 ? `${limitGb.toFixed(0)} GB` : `${(rule.maxVideoBytes / (1024 * 1024)).toFixed(0)} MB`} or smaller.`);
    }

    if (platform === "tiktok" && videos.length && action === "schedule") err("TikTok scheduling is not available yet. Publish TikTok posts now instead.");
    if (platform === "tiktok" && action === "publish") {
      const ts = tiktokSettings || {};
      if (!ts.privacyLevel) err("Choose who can view this TikTok post before publishing.");
      if (ts.isBrandedContent && ts.privacyLevel === "SELF_ONLY") err("Branded content cannot be set to private on TikTok. Choose a different privacy setting or turn off branded content.");
    }
    if ((platform === "instagram" || platform === "facebook") && (action === "publish" || action === "schedule")) err(`${rule.name} publishing is not connected to Creovah yet.`);
  }
  return errors;
}
function validateMediaAssetsOwnership(assets, userId) {
  const prefix = `creovah/${String(userId)}/`;
  return (Array.isArray(assets) ? assets : []).every(asset => {
    const publicId = String(asset?.publicId || "");
    const secureUrl = String(asset?.secureUrl || "");
    return publicId.startsWith(prefix) && /^https:\/\//i.test(secureUrl);
  });
}
function validationMessage(errors) {
  return errors.map(e => `${PLATFORM_RULES[e.platform]?.name || e.platform}: ${e.message}`).join("\n");
}

app.get("/api/content", auth, async (req, res) => {
  try {
    const items = await Content.find({ userId: req.auth.id }).sort({ scheduledFor: 1, createdAt: -1 }).limit(100).lean();
    res.json({ items });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Unable to load your content right now." });
  }
});

async function waitForLinkedInMedia(token, urn, kind, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  const encoded = encodeURIComponent(urn);
  const base = kind === "video" ? "https://api.linkedin.com/rest/videos/" : "https://api.linkedin.com/rest/images/";
  let lastStatus = "PROCESSING";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(base + encoded, {
        headers: { Authorization: `Bearer ${token}`, "X-Restli-Protocol-Version": "2.0.0" }
      });
      const data = await response.json().catch(() => ({}));
      if (response.ok) {
        lastStatus = String(data.status || "PROCESSING").toUpperCase();
        if (lastStatus === "AVAILABLE") return data;
        if (["PROCESSING_FAILED", "CLIENT_ERROR", "SERVER_ERROR", "INCOMPLETE"].includes(lastStatus)) {
          throw new Error(`LinkedIn media processing failed (${lastStatus}).`);
        }
      }
    } catch (error) {
      if (error.message && error.message.includes("media processing failed")) throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
  throw new Error(`LinkedIn media is still processing (${lastStatus}). Please try publishing again in a moment.`);
}

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
      return res.json({ urn: value.image, mediaType: "image", status: "PROCESSING" });
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
      return res.json({ urn: value.video, mediaType: "video", status: "PROCESSING" });
    }
    return res.status(400).json({ message: "Use a JPG, PNG, GIF or MP4 file." });
  } catch (error) { console.error("LinkedIn media upload error:", error); res.status(500).json({ message: error.message || "Unable to upload media to LinkedIn." }); }
});

app.post("/api/content", auth, async (req, res) => {
  try {
    const body = String(req.body.body || "").trim();
    const platforms = Array.isArray(req.body.platforms) ? req.body.platforms.filter(p => Object.prototype.hasOwnProperty.call(PLATFORM_RULES, p)) : [];
    const requestedStatus = ["draft", "scheduled"].includes(req.body.status) ? req.body.status : "draft";
    const publishNow = Boolean(req.body.publishNow);
    const action = publishNow ? "publish" : requestedStatus === "scheduled" ? "schedule" : "draft";
    const mediaAssets = Array.isArray(req.body.mediaAssets) ? req.body.mediaAssets : [];
    if (!validateMediaAssetsOwnership(mediaAssets, req.auth.id)) return res.status(400).json({ message: "One or more media files are not valid Creovah media." });
    if (!body) return res.status(400).json({ message: "Write something for your post." });
    if (!platforms.length) return res.status(400).json({ message: "Choose at least one platform." });
    // Optional per-platform overrides: a platform gets its own body and/or media instead of the shared
    // content above. Only platforms actually selected for this post, and only fields the client sent,
    // are kept; anything else falls back to the shared body/mediaAssets at publish time.
    const rawOverrides = req.body.perPlatformOverrides && typeof req.body.perPlatformOverrides === "object" ? req.body.perPlatformOverrides : {};
    const perPlatformOverrides = {};
    for (const platform of Object.keys(rawOverrides)) {
      if (!platforms.includes(platform)) continue;
      const raw = rawOverrides[platform]; if (!raw || typeof raw !== "object") continue;
      const entry = {};
      if (typeof raw.body === "string") entry.body = raw.body.trim();
      if (Array.isArray(raw.mediaAssets)) {
        if (!validateMediaAssetsOwnership(raw.mediaAssets, req.auth.id)) return res.status(400).json({ message: `One or more custom media files for ${platform} are not valid Creovah media.` });
        entry.mediaAssets = raw.mediaAssets;
      }
      if (Object.keys(entry).length) perPlatformOverrides[platform] = entry;
    }
    // TikTok-only posting settings (privacy, comments/duet/stitch, branded/AI content disclosure).
    // Ignored for every other platform; only ever applied when tiktok is a selected platform.
    const rawTiktokSettings = req.body.tiktokSettings && typeof req.body.tiktokSettings === "object" ? req.body.tiktokSettings : {};
    const tiktokSettings = platforms.includes("tiktok") ? {
      privacyLevel: typeof rawTiktokSettings.privacyLevel === "string" ? rawTiktokSettings.privacyLevel : "",
      disableComment: Boolean(rawTiktokSettings.disableComment),
      disableDuet: Boolean(rawTiktokSettings.disableDuet),
      disableStitch: Boolean(rawTiktokSettings.disableStitch),
      isBrandedContent: Boolean(rawTiktokSettings.isBrandedContent),
      isAigc: Boolean(rawTiktokSettings.isAigc)
    } : undefined;
    let scheduledFor = null;
    if (requestedStatus === "scheduled") {
      scheduledFor = new Date(req.body.scheduledFor);
      if (Number.isNaN(scheduledFor.getTime())) return res.status(400).json({ message: "Choose a valid date and time." });
      if (scheduledFor <= new Date()) return res.status(400).json({ message: "Scheduled time must be in the future." });
    }
    const user = await findUserById(req.auth.id);
    if (!user) return res.status(404).json({ message: "Account not found." });
    for (const platform of platforms) {
      if (platform === "linkedin" && !user.connections?.linkedin?.connected) return res.status(400).json({ message: "Connect LinkedIn before publishing or scheduling LinkedIn content." });
      if (platform === "x" && !user.connections?.x?.connected) return res.status(400).json({ message: "Connect X before publishing or scheduling X content." });
      if (platform === "tiktok" && !user.connections?.tiktok?.connected) return res.status(400).json({ message: "Connect TikTok before publishing or scheduling TikTok content." });
      if (platform === "youtube" && !user.connections?.youtube?.connected) return res.status(400).json({ message: "Connect YouTube before publishing or scheduling YouTube content." });
    }
    if (action !== "draft") {
      const errors = validateContentForPlatforms({ platforms, body, mediaAssets, action, tiktokSettings, perPlatformOverrides });
      if (errors.length) return res.status(422).json({ message: "Fix the platform requirements before continuing.", errors });
    }
    const item = await Content.create({
      userId: req.auth.id, title: "", body, platforms, status: requestedStatus, scheduledFor,
      mediaUrl: mediaAssets[0]?.secureUrl || "", mediaUrn: "", mediaType: mediaAssets[0]?.resourceType === "video" || String(mediaAssets[0]?.mimeType || "").startsWith("video/") ? "video" : mediaAssets.length ? "image" : "",
      mediaAltText: String(req.body.mediaAltText || "").trim(), mediaAssets, tiktokSettings,
      perPlatformOverrides: Object.keys(perPlatformOverrides).length ? perPlatformOverrides : undefined
    });
    if (publishNow) {
      const externalPosts = {}; const publishErrors = [];
      for (const platform of platforms) {
        try {
          const platformItem = resolvePlatformItem(item, platform);
          if (platform === "linkedin") externalPosts.linkedin = await publishLinkedInContent(user, platformItem);
          else if (platform === "x") externalPosts.x = await publishXContent(user, platformItem);
          else if (platform === "tiktok") externalPosts.tiktok = await publishTikTokContent(user, platformItem);
          else if (platform === "youtube") externalPosts.youtube = await publishYouTubeContent(user, platformItem);
        } catch (platformError) {
          console.error(`${platform} publish failed for ${item._id}:`, platformError);
          publishErrors.push({ platform, message: platformError.message || `Unable to publish to ${platform}.` });
        }
      }
      item.externalPosts = externalPosts; item.externalPostUrn = Object.values(externalPosts).find(Boolean) || "";
      if (publishErrors.length && Object.values(externalPosts).some(Boolean)) {
        item.status = "published"; item.publishedAt = new Date(); item.scheduledFor = null; await item.save();
        return res.status(207).json({ item, message: "Published to some selected platforms, but one or more platforms could not be published.", errors: publishErrors });
      }
      if (publishErrors.length) { await Content.deleteOne({ _id: item._id }); return res.status(502).json({ message: "Creovah could not publish this post.", errors: publishErrors }); }
      item.status = "published"; item.publishedAt = new Date(); item.scheduledFor = null; await item.save();
    }
    res.status(201).json({ item });
  } catch (error) {
    console.error("Content save/publish error:", error);
    res.status(500).json({ message: error.message || "Unable to complete this action right now." });
  }
});

app.get("/api/content/:id/media-preview", auth, async (req, res) => {
  try {
    const item = await Content.findOne({ _id: req.params.id, userId: req.auth.id }).lean();
    if (!item) return res.status(404).json({ message: "Content not found." });
    if (Array.isArray(item.mediaAssets) && item.mediaAssets.length) return res.json({ url: item.mediaAssets[0].secureUrl, mediaType: item.mediaAssets[0].resourceType === "video" ? "video" : "image" });
    if (!item.mediaUrn) return res.status(404).json({ message: "This post has no media." });
    const user = await findUserById(req.auth.id); const conn = user?.connections?.linkedin;
    if (!conn?.connected || !conn.accessTokenEncrypted) return res.status(400).json({ message: "Reconnect LinkedIn to load the existing media." });
    const token = decryptToken(conn.accessTokenEncrypted); const endpoint=item.mediaType==="video"?"videos":"images"; const encoded=encodeURIComponent(item.mediaUrn);
    let response=await fetch(`https://api.linkedin.com/rest/${endpoint}/${encoded}`,{headers:{Authorization:`Bearer ${token}`,"Linkedin-Version":LINKEDIN_VERSION,"X-Restli-Protocol-Version":"2.0.0"}}); let data=await response.json().catch(()=>({}));
    if(!response.ok&&endpoint==="images"){response=await fetch(`https://api.linkedin.com/rest/images/${encoded}`,{headers:{Authorization:`Bearer ${token}`}});data=await response.json().catch(()=>({}));}
    if(!response.ok||!data.downloadUrl)return res.status(response.status||404).json({message:data.message||"LinkedIn has not made this media available yet."});
    res.json({url:data.downloadUrl,mediaType:item.mediaType,expiresAt:data.downloadUrlExpiresAt||null});
  } catch(error){res.status(500).json({message:error.message||"Unable to load the existing media."});}
});

app.patch("/api/content/:id", auth, async (req, res) => {
  try {
    const item = await Content.findOne({ _id: req.params.id, userId: req.auth.id });
    if (!item) return res.status(404).json({ message: "Content not found." });
    const body = String(req.body.body ?? item.body).trim();
    const title = "";
    if (!body) return res.status(400).json({ message: "Write something for your post." });

    const user = await findUserById(req.auth.id);
    if (item.status === "published" && item.platforms.includes("x") && item.externalPosts?.x) {
      const ageMs = Date.now() - new Date(item.publishedAt || item.updatedAt || Date.now()).getTime();
      if (ageMs > 30 * 60 * 1000) return res.status(400).json({ message: "X posts can only be edited within 30 minutes of publishing." });
    }
    if (item.status === "published") {
      if (item.platforms.includes("linkedin") && (item.externalPosts?.linkedin || item.externalPostUrn) && user?.connections?.linkedin?.connected) {
        const token = decryptToken(user.connections.linkedin.accessTokenEncrypted);
        const liUrn = item.externalPosts?.linkedin || item.externalPostUrn;
        await linkedinFetch(`https://api.linkedin.com/rest/posts/${encodeURIComponent(liUrn)}`, {
          method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "X-RestLi-Method": "PARTIAL_UPDATE" },
          body: JSON.stringify({ patch: { $set: { commentary: body } } })
        });
      }
      if (item.platforms.includes("x") && item.externalPosts?.x) {
        const x = await getXAccessToken(user);
        const result = await xApi("POST", "/2/tweets", x.token, { text: body, edit_options: { previous_post_id: item.externalPosts.x } });
        if (result?.data?.id) item.externalPosts.x = result.data.id;
      }
    }

    if (item.status === "scheduled" && Object.prototype.hasOwnProperty.call(req.body, "scheduledFor")) {
      const scheduledFor = new Date(req.body.scheduledFor);
      if (Number.isNaN(scheduledFor.getTime())) return res.status(400).json({ message: "Choose a valid date and time." });
      if (scheduledFor <= new Date()) return res.status(400).json({ message: "Scheduled time must be in the future." });
      item.scheduledFor = scheduledFor;
    }
    if (item.status === "draft" && Array.isArray(req.body.mediaAssets)) {
      item.mediaAssets = req.body.mediaAssets;
      item.mediaUrl = item.mediaAssets[0]?.secureUrl || "";
      item.mediaType = item.mediaAssets[0]?.resourceType === "video" || String(item.mediaAssets[0]?.mimeType || "").startsWith("video/") ? "video" : item.mediaAssets.length ? "image" : "";
    }
    item.title = ""; item.body = body; await item.save();
    let message = "Your changes were saved.";
    if (item.status === "published" && item.platforms.includes("tiktok") && item.externalPosts?.tiktok) {
      message = "Your changes were saved in Creovah. The published TikTok caption was not changed.";
      if (item.platforms.includes("x") && item.externalPosts?.x) message = "Your changes were saved in Creovah and updated on X. The published TikTok caption was not changed.";
    } else if (item.status === "published" && item.platforms.includes("x") && item.externalPosts?.x) {
      message = "Your changes were saved on X and Creovah.";
    }
    res.json({ item, message });
  } catch (error) { res.status(500).json({ message: error.message || "Unable to update this post right now." }); }
});

async function deleteFromCloudinary(asset) {
  if (!cloudinaryReady() || !asset?.publicId) return;
  const timestamp = Math.floor(Date.now() / 1000);
  const params = { public_id: asset.publicId, timestamp, invalidate: true, resource_type: asset.resourceType === "video" ? "video" : "image" };
  const signature = cloudinarySignature(params);
  const form = new FormData(); form.append("public_id", asset.publicId); form.append("timestamp", String(timestamp)); form.append("invalidate", "true"); form.append("api_key", CLOUDINARY_API_KEY); form.append("signature", signature);
  const response = await fetch(`https://api.cloudinary.com/v1_1/${encodeURIComponent(CLOUDINARY_CLOUD_NAME)}/${params.resource_type}/destroy`, { method:"POST", body:form });
  if (!response.ok) throw new Error(`Cloudinary media deletion failed (${response.status}).`);
}

app.delete("/api/content/:id", auth, async (req, res) => {
  try {
    const item = await Content.findOne({ _id: req.params.id, userId: req.auth.id });
    if (!item) return res.status(404).json({ message: "Content not found." });
    const user = await findUserById(req.auth.id);
    const external = item.externalPosts || {};
    const liUrn = external.linkedin || (item.platforms.includes("linkedin") ? item.externalPostUrn : "");
    if (item.platforms.includes("linkedin") && liUrn && user?.connections?.linkedin?.connected) {
      const token = decryptToken(user.connections.linkedin.accessTokenEncrypted);
      await linkedinFetch(`https://api.linkedin.com/rest/posts/${encodeURIComponent(liUrn)}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}`, "X-RestLi-Method": "DELETE" } });
    }
    if (item.platforms.includes("x") && external.x && user?.connections?.x?.connected) {
      const x = await getXAccessToken(user);
      await xApi("DELETE", `/2/tweets/${encodeURIComponent(external.x)}`, x.token);
    }
    if (Array.isArray(item.mediaAssets)) {
      for (const asset of item.mediaAssets) { try { await deleteFromCloudinary(asset); } catch (mediaError) { console.error("Cloudinary cleanup failed:", mediaError.message); } }
    }
    await Content.deleteOne({ _id: item._id });
    res.json({ message: "Post deleted." });
  } catch (error) { res.status(500).json({ message: error.message || "Unable to delete this post right now." }); }
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

    const allowedProfileTypes = ["influencer", "creator", "developer", "business", "agency", "marketer", "student", "other"];
    const allowedSources = ["instagram", "tiktok", "facebook", "google", "friend", "search", "other"];
    if (req.body.role && !allowedProfileTypes.includes(req.body.role)) return res.status(400).json({ message: "Invalid profile type." });
    if (req.body.discoverySource && !allowedSources.includes(req.body.discoverySource)) return res.status(400).json({ message: "Invalid discovery source." });

    if (req.body.role) user.profileType = req.body.role;
    if (user.role !== "admin") user.role = "user";
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
    const state = createOAuthState(req.auth.id, "linkedin", { returnTo: req.query.returnTo });
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
  const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
  const pending = state ? consumeOAuthState(String(state)) : null;
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status });
    if (reason) params.set("reason", reason);
    if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`${safeReturnTo(pending?.returnTo)}?${params.toString()}`);
  };
  try {
    if (oauthError) return redirectToDashboard("error", "denied", oauthDescription || oauthError);
    if (!code || !pending || pending.platform !== "linkedin") return redirectToDashboard("error", "session-expired");
    const result = await completeLinkedInConnection(pending.userId, String(code));
    return redirectToDashboard("linkedin-success", null, `${result.name} connected.`);
  } catch (error) {
    console.error("LinkedIn OAuth callback error:", error.message);
    return redirectToDashboard("error", "unexpected", error.message || "LinkedIn returned an unexpected error while connecting your account.");
  }
});


async function fetchAssetBuffer(asset) {
  if (!asset?.secureUrl) throw new Error("Saved media is missing its Cloudinary URL.");
  const response = await fetch(asset.secureUrl, { redirect: "follow" });
  if (!response.ok) throw new Error(`Could not retrieve saved media (${response.status}).`);
  const buffer = Buffer.from(await response.arrayBuffer());
  return { buffer, mimeType: String(asset.mimeType || response.headers.get("content-type") || "application/octet-stream").split(";")[0].toLowerCase(), size: buffer.length, originalname: asset.originalName || "media" };
}
async function prepareLinkedInMediaFromAsset(user, asset) {
  const file = await fetchAssetBuffer(asset);
  const mime = file.mimeType;
  if (["image/jpeg","image/png","image/gif"].includes(mime)) {
    const conn = user.connections?.linkedin; const token = decryptToken(conn.accessTokenEncrypted);
    if (file.size > 10*1024*1024) throw new Error("LinkedIn images must be 10 MB or smaller.");
    const init = await linkedinFetch("https://api.linkedin.com/rest/images?action=initializeUpload", { method:"POST", headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"}, body:JSON.stringify({initializeUploadRequest:{owner:conn.memberUrn}}) });
    const value=init.data.value||{}; if(!value.uploadUrl||!value.image)throw new Error("LinkedIn did not return an image upload URL.");
    const up=await fetch(value.uploadUrl,{method:"PUT",headers:{"Content-Type":mime},body:file.buffer}); if(!up.ok)throw new Error(`LinkedIn image upload failed (${up.status}).`);
    return {urn:value.image,type:"image"};
  }
  if (mime === "video/mp4") {
    const conn=user.connections?.linkedin; const token=decryptToken(conn.accessTokenEncrypted);
    const init=await linkedinFetch("https://api.linkedin.com/rest/videos?action=initializeUpload",{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify({initializeUploadRequest:{owner:conn.memberUrn,videoSize:file.size,uploadCaptions:false,uploadThumbnail:false}})});
    const value=init.data.value||{}; if(!value.uploadInstructions?.length||!value.video)throw new Error("LinkedIn did not return video upload instructions.");
    for(const instruction of value.uploadInstructions){const chunk=file.buffer.subarray(Number(instruction.firstByte||0),Number(instruction.lastByte||file.size-1)+1);const up=await fetch(instruction.uploadUrl,{method:"PUT",headers:{"Content-Type":"video/mp4","Content-Length":String(chunk.length)},body:chunk});if(!up.ok)throw new Error(`LinkedIn video upload failed (${up.status}).`);}
    await waitForLinkedInMedia(token,value.video,"video"); return {urn:value.video,type:"video"};
  }
  throw new Error("LinkedIn supports JPG, PNG, GIF images and MP4 video in Creovah.");
}

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

// Merges a platform's content override (if any) on top of the shared body/mediaAssets, returning a
// lightweight view object the existing publishXContent(user, item)-style functions can consume as-is.
function resolvePlatformItem(item, platform) {
  const override = item.perPlatformOverrides && item.perPlatformOverrides[platform];
  if (!override) return item;
  return {
    ...item.toObject ? item.toObject() : item,
    body: override.body !== undefined ? override.body : item.body,
    mediaAssets: override.mediaAssets !== undefined ? override.mediaAssets : item.mediaAssets
  };
}

async function publishLinkedInContent(user, item) {
  const conn = user.connections?.linkedin;
  if (!conn?.connected || !conn.accessTokenEncrypted || !conn.memberUrn) throw new Error("LinkedIn is not connected.");
  let mediaUrn = "";
  if (Array.isArray(item.mediaAssets) && item.mediaAssets.length) mediaUrn = (await prepareLinkedInMediaFromAsset(user, item.mediaAssets[0])).urn;
  const token = decryptToken(conn.accessTokenEncrypted);
  const content = { author: conn.memberUrn, commentary: item.body || "", visibility: "PUBLIC", distribution: { feedDistribution: "MAIN_FEED", targetEntities: [], thirdPartyDistributionChannels: [] }, lifecycleState: "PUBLISHED", isReshareDisabledByAuthor: false };
  if (mediaUrn) content.content = { media: { id: mediaUrn, ...(item.mediaAltText ? { altText: item.mediaAltText } : {}) } };
  const { response } = await linkedinFetch("https://api.linkedin.com/rest/posts", { method:"POST", headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"}, body:JSON.stringify(content) });
  return response.headers.get("x-restli-id") || "";
}

// Publish due scheduled posts. Creovah owns the schedule and sends each post when it is due.
let schedulerBusy = false;
async function processSchedules() {
  if (schedulerBusy || mongoose.connection.readyState !== 1) return;
  schedulerBusy = true;
  try {
    const due = await Content.find({ status: "scheduled", scheduledFor: { $lte: new Date() }, platforms: { $in: ["linkedin", "x"] } }).limit(10);
    for (const item of due) {
      try {
        const user = await findUserById(item.userId); if (!user) throw new Error("Account not found.");
        const externalPosts = {}; const publishErrors = [];
        for (const platform of item.platforms) {
          try {
            const platformItem = resolvePlatformItem(item, platform);
            if (platform === "linkedin") externalPosts.linkedin = await publishLinkedInContent(user, platformItem);
            else if (platform === "x") externalPosts.x = await publishXContent(user, platformItem);
            else if (platform === "youtube") externalPosts.youtube = await publishYouTubeContent(user, platformItem);
          } catch (platformError) { publishErrors.push({ platform, message: platformError.message || "Publishing failed." }); }
        }
        item.externalPosts = externalPosts; item.externalPostUrn = Object.values(externalPosts).find(Boolean) || "";
        if (publishErrors.length && Object.values(externalPosts).some(Boolean)) item.publishErrors = publishErrors;
        if (publishErrors.length && !Object.values(externalPosts).some(Boolean)) { console.error(`Scheduled post ${item._id} failed:`, publishErrors); continue; }
        item.status = "published"; item.publishedAt = new Date(); item.scheduledFor = null; await item.save();
      } catch (error) { console.error(`Scheduled post ${item._id} failed:`, error.message); }
    }
  } catch (error) { console.error("Scheduler error:", error.message); }
  finally { schedulerBusy = false; }
}
setInterval(processSchedules, 60 * 1000);


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
      linkedin:{connected:Boolean(u.connections?.linkedin?.connected),memberId:u.connections?.linkedin?.memberId||"",memberUrn:u.connections?.linkedin?.memberUrn||"",name:u.connections?.linkedin?.name||"",email:u.connections?.linkedin?.email||""},
      x:{connected:Boolean(u.connections?.x?.connected),userId:u.connections?.x?.userId||"",username:u.connections?.x?.username||"",name:u.connections?.x?.name||""},
      tiktok:{connected:Boolean(u.connections?.tiktok?.connected),username:u.connections?.tiktok?.username||"",name:u.connections?.tiktok?.name||""},
      youtube:{connected:Boolean(u.connections?.youtube?.connected),channelId:u.connections?.youtube?.channelId||"",channelTitle:u.connections?.youtube?.channelTitle||""}
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

// --- X OAuth 2.0 PKCE + publishing ---
const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || "";
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || `${APP_BASE_URL}/api/connections/x/callback`;
const X_SCOPES = "tweet.read tweet.write users.read media.write offline.access";

async function xApi(method, pathName, token, body) {
  const response = await fetch(`https://api.x.com${pathName}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {})
  });
  const text = await response.text(); let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!response.ok) {
    const err = data?.detail || data?.title || data?.errors?.[0]?.detail || data?.errors?.[0]?.message || data?.error || data?.raw || `X request failed (${response.status}).`;
    throw new Error(String(err));
  }
  return data;
}
function base64url(buffer) { return Buffer.from(buffer).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
function createPkcePair() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

app.get("/api/connections/x/start", auth, (req, res) => {
  try {
    if (!X_CLIENT_ID) return res.status(500).json({ message: "X connection is not configured on the server yet." });
    const { verifier, challenge } = createPkcePair();
    const state = createOAuthState(req.auth.id, "x", { codeVerifier: verifier, returnTo: req.query.returnTo });
    const params = new URLSearchParams({ response_type: "code", client_id: X_CLIENT_ID, redirect_uri: X_REDIRECT_URI, scope: X_SCOPES, state, code_challenge: challenge, code_challenge_method: "S256" });
    res.json({ url: `https://x.com/i/oauth2/authorize?${params.toString()}` });
  } catch (error) { console.error("X OAuth start error:", error); res.status(500).json({ message: "Unable to start the X connection." }); }
});

async function exchangeXCode(code, verifier) {
  const body = new URLSearchParams({ code: String(code), grant_type: "authorization_code", client_id: X_CLIENT_ID, redirect_uri: X_REDIRECT_URI, code_verifier: verifier });
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (X_CLIENT_SECRET) headers.Authorization = `Basic ${Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64")}`;
  const response = await fetch("https://api.x.com/2/oauth2/token", { method: "POST", headers, body });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(data.error_description || data.detail || data.error || "X token exchange failed.");
  return data;
}

async function completeXConnection(userId, code, verifier) {
  const user = await findUserById(userId); if (!user) throw new Error("Account not found.");
  const token = await exchangeXCode(code, verifier);
  const me = await xApi("GET", "/2/users/me", token.access_token);
  const profile = me.data || {};
  user.connections = user.connections || {};
  user.connections.x = {
    connected: true, userId: profile.id || "", username: profile.username || "", name: profile.name || "",
    accessTokenEncrypted: encryptToken(token.access_token),
    refreshTokenEncrypted: token.refresh_token ? encryptToken(token.refresh_token) : "",
    tokenExpiresAt: token.expires_in ? new Date(Date.now() + Number(token.expires_in) * 1000) : null,
    refreshTokenExpiresAt: null
  };
  user.socials = { ...user.socials, x: true };
  await saveUser(user);
  return { name: profile.name || profile.username || "X" };
}

app.get("/api/connections/x/callback", async (req, res) => {
  const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
  const pending = state ? consumeOAuthState(String(state)) : null;
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status }); if (reason) params.set("reason", reason); if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`${safeReturnTo(pending?.returnTo)}?${params.toString()}`);
  };
  try {
    if (oauthError) return redirectToDashboard("error", "denied", oauthDescription || oauthError);
    if (!code || !pending || pending.platform !== "x" || !pending.codeVerifier) return redirectToDashboard("error", "session-expired", "The X connection session expired. Please try again.");
    const result = await completeXConnection(pending.userId, String(code), pending.codeVerifier);
    return redirectToDashboard("x-success", null, `${result.name} connected.`);
  } catch (error) { console.error("X OAuth callback error:", error.message); return redirectToDashboard("error", "unexpected", error.message || "X returned an unexpected error while connecting your account."); }
});

async function getXAccessToken(user) {
  const conn = user?.connections?.x;
  if (!conn?.connected || !conn.accessTokenEncrypted) throw new Error("Connect X before publishing.");
  if (conn.tokenExpiresAt && new Date(conn.tokenExpiresAt).getTime() > Date.now() + 60 * 1000) return { token: decryptToken(conn.accessTokenEncrypted) };
  if (!conn.refreshTokenEncrypted) return { token: decryptToken(conn.accessTokenEncrypted) };
  const refreshToken = decryptToken(conn.refreshTokenEncrypted);
  const body = new URLSearchParams({ refresh_token: refreshToken, grant_type: "refresh_token", client_id: X_CLIENT_ID });
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (X_CLIENT_SECRET) headers.Authorization = `Basic ${Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64")}`;
  const response = await fetch("https://api.x.com/2/oauth2/token", { method: "POST", headers, body });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(data.error_description || data.error || "X session expired. Please reconnect X.");
  conn.accessTokenEncrypted = encryptToken(data.access_token);
  if (data.refresh_token) conn.refreshTokenEncrypted = encryptToken(data.refresh_token);
  conn.tokenExpiresAt = data.expires_in ? new Date(Date.now() + Number(data.expires_in) * 1000) : null;
  await saveUser(user);
  return { token: data.access_token };
}

async function uploadXMedia(user, file) {
  const { token } = await getXAccessToken(user);
  const mime = String(file.mimetype || "").toLowerCase();
  if (!["image/jpeg","image/png","image/gif","image/webp","video/mp4","video/quicktime","video/webm"].includes(mime)) throw new Error("X supports JPG, PNG, GIF, WEBP and MP4 media here.");
  if (mime.startsWith("image/")) {
    if (file.size > 5 * 1024 * 1024) throw new Error("X images must be 5 MB or smaller.");
    const result = await xApi("POST", "/2/media/upload", token, { media: file.buffer.toString("base64"), media_category: mime === "image/gif" ? "tweet_gif" : "tweet_image", media_type: mime });
    return { id: result?.data?.id, type: "image" };
  }
  if (file.size > 512 * 1024 * 1024) throw new Error("X videos must be 512 MB or smaller.");
  const initResp = await fetch("https://api.x.com/2/media/upload/initialize", { method:"POST", headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"}, body:JSON.stringify({media_category:"tweet_video",media_type:mime,total_bytes:file.size}) });
  const init = await initResp.json().catch(()=>({})); if(!initResp.ok || !init.data?.id) throw new Error(init.detail || init.errors?.[0]?.detail || "X video upload could not be initialized.");
  const id=init.data.id; const chunkSize=5*1024*1024;
  for(let offset=0,segment=0; offset<file.size; offset+=chunkSize,segment++){
    const chunk=file.buffer.subarray(offset,Math.min(offset+chunkSize,file.size));
    const form=new FormData(); form.append("media",new Blob([chunk]),"chunk.bin"); form.append("segment_index",String(segment));
    const r=await fetch(`https://api.x.com/2/media/upload/${encodeURIComponent(id)}/append`,{method:"POST",headers:{Authorization:`Bearer ${token}`},body:form});
    if(!r.ok) throw new Error(`X video upload failed (${r.status}).`);
  }
  const fin=await fetch(`https://api.x.com/2/media/upload/${encodeURIComponent(id)}/finalize`,{method:"POST",headers:{Authorization:`Bearer ${token}`}}); const finalized=await fin.json().catch(()=>({})); if(!fin.ok) throw new Error(finalized.detail || finalized.errors?.[0]?.detail || "X video upload could not be finalized.");
  let info=finalized.data?.processing_info;
  while(info && ["pending","in_progress"].includes(String(info.state).toLowerCase())){
    await new Promise(r=>setTimeout(r,Math.max(1000,Number(info.check_after_secs||2)*1000)));
    const st=await fetch(`https://api.x.com/2/media/upload?media_id=${encodeURIComponent(id)}`,{headers:{Authorization:`Bearer ${token}`}}); const sd=await st.json().catch(()=>({})); if(!st.ok) throw new Error(sd.detail || sd.errors?.[0]?.detail || "X video processing status failed."); info=sd.data?.processing_info;
  }
  if(info && String(info.state).toLowerCase()!=="succeeded") throw new Error("X could not finish processing the video.");
  return {id,type:"video"};
}

app.post("/api/x/media", auth, mediaUpload.single("media"), async (req,res)=>{
  try { if(!req.file)return res.status(400).json({message:"Choose a photo or video."}); const user=await findUserById(req.auth.id); const media=await uploadXMedia(user,req.file); res.json({urn:media.id,mediaType:media.type}); }
  catch(error){ console.error("X media upload error:",error); res.status(500).json({message:error.message||"Unable to upload media to X."}); }
});

async function publishXContent(user,item) {
  const { token } = await getXAccessToken(user);
  const payload = { text: item.body || "" };
  if (Array.isArray(item.mediaAssets) && item.mediaAssets.length) {
    const mediaIds=[];
    for (const asset of item.mediaAssets) mediaIds.push(String((await uploadXMedia(user, await fetchAssetBuffer(asset))).id));
    payload.media = { media_ids: mediaIds };
  }
  const result = await xApi("POST", "/2/tweets", token, payload);
  return result?.data?.id || "";
}

// --- YouTube (Google OAuth 2.0 + Data API v3 resumable upload) ---
const YOUTUBE_CLIENT_ID = process.env.YOUTUBE_CLIENT_ID;
const YOUTUBE_CLIENT_SECRET = process.env.YOUTUBE_CLIENT_SECRET;
const YOUTUBE_REDIRECT_URI = process.env.YOUTUBE_REDIRECT_URI || `${APP_BASE_URL}/api/connections/youtube/callback`;
const YOUTUBE_SCOPES = "https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly";

app.get("/api/connections/youtube/start", auth, (req, res) => {
  try {
    if (!YOUTUBE_CLIENT_ID || !YOUTUBE_CLIENT_SECRET) return res.status(500).json({ message: "YouTube connection is not configured on the server yet." });
    const state = createOAuthState(req.auth.id, "youtube", { returnTo: req.query.returnTo });
    const params = new URLSearchParams({
      response_type: "code",
      client_id: YOUTUBE_CLIENT_ID,
      redirect_uri: YOUTUBE_REDIRECT_URI,
      state,
      scope: YOUTUBE_SCOPES,
      access_type: "offline",
      // Forces Google to always return a refresh_token, even if this user connected before.
      // Without this, reconnecting an existing user would silently omit the refresh_token
      // and Creovah would lose the ability to publish once the short-lived access token expires.
      prompt: "consent"
    });
    res.json({ url: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}` });
  } catch (error) {
    console.error("YouTube OAuth start error:", error);
    res.status(500).json({ message: "Unable to start the YouTube connection." });
  }
});

async function exchangeYouTubeCode(code) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: String(code),
    client_id: YOUTUBE_CLIENT_ID,
    client_secret: YOUTUBE_CLIENT_SECRET,
    redirect_uri: YOUTUBE_REDIRECT_URI
  });
  const response = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(data.error_description || data.error || "YouTube token exchange failed.");
  return data;
}

async function completeYouTubeConnection(userId, code) {
  const user = await findUserById(userId);
  if (!user) throw new Error("Account not found.");
  const token = await exchangeYouTubeCode(code);
  if (!token.refresh_token) throw new Error("Google did not return a refresh token. Please try connecting YouTube again.");
  const channelResp = await fetch("https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true", { headers: { Authorization: `Bearer ${token.access_token}` } });
  const channelData = await channelResp.json().catch(() => ({}));
  const channel = channelData.items?.[0];
  if (!channelResp.ok || !channel) throw new Error(channelData.error?.message || "Could not read the connected YouTube channel. Make sure the Google account has a YouTube channel.");
  user.connections = user.connections || {};
  user.connections.youtube = {
    connected: true,
    channelId: channel.id,
    channelTitle: channel.snippet?.title || "YouTube channel",
    accessTokenEncrypted: encryptToken(token.access_token),
    refreshTokenEncrypted: encryptToken(token.refresh_token),
    tokenExpiresAt: token.expires_in ? new Date(Date.now() + Number(token.expires_in) * 1000) : null
  };
  user.socials = { ...user.socials, youtube: true };
  await saveUser(user);
  return { name: channel.snippet?.title || "YouTube" };
}

app.get("/api/connections/youtube/callback", async (req, res) => {
  const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
  const pending = state ? consumeOAuthState(String(state)) : null;
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status });
    if (reason) params.set("reason", reason);
    if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`${safeReturnTo(pending?.returnTo)}?${params.toString()}`);
  };
  try {
    if (oauthError) return redirectToDashboard("error", "denied", oauthDescription || oauthError);
    if (!code || !pending || pending.platform !== "youtube") return redirectToDashboard("error", "session-expired");
    const result = await completeYouTubeConnection(pending.userId, String(code));
    return redirectToDashboard("youtube-success", null, `${result.name} connected.`);
  } catch (error) {
    console.error("YouTube OAuth callback error:", error.message);
    return redirectToDashboard("error", "unexpected", error.message || "YouTube returned an unexpected error while connecting your account.");
  }
});

async function getYouTubeAccessToken(user) {
  const conn = user?.connections?.youtube;
  if (!conn?.connected || !conn.refreshTokenEncrypted) throw new Error("Connect YouTube before publishing.");
  if (conn.accessTokenEncrypted && conn.tokenExpiresAt && new Date(conn.tokenExpiresAt).getTime() > Date.now() + 60 * 1000) {
    return { token: decryptToken(conn.accessTokenEncrypted) };
  }
  const refreshToken = decryptToken(conn.refreshTokenEncrypted);
  const body = new URLSearchParams({ refresh_token: refreshToken, grant_type: "refresh_token", client_id: YOUTUBE_CLIENT_ID, client_secret: YOUTUBE_CLIENT_SECRET });
  const response = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(data.error_description || data.error || "YouTube session expired. Please reconnect YouTube.");
  conn.accessTokenEncrypted = encryptToken(data.access_token);
  conn.tokenExpiresAt = data.expires_in ? new Date(Date.now() + Number(data.expires_in) * 1000) : null;
  await saveUser(user);
  return { token: data.access_token };
}

// YouTube requires a title distinct from the description. Creovah's composer only has one body
// field, so the title is derived from the first line of the caption (falling back to a generic
// title), and the full caption is kept as the description so nothing the user wrote is dropped.
function deriveYouTubeTitle(body) {
  const firstLine = String(body || "").split("\n")[0].trim();
  if (!firstLine) return "Untitled video";
  return firstLine.length > 100 ? firstLine.slice(0, 97) + "..." : firstLine;
}

async function publishYouTubeContent(user, item) {
  const assets = Array.isArray(item.mediaAssets) ? item.mediaAssets : [];
  const video = assets.find(a => String(a?.mimeType || "").startsWith("video/") || a?.resourceType === "video");
  if (!video) throw new Error("YouTube requires a video. Add a video before publishing.");
  const file = await fetchAssetBuffer(video);
  if (!file.mimeType.startsWith("video/")) throw new Error("YouTube requires a video file.");
  if (file.size > 128 * 1024 * 1024 * 1024) throw new Error("YouTube videos must be 128 GB or smaller.");
  const { token } = await getYouTubeAccessToken(user);
  const metadata = {
    snippet: {
      title: deriveYouTubeTitle(item.body),
      description: item.body || "",
      categoryId: "22"
    },
    status: { privacyStatus: "public", selfDeclaredMadeForKids: false }
  };
  const initResp = await fetch("https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json; charset=UTF-8",
      "X-Upload-Content-Type": file.mimeType,
      "X-Upload-Content-Length": String(file.size)
    },
    body: JSON.stringify(metadata)
  });
  if (!initResp.ok) {
    const errData = await initResp.json().catch(() => ({}));
    throw new Error(errData.error?.message || `YouTube upload could not be initialized (${initResp.status}).`);
  }
  const uploadUrl = initResp.headers.get("location");
  if (!uploadUrl) throw new Error("YouTube did not return an upload session URL.");
  const uploadResp = await fetch(uploadUrl, {
    method: "PUT",
    headers: { "Content-Type": file.mimeType, "Content-Length": String(file.size) },
    body: file.buffer
  });
  const uploadData = await uploadResp.json().catch(() => ({}));
  if (!uploadResp.ok || !uploadData.id) throw new Error(uploadData.error?.message || `YouTube video upload failed (${uploadResp.status}).`);
  return uploadData.id;
}

// --- TikTok Login Kit + Content Posting API ---
const TIKTOK_CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY;
const TIKTOK_CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET;
const TIKTOK_REDIRECT_URI = process.env.TIKTOK_REDIRECT_URI || `${APP_BASE_URL}/api/connections/tiktok/callback`;
const TIKTOK_SCOPES = "user.info.basic,video.publish";

async function tiktokJsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!response.ok) {
    const detail = data.error_description || data.error?.message || data.error?.code || data.message || data.raw || `TikTok request failed (${response.status}).`;
    throw new Error(String(detail));
  }
  if (data.error && data.error.code && data.error.code !== "ok") throw new Error(data.error.message || data.error.code);
  return data;
}

app.get("/api/connections/tiktok/start", auth, (req, res) => {
  try {
    if (!TIKTOK_CLIENT_KEY || !TIKTOK_CLIENT_SECRET) return res.status(500).json({ message: "TikTok connection is not configured on the server yet." });
    const state = createOAuthState(req.auth.id, "tiktok", { returnTo: req.query.returnTo });
    const params = new URLSearchParams({
      client_key: TIKTOK_CLIENT_KEY,
      response_type: "code",
      scope: TIKTOK_SCOPES,
      redirect_uri: TIKTOK_REDIRECT_URI,
      state
    });
    res.json({ url: `https://www.tiktok.com/v2/auth/authorize/?${params.toString()}` });
  } catch (error) {
    console.error("TikTok OAuth start error:", error);
    res.status(500).json({ message: "Unable to start the TikTok connection." });
  }
});

async function exchangeTikTokCode(code) {
  const body = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    client_secret: TIKTOK_CLIENT_SECRET,
    code: String(code),
    grant_type: "authorization_code",
    redirect_uri: TIKTOK_REDIRECT_URI
  });
  const data = await tiktokJsonFetch("https://open.tiktokapis.com/v2/oauth/token/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache" },
    body
  });
  if (!data.access_token) throw new Error("TikTok did not return an access token.");
  return data;
}

async function completeTikTokConnection(userId, code) {
  const user = await findUserById(userId);
  if (!user) throw new Error("Account not found.");
  const token = await exchangeTikTokCode(code);
  const profile = await tiktokJsonFetch("https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name", {
    headers: { Authorization: `Bearer ${token.access_token}` }
  });
  const profileUser = profile.data?.user || {};
  user.connections = user.connections || {};
  user.connections.tiktok = {
    connected: true,
    openId: token.open_id || profileUser.open_id || "",
    username: "",
    name: profileUser.display_name || "TikTok account",
    accessTokenEncrypted: encryptToken(token.access_token),
    refreshTokenEncrypted: token.refresh_token ? encryptToken(token.refresh_token) : "",
    tokenExpiresAt: token.expires_in ? new Date(Date.now() + Number(token.expires_in) * 1000) : null,
    refreshTokenExpiresAt: token.refresh_expires_in ? new Date(Date.now() + Number(token.refresh_expires_in) * 1000) : null
  };
  user.socials = { ...user.socials, tiktok: true };
  await saveUser(user);
  return { name: user.connections.tiktok.name };
}

async function getTikTokAccessToken(user) {
  const conn = user?.connections?.tiktok;
  if (!conn?.connected || !conn.accessTokenEncrypted) throw new Error("Connect TikTok before publishing.");
  if (conn.tokenExpiresAt && new Date(conn.tokenExpiresAt).getTime() > Date.now() + 60 * 1000) return { token: decryptToken(conn.accessTokenEncrypted) };
  if (!conn.refreshTokenEncrypted) return { token: decryptToken(conn.accessTokenEncrypted) };
  const body = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    client_secret: TIKTOK_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: decryptToken(conn.refreshTokenEncrypted)
  });
  const data = await tiktokJsonFetch("https://open.tiktokapis.com/v2/oauth/token/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache" },
    body
  });
  conn.accessTokenEncrypted = encryptToken(data.access_token);
  if (data.refresh_token) conn.refreshTokenEncrypted = encryptToken(data.refresh_token);
  conn.tokenExpiresAt = data.expires_in ? new Date(Date.now() + Number(data.expires_in) * 1000) : null;
  conn.refreshTokenExpiresAt = data.refresh_expires_in ? new Date(Date.now() + Number(data.refresh_expires_in) * 1000) : conn.refreshTokenExpiresAt;
  await saveUser(user);
  return { token: data.access_token };
}

async function queryTikTokCreator(token) {
  return tiktokJsonFetch("https://open.tiktokapis.com/v2/post/publish/creator_info/query/", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json; charset=UTF-8" },
    body: JSON.stringify({})
  });
}

// Normalizes and validates the TikTok-only disclosure/privacy settings that come from the composer.
// These are required by TikTok's Content Posting API review guidelines: creators must be able to
// choose privacy level and interaction settings themselves, and content must be disclosed as
// branded content and/or AI-generated content when applicable.
function normalizeTikTokSettings(raw, allowedPrivacyOptions) {
  const s = raw && typeof raw === "object" ? raw : {};
  const options = Array.isArray(allowedPrivacyOptions) ? allowedPrivacyOptions : [];
  let privacyLevel = typeof s.privacyLevel === "string" ? s.privacyLevel : "";
  if (!options.includes(privacyLevel)) privacyLevel = options.includes("PUBLIC_TO_EVERYONE") ? "PUBLIC_TO_EVERYONE" : options[0];
  if (!privacyLevel) throw new Error("TikTok did not return an available privacy setting.");
  const isBrandedContent = Boolean(s.isBrandedContent);
  const isAigc = Boolean(s.isAigc);
  // TikTok disallows branded content set to private.
  if (isBrandedContent && privacyLevel === "SELF_ONLY") throw new Error("Branded content cannot be set to private on TikTok. Choose a different privacy setting or turn off branded content.");
  return {
    privacyLevel,
    disableComment: Boolean(s.disableComment),
    disableDuet: Boolean(s.disableDuet),
    disableStitch: Boolean(s.disableStitch),
    isBrandedContent,
    isAigc
  };
}

async function publishTikTokPhoto(user, item, assets, tiktokSettings) {
  if (!Array.isArray(assets) || !assets.length) throw new Error("TikTok requires at least one photo.");
  const { token } = await getTikTokAccessToken(user);
  const creator = await queryTikTokCreator(token); const info=creator.data||{};
  const options=Array.isArray(info.privacy_level_options)?info.privacy_level_options:[];
  const settings = normalizeTikTokSettings(tiktokSettings, options);
  const urls=[];
  for(const asset of assets){if(!asset?.secureUrl)throw new Error("TikTok photo is missing its saved media URL."); if(Number(asset.bytes||0)>20*1024*1024)throw new Error("Each TikTok photo must be 20 MB or smaller."); urls.push(mediaProxyUrl(asset));}
  const init=await tiktokJsonFetch("https://open.tiktokapis.com/v2/post/publish/content/init/",{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json; charset=UTF-8"},body:JSON.stringify({post_info:{title:(item.body||"").slice(0,90),description:(item.body||"").slice(0,4000),privacy_level:settings.privacyLevel,disable_comment:settings.disableComment,auto_add_music:false,brand_content_toggle:settings.isBrandedContent,is_aigc:settings.isAigc},source_info:{source:"PULL_FROM_URL",photo_cover_index:0,photo_images:urls},post_mode:"DIRECT_POST",media_type:"PHOTO"})});
  const id=init.data?.publish_id;if(!id)throw new Error("TikTok did not return a photo publish ID.");return id;
}
async function publishTikTokVideo(user,item,asset,tiktokSettings){
  if(!asset)throw new Error("TikTok requires a video. Add a video before publishing.");
  const file=await fetchAssetBuffer(asset); const mime=file.mimeType;
  if(!["video/mp4","video/quicktime","video/webm"].includes(mime))throw new Error("TikTok video must be MP4, MOV or WEBM.");
  if(file.size>4*1024*1024*1024)throw new Error("TikTok videos must be 4 GB or smaller.");
  const {token}=await getTikTokAccessToken(user); const creator=await queryTikTokCreator(token); const info=creator.data||{}; const options=Array.isArray(info.privacy_level_options)?info.privacy_level_options:[];
  const settings = normalizeTikTokSettings(tiktokSettings, options);
  const chunkSize=10*1024*1024,totalChunks=Math.ceil(file.size/chunkSize);
  const init=await tiktokJsonFetch("https://open.tiktokapis.com/v2/post/publish/video/init/",{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json; charset=UTF-8"},body:JSON.stringify({post_info:{title:(item.body||"").slice(0,2200),privacy_level:settings.privacyLevel,disable_duet:settings.disableDuet,disable_comment:settings.disableComment,disable_stitch:settings.disableStitch,brand_content_toggle:settings.isBrandedContent,is_aigc:settings.isAigc},source_info:{source:"FILE_UPLOAD",video_size:file.size,chunk_size:chunkSize,total_chunk_count:totalChunks}})});
  const uploadUrl=init.data?.upload_url,publishId=init.data?.publish_id;if(!uploadUrl||!publishId)throw new Error("TikTok did not return an upload URL.");
  for(let offset=0;offset<file.size;offset+=chunkSize){const end=Math.min(offset+chunkSize,file.size)-1;const chunk=file.buffer.subarray(offset,end+1);const r=await fetch(uploadUrl,{method:"PUT",headers:{"Content-Type":mime,"Content-Length":String(chunk.length),"Content-Range":`bytes ${offset}-${end}/${file.size}`},body:chunk});if(!r.ok){const detail=await r.text().catch(()=>"");throw new Error(`TikTok video upload failed (${r.status}).${detail?` ${detail.slice(0,250)}`:""}`);}}
  return publishId;
}
async function publishTikTokContent(user,item){
  const assets=Array.isArray(item.mediaAssets)?item.mediaAssets:[]; if(!assets.length)throw new Error("TikTok requires a photo or video.");
  const videos=assets.filter(a=>String(a?.mimeType||"").startsWith("video/")||a?.resourceType==="video");
  const tiktokSettings=item.tiktokSettings||{};
  if(videos.length)return publishTikTokVideo(user,item,videos[0],tiktokSettings);
  return publishTikTokPhoto(user,item,assets,tiktokSettings);
}

// Lets the composer populate privacy options and creator info for the TikTok-only settings panel.
app.get("/api/connections/tiktok/creator-info", auth, async (req, res) => {
  try {
    const user = await findUserById(req.auth.id);
    if (!user?.connections?.tiktok?.connected) return res.status(400).json({ message: "Connect TikTok before loading its posting settings." });
    const { token } = await getTikTokAccessToken(user);
    const creator = await queryTikTokCreator(token);
    const info = creator.data || {};
    res.json({
      privacyOptions: Array.isArray(info.privacy_level_options) ? info.privacy_level_options : [],
      commentDisabled: Boolean(info.comment_disabled),
      duetDisabled: Boolean(info.duet_disabled),
      stitchDisabled: Boolean(info.stitch_disabled),
      maxVideoDurationSec: info.max_video_post_duration_sec || null
    });
  } catch (error) {
    console.error("TikTok creator-info error:", error);
    res.status(500).json({ message: error.message || "Unable to load TikTok posting settings." });
  }
});

app.post("/api/tiktok/publish", auth, async (req,res)=>{
  return res.status(410).json({message:"TikTok publishing now uses Creovah's saved media flow. Save/upload the media through the composer and publish the post from there."});
});

app.get("/api/connections/tiktok/callback", async (req, res) => {
  const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
  const pending = state ? consumeOAuthState(String(state)) : null;
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status });
    if (reason) params.set("reason", reason);
    if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`${safeReturnTo(pending?.returnTo)}?${params.toString()}`);
  };
  try {
    if (oauthError) return redirectToDashboard("error", "denied", oauthDescription || oauthError);
    if (!code || !pending || pending.platform !== "tiktok") return redirectToDashboard("error", "session-expired");
    const result = await completeTikTokConnection(pending.userId, String(code));
    return redirectToDashboard("tiktok-success", null, result.name ? `${result.name} connected.` : "TikTok connected successfully.");
  } catch (error) {
    console.error("TikTok OAuth callback error:", error.message);
    return redirectToDashboard("error", "unexpected", error.message || "TikTok returned an unexpected error while connecting your account.");
  }
});

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
// Only two known post-connection destinations are ever allowed — never a value built from
// arbitrary user input — so this can't be used to redirect anywhere off the app.
function safeReturnTo(value) {
  return value === "onboarding" ? "/onboarding/index.html" : "/dashboard.html";
}
function createOAuthState(userId, platform, extra = {}) {
  const state = crypto.randomBytes(16).toString("hex");
  pendingOAuthStates.set(state, {
    userId: String(userId),
    platform,
    ...extra,
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
    const state = createOAuthState(req.auth.id, "facebook", { returnTo: req.query.returnTo });
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
    const state = createOAuthState(req.auth.id, "instagram", { returnTo: req.query.returnTo });
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
  const { code, state, error: oauthError, error_description: oauthDescription } = req.query;
  const pending = state ? consumeOAuthState(String(state)) : null;
  const redirectToDashboard = (status, reason, message) => {
    const params = new URLSearchParams({ connect: status });
    if (reason) params.set("reason", reason);
    if (message) params.set("message", String(message).slice(0, 500));
    return res.redirect(`${safeReturnTo(pending?.returnTo)}?${params.toString()}`);
  };

  try {
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
    if (!["instagram", "facebook", "linkedin", "x", "tiktok", "youtube"].includes(platform)) return res.status(400).json({ message: "Unknown platform." });
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
      facebook: { connected: false },
      tiktok: { connected: false }
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
