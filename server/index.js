require("dotenv").config();
const path=require("path"),fs=require("fs"),crypto=require("crypto"),express=require("express"),cors=require("cors"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),mongoose=require("mongoose");
const app=express(),PORT=Number(process.env.PORT)||10000,SECRET=process.env.JWT_SECRET||"dev-secret-change-me",PUBLIC=path.join(__dirname,"..","public"),DATA=path.join(__dirname,"data","users.json");
fs.mkdirSync(path.dirname(DATA),{recursive:true}); if(!fs.existsSync(DATA))fs.writeFileSync(DATA,"[]");
app.use(cors());app.use(express.json({limit:"2mb"}));
const schema=new mongoose.Schema({
 name:{type:String,required:true},username:{type:String,unique:true,index:true},email:{type:String,unique:true,index:true},
 phone:String,passwordHash:String,role:String,discoverySource:String,
 socials:{instagram:{type:Boolean,default:false},facebook:{type:Boolean,default:false},tiktok:{type:Boolean,default:false}},
 notifications:{type:Boolean,default:false},emailVerified:{type:Boolean,default:false},
 verificationCodeHash:String,verificationExpiresAt:Date,onboardingCompleted:{type:Boolean,default:false}
},{timestamps:true});
const User=mongoose.model("User",schema);let mongo=false;
async function db(){if(!process.env.MONGODB_URI)return;await mongoose.connect(process.env.MONGODB_URI);mongo=true;console.log("[Creovah] MongoDB connected");}
const read=()=>JSON.parse(fs.readFileSync(DATA,"utf8"));const write=x=>fs.writeFileSync(DATA,JSON.stringify(x,null,2));
const safe=u=>{if(!u)return null;let x=u.toObject?u.toObject():{...u};delete x.passwordHash;delete x.verificationCodeHash;delete x.verificationExpiresAt;return x};
const id=u=>String(u._id||u.id), token=u=>jwt.sign({id:id(u),email:u.email},SECRET,{expiresIn:"7d"});
async function byEmail(e){return mongo?User.findOne({email:e}):read().find(u=>u.email===e)||null}
async function byUser(n){return mongo?User.findOne({username:n}):read().find(u=>u.username===n)||null}
async function byId(i){return mongo?User.findById(i):read().find(u=>u.id===i)||null}
async function save(u){if(mongo)return u.save();let a=read(),i=a.findIndex(x=>x.id===u.id);a[i]=u;write(a)}
function auth(req,res,next){try{let t=(req.headers.authorization||"").replace("Bearer ","");req.user=jwt.verify(t,SECRET);next()}catch{return res.status(401).json({message:"Authentication required."})}}
function code(){return String(crypto.randomInt(100000,1000000))}
async function mail(user,c){
 if(!process.env.MAILJET_API_KEY||!process.env.MAILJET_SECRET_KEY||!process.env.MAILJET_SENDER_EMAIL){
  console.log(`[Creovah] Verification code for ${user.email}: ${c}`);return process.env.NODE_ENV==="production"?{}:{devVerificationCode:c};
 }
 let auth=Buffer.from(`${process.env.MAILJET_API_KEY}:${process.env.MAILJET_SECRET_KEY}`).toString("base64");
 let r=await fetch("https://api.mailjet.com/v3.1/send",{method:"POST",headers:{Authorization:`Basic ${auth}`,"Content-Type":"application/json"},body:JSON.stringify({Messages:[{From:{Email:process.env.MAILJET_SENDER_EMAIL,Name:process.env.MAILJET_SENDER_NAME||"Creovah"},To:[{Email:user.email,Name:user.name}],Subject:"Verify your Creovah account",HTMLPart:`<h2>Verify your Creovah account</h2><p>Your code:</p><h1 style="letter-spacing:8px">${c}</h1><p>This code expires in 10 minutes.</p>`}]})});
 if(!r.ok)throw new Error(await r.text());return {};
}
app.get("/api/health",(_,r)=>r.json({ok:true,service:"creovah-api",database:mongo?"mongodb":"json-dev"}));
app.post("/api/auth/register",async(req,res)=>{try{
 let {name,username,email,phone,password,confirmPassword}=req.body||{};if(!name||!username||!email||!phone||!password)return res.status(400).json({message:"All account fields are required."});
 if(password.length<8)return res.status(400).json({message:"Password must be at least 8 characters."});if(password!==confirmPassword)return res.status(400).json({message:"Passwords do not match."});
 email=email.trim().toLowerCase();username=username.trim().toLowerCase();if(await byEmail(email))return res.status(409).json({message:"Email already registered."});if(await byUser(username))return res.status(409).json({message:"Username already taken."});
 let c=code(),u;if(mongo)u=await User.create({name,username,email,phone,passwordHash:await bcrypt.hash(password,12),verificationCodeHash:crypto.createHash("sha256").update(c).digest("hex"),verificationExpiresAt:new Date(Date.now()+600000)});
 else{u={id:crypto.randomUUID(),name,username,email,phone,passwordHash:await bcrypt.hash(password,12),verificationCodeHash:crypto.createHash("sha256").update(c).digest("hex"),verificationExpiresAt:new Date(Date.now()+600000).toISOString(),socials:{instagram:false,facebook:false,tiktok:false},emailVerified:false,onboardingCompleted:false};let a=read();a.push(u);write(a)}
 let m=await mail(u,c);res.status(201).json({userId:id(u),message:"Account created. Check your email.",...m});
}catch(e){console.error(e);res.status(500).json({message:"Could not create account."})}});
app.post("/api/auth/verify-email",async(req,res)=>{try{let u=await byId(req.body.userId);if(!u)return res.status(404).json({message:"Account not found."});if(u.emailVerified)return res.json({token:token(u),user:safe(u)});
if(new Date(u.verificationExpiresAt)<new Date())return res.status(400).json({message:"Code expired. Request a new one."});
let h=crypto.createHash("sha256").update(String(req.body.code||"")).digest("hex");if(h!==u.verificationCodeHash)return res.status(400).json({message:"Incorrect verification code."});
u.emailVerified=true;u.verificationCodeHash=null;u.verificationExpiresAt=null;await save(u);res.json({token:token(u),user:safe(u),message:"Email verified."})}catch(e){res.status(500).json({message:"Verification failed."})}});
app.post("/api/auth/resend-code",async(req,res)=>{try{let u=await byId(req.body.userId);if(!u)return res.status(404).json({message:"Account not found."});let c=code();u.verificationCodeHash=crypto.createHash("sha256").update(c).digest("hex");u.verificationExpiresAt=new Date(Date.now()+600000);await save(u);let m=await mail(u,c);res.json({message:"New code sent.",...m})}catch(e){res.status(500).json({message:"Could not resend code."})}});
app.post("/api/auth/login",async(req,res)=>{let u=await byEmail(String(req.body.email||"").trim().toLowerCase());if(!u||!(await bcrypt.compare(req.body.password||"",u.passwordHash)))return res.status(401).json({message:"Invalid email or password."});if(!u.emailVerified)return res.status(403).json({message:"Please verify your email first.",userId:id(u)});res.json({token:token(u),user:safe(u)})});
app.post("/api/onboarding",auth,async(req,res)=>{let u=await byId(req.user.id);if(!u)return res.status(404).json({message:"Account not found."});u.role=req.body.role||u.role;u.discoverySource=req.body.discoverySource||u.discoverySource;u.socials={instagram:!!req.body.socials?.instagram,facebook:!!req.body.socials?.facebook,tiktok:!!req.body.socials?.tiktok};u.notifications=!!req.body.notifications;u.onboardingCompleted=true;await save(u);res.json({user:safe(u)})});
app.get("/api/me",auth,async(req,res)=>{let u=await byId(req.user.id);if(!u)return res.status(404).json({message:"Account not found."});res.json({user:safe(u)})});
app.use(express.static(PUBLIC));app.get("*splat",(req,res,next)=>req.path.startsWith("/api/")?next():res.sendFile(path.join(PUBLIC,"index.html")));
db().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log(`Creovah on ${PORT}`)));
