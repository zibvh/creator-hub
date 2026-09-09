const steps = [...document.querySelectorAll(".step")];
let current = 1;
const data = {name:"",username:"",email:"",phone:"",role:"",source:"",socials:[],notifications:false};

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

function showStep(n){
  current=n;
  steps.forEach(s=>s.classList.toggle("active",+s.dataset.step===n));
  $("#stepCounter").textContent=`${n} of ${steps.length}`;
  $("#progressBar").style.width=`${(n/steps.length)*100}%`;
  $("#backBtn").style.visibility=n===1||n===6?"hidden":"visible";
  window.scrollTo({top:0,behavior:"smooth"});
  const copy=[
    ["WELCOME","Let's get you set up.","Create your CreatorHub account. It only takes a minute."],
    ["VERIFY EMAIL","Almost there.","Verify your email so we know it's really you."],
    ["ABOUT YOU","Tell us about yourself.","This helps us tailor CreatorHub to how you create and work."],
    ["SOCIAL ACCOUNTS","CONNECT","Connect the platforms you want CreatorHub to manage."],
    ["NOTIFICATIONS","STAY IN THE LOOP","Get useful alerts without having to keep checking CreatorHub."],
    ["READY","YOU'RE READY","Your workspace is ready."]
  ][n-1];
  $("#eyebrow").textContent=copy[0];$("#title").textContent=copy[1];$("#subtitle").textContent=copy[2];
}

function validAccount(){
  const fields=["name","username","email","phone"];
  let ok=true;
  fields.forEach(id=>{const el=$("#"+id);if(!el.value.trim()||!el.checkValidity()){el.style.borderColor="#f07070";ok=false}else el.style.borderColor=""});
  if(!ok)return false;
  data.name=$("#name").value.trim();data.username=$("#username").value.trim().replace(/^@/,"");data.email=$("#email").value.trim();data.phone=$("#phone").value.trim();
  return true;
}

$$("[data-next]").forEach(btn=>btn.addEventListener("click",()=>{
  if(current===1&&!validAccount())return;
  if(current===2){
    const code=$$(".otp input").map(i=>i.value).join("");
    if(code.length!==6)return alert("Enter the 6-digit verification code.");
  }
  if(current===3&&!data.role)return alert("Pick what best describes what you do.");
  if(current===3&&!data.source)return alert("Tell us where you found CreatorHub.");
  if(current===4) data.socials=$$(".social.connected").map(x=>x.dataset.social);
  if(current===5) data.notifications=Notification?.permission==="granted";
  if(current===5||current===4||current===3||current===2||current===1) showStep(current+1);
  if(current===6) return;
  if(current===5){$("#namePreview").textContent=data.name.split(" ")[0];renderSummary()}
}));

$("#backBtn").addEventListener("click",()=>{if(current>1)showStep(current-1)});

$$("[data-choice]").forEach(group=>{
  group.addEventListener("click",e=>{
    const b=e.target.closest("button");if(!b)return;
    group.querySelectorAll("button").forEach(x=>x.classList.remove("selected"));b.classList.add("selected");
    data[group.dataset.choice]=b.textContent;
  });
});

$$(".social").forEach(btn=>btn.addEventListener("click",()=>{
  btn.classList.toggle("connected");
  btn.querySelector("b").textContent=btn.classList.contains("connected")?"Connected":"Connect";
}));

const otp=$$("#otpInputs input");
otp.forEach((input,i)=>{
  input.addEventListener("input",()=>{input.value=input.value.replace(/\D/g,"").slice(0,1);if(input.value&&i<otp.length-1)otp[i+1].focus()});
  input.addEventListener("keydown",e=>{if(e.key==="Backspace"&&!input.value&&i>0)otp[i-1].focus()});
});

$("#email").addEventListener("input",()=>$("#emailPreview").textContent=$("#email").value||"you@example.com");
$("#resendBtn").addEventListener("click",()=>{const hint=$("#resendHint");hint.textContent="A new code has been sent. Check your inbox.";setTimeout(()=>hint.textContent="Didn't get it? Check spam or resend.",3000)});

$("#notifyBtn").addEventListener("click",async()=>{
  if(!("Notification" in window)){ $("#permissionStatus").textContent="This browser does not support web notifications."; return; }
  try{
    const permission=await Notification.requestPermission();
    data.notifications=permission==="granted";
    $("#permissionStatus").textContent=permission==="granted"?"Notifications are enabled.":"Notifications are still off.";
    $("#permissionStatus").classList.toggle("allowed",permission==="granted");
    $("#notifyBtn").textContent=permission==="granted"?"Notifications enabled":"Allow notifications";
  }catch(e){$("#permissionStatus").textContent="We couldn't request notification permission here."}
});

function renderSummary(){
  $("#summary").innerHTML=`
    <div><small>Username</small><strong>@${escapeHtml(data.username)}</strong></div>
    <div><small>Role</small><strong>${escapeHtml(data.role||"Creator")}</strong></div>
    <div><small>Socials</small><strong>${data.socials.length?data.socials.join(", "):"None connected"}</strong></div>
    <div><small>Notifications</small><strong>${data.notifications?"Enabled":"Off"}</strong></div>`;
}
function escapeHtml(v){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}

showStep(1);
