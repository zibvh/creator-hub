const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let step=1,userId=null,role="",source="",resendUntil=0,timerInterval,me=null;
const screens=$$(".screen"), bar=$("#progressBar"), label=$("#stepLabel");
const stepOrder=[1,3,4,5,6,7];
function render(){screens.forEach(s=>s.classList.toggle("active",Number(s.dataset.step)===step));const pos=stepOrder.indexOf(step)+1;bar.style.width=(step===7?100:pos*20)+"%";label.textContent=step===7?"DONE":String(pos).padStart(2,"0")+" / 05";lucide.createIcons()}
function go(n){step=n;render();window.scrollTo({top:0,behavior:"smooth"})}
function err(id,msg){$(id).textContent=msg||""}
function token(){return localStorage.getItem("creovah_token")}
async function api(url,opts={}){const r=await fetch(url,opts);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||"Something went wrong.");return d}
async function authedApi(url,opts={}){return api(url,{...opts,headers:{...(opts.headers||{}),Authorization:"Bearer "+token()}})}
$$("[data-toggle]").forEach(b=>b.onclick=()=>{const i=$("#password");i.type=i.type==="password"?"text":"password";b.innerHTML=i.type==="password"?'<i data-lucide="eye"></i>':'<i data-lucide="eye-off"></i>';lucide.createIcons()});
$("#password").oninput=e=>$("#meter").style.width=Math.min(100,(e.target.value.length/12)*100)+"%";

$("#accountForm").onsubmit=async e=>{e.preventDefault();err("#error1");if($("#password").value!==$("#confirm").value)return err("#error1","Passwords do not match.");const btn=e.submitter;btn.disabled=true;try{const d=await api("/api/auth/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:$("#name").value,username:$("#username").value,email:$("#email").value,phone:$("#phone").value,password:$("#password").value})});userId=d.user.id;localStorage.setItem("creovah_token",d.token);go(3)}catch(x){err("#error1",x.message)}finally{btn.disabled=false}};

const roles=[["creator","Creator"],["influencer","Influencer"],["developer","Developer"],["business","Business owner"],["agency","Agency"],["marketer","Marketer"],["student","Student"],["other","Something else"]];
const sources=[["instagram","Instagram"],["tiktok","TikTok"],["facebook","Facebook"],["google","Google"],["friend","A friend"],["search","Search"],["other","Somewhere else"]];
function makeChoices(target,data,select){$(target).innerHTML=data.map(([v,t])=>`<button class="choice" type="button" data-value="${v}"><span>${t}</span><i data-lucide="check"></i></button>`).join("");$$(target+" .choice").forEach(b=>b.onclick=()=>{$$(target+" .choice").forEach(x=>x.classList.remove("selected"));b.classList.add("selected");select(b.dataset.value)});lucide.createIcons()}
makeChoices("#roleChoices",roles,v=>role=v);makeChoices("#sourceChoices",sources,v=>source=v);
$("#roleNext").onclick=async()=>{if(!role)return err("#error3","Choose one option to continue.");err("#error3");try{await save({role});go(4)}catch(x){err("#error3",x.message)}};
$("#sourceNext").onclick=async()=>{if(!source)return err("#error4","Choose one option to continue.");err("#error4");try{await save({discoverySource:source});go(5)}catch(x){err("#error4",x.message)}};

$("#notifyBtn").onclick=async()=>{if(!("Notification"in window))return;const p=await Notification.requestPermission();if(p==="granted"){$("#notifyBtn").textContent="Allowed";$("#notifyBtn").classList.add("allowed")}};
$("#notifyNext").onclick=async()=>{err("#error5");try{await save({notifications:"Notification"in window&&Notification.permission==="granted"});await loadMeAndRenderSocials();go(6)}catch(x){err("#error5",x.message)}};

async function save(body){return authedApi("/api/onboarding",{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})}

const socialPlatforms=[["linkedin","LinkedIn","linkedin"],["x","X","x"],["tiktok","TikTok","music-2"],["youtube","YouTube","youtube"],["facebook","Facebook","facebook"],["instagram","Instagram","instagram"]];
async function loadMeAndRenderSocials(){
  try{const d=await authedApi("/api/me");me=d.user}catch(x){me=me||{connections:{}}}
  renderSocialList();
}
function renderSocialList(){
  const connections=me?.connections||{};
  $("#socialList").innerHTML=socialPlatforms.map(([key,label,icon])=>{
    const connected=Boolean(connections[key]?.connected);
    return `<button type="button" class="social ${connected?"connected":""}" data-social="${key}"><span class="social-icon"><i data-lucide="${icon}"></i></span><span><b>${label}</b><small>${connected?"Connected":"Not connected"}</small></span><span class="state"><i data-lucide="${connected?"check-circle-2":"chevron-right"}"></i></span></button>`;
  }).join("");
  $$("#socialList .social").forEach(b=>b.onclick=()=>connectSocial(b.dataset.social));
  lucide.createIcons();
}
async function connectSocial(platform){
  if(me?.connections?.[platform]?.connected)return;
  err("#error6");
  try{
    const r=await authedApi(`/api/connections/${platform}/start?returnTo=onboarding`);
    if(!r.url)throw new Error("Unable to start the connection.");
    location.href=r.url;
  }catch(x){err("#error6",x.message)}
}
$("#skipSocials").onclick=()=>finishSetup();
$("#finish").onclick=async()=>{err("#error6");try{await finishSetup()}catch(x){err("#error6",x.message)}};
async function finishSetup(){await save({complete:true});go(7)}

// If the user just came back from connecting a social account mid-onboarding (the OAuth
// callback redirects here with ?connect=...), resume at the connect-accounts step instead
// of restarting from the beginning, and show whether the connection succeeded.
async function resumeIfReturningFromOAuth(){
  const params=new URLSearchParams(location.search);
  const status=params.get("connect");
  if(!status||!token())return false;
  history.replaceState({},"",location.pathname);
  await loadMeAndRenderSocials();
  go(6);
  if(status==="error")err("#error6",params.get("message")||"The social account could not be connected.");
  return true;
}
resumeIfReturningFromOAuth().then(resumed=>{if(!resumed)render()});
