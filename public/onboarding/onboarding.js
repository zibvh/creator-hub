const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let step=1,userId=null,role="",source="",socials={instagram:false,facebook:false,tiktok:false},resendUntil=0,timerInterval;
const screens=$$(".screen"), bar=$("#progressBar"), label=$("#stepLabel");
const stepOrder=[1,3,4,5,6];
function render(){screens.forEach(s=>s.classList.toggle("active",Number(s.dataset.step)===step));const pos=stepOrder.indexOf(step)+1;bar.style.width=(step===6?100:pos*20)+"%";label.textContent=step===6?"DONE":String(pos).padStart(2,"0")+" / 04";lucide.createIcons()}
function go(n){step=n;render();window.scrollTo({top:0,behavior:"smooth"})}
function err(id,msg){$(id).textContent=msg||""}
async function api(url,opts={}){const r=await fetch(url,opts);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||"Something went wrong.");return d}
$$("[data-toggle]").forEach(b=>b.onclick=()=>{const i=$("#password");i.type=i.type==="password"?"text":"password";b.innerHTML=i.type==="password"?'<i data-lucide="eye"></i>':'<i data-lucide="eye-off"></i>';lucide.createIcons()});
$("#password").oninput=e=>$("#meter").style.width=Math.min(100,(e.target.value.length/12)*100)+"%";

$("#accountForm").onsubmit=async e=>{e.preventDefault();err("#error1");if($("#password").value!==$("#confirm").value)return err("#error1","Passwords do not match.");const btn=e.submitter;btn.disabled=true;try{const d=await api("/api/auth/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:$("#name").value,username:$("#username").value,email:$("#email").value,phone:$("#phone").value,password:$("#password").value})});userId=d.user.id;localStorage.setItem("creovah_token",d.token);go(3)}catch(x){err("#error1",x.message)}finally{btn.disabled=false}};

const roles=[["creator","Creator"],["influencer","Influencer"],["developer","Developer"],["business","Business owner"],["agency","Agency"],["marketer","Marketer"],["student","Student"],["other","Something else"]];
const sources=[["instagram","Instagram"],["tiktok","TikTok"],["facebook","Facebook"],["google","Google"],["friend","A friend"],["search","Search"],["other","Somewhere else"]];
function makeChoices(target,data,select){$(target).innerHTML=data.map(([v,t])=>`<button class="choice" type="button" data-value="${v}"><span>${t}</span><i data-lucide="check"></i></button>`).join("");$$(target+" .choice").forEach(b=>b.onclick=()=>{$$(target+" .choice").forEach(x=>x.classList.remove("selected"));b.classList.add("selected");select(b.dataset.value)});lucide.createIcons()}
makeChoices("#roleChoices",roles,v=>role=v);makeChoices("#sourceChoices",sources,v=>source=v);
$("#roleNext").onclick=async()=>{if(!role)return err("#error3","Choose one option to continue.");err("#error3");try{await save({role});go(4)}catch(x){err("#error3",x.message)}};
$("#sourceNext").onclick=async()=>{if(!source)return err("#error4","Choose one option to continue.");err("#error4");try{await save({discoverySource:source});go(5)}catch(x){err("#error4",x.message)}};

$$(".social").forEach(b=>b.onclick=()=>{const key=b.dataset.social;socials[key]=!socials[key];b.classList.toggle("connected",socials[key]);b.querySelector(".state").outerHTML=socials[key]?'<i class="state" data-lucide="check"></i>':'<i class="state" data-lucide="plus"></i>';lucide.createIcons()});
$("#notifyBtn").onclick=async()=>{if(!("Notification"in window))return;const p=await Notification.requestPermission();if(p==="granted"){$("#notifyBtn").textContent="Allowed";$("#notifyBtn").classList.add("allowed")}};

async function save(body){return api("/api/onboarding",{method:"PATCH",headers:{"Content-Type":"application/json",Authorization:"Bearer "+localStorage.getItem("creovah_token")},body:JSON.stringify(body)})}
async function finishSetup(){await save({socials,notifications:"Notification"in window&&Notification.permission==="granted",complete:true});go(6)}
$("#finish").onclick=async()=>{err("#error5");try{await finishSetup()}catch(x){err("#error5",x.message)}};
$("#skip").onclick=async()=>{err("#error5");try{await finishSetup()}catch(x){err("#error5",x.message)}};

render();
