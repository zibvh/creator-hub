
const t=localStorage.getItem('creovah_token');if(!t)location.href='/auth.html';
const $=id=>document.getElementById(id);let user=null,items=[],selectedPreview='linkedin',selectedFile=null,selectedFiles=[],uploadedMedia=null,editingId=null,originalAltText='',composerMode='draft',actionBusy=false;
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function notice(title,msg,type='success'){const card=$('noticeCard');card.classList.remove('success','failure');card.classList.add(type);$('noticeTitle').textContent=title;$('noticeMessage').textContent=msg;$('noticeIcon').innerHTML=`<i data-lucide="${type==='success'?'check':'circle-alert'}"></i>`;$('noticeModal').classList.add('open');lucide.createIcons()}
function closeNotice(){$('noticeModal').classList.remove('open')}$('noticeAction').onclick=closeNotice;
function localSchedule(){
  const date=$('scheduleDate')?.value;
  const time=$('scheduleTime')?.value;
  if(!date||!time)return null;
  const d=new Date(`${date}T${time}`);
  return Number.isNaN(d.getTime())?null:d.toISOString();
}
function clearInlineError(){ const el=$('formError'); if(el){el.textContent='';el.style.display='none';} }
function showError(title,msg){
  clearInlineError();
  notice(title,msg,'failure');
}

function connectedPlatforms(){const a=[];if(user?.connections?.linkedin?.connected)a.push('linkedin');if(user?.connections?.facebook?.connected)a.push('facebook');if(user?.connections?.instagram?.connected)a.push('instagram');if(user?.connections?.tiktok?.connected || user?.socials?.tiktok)a.push('tiktok');if(user?.connections?.x?.connected)a.push('x');if(user?.connections?.youtube?.connected)a.push('youtube');return a}
function logo(p){return `<i data-lucide="${p==='tiktok'?'music-2':p}"></i>`}
function updateStats(){$('totalCount').textContent=items.length;$('connected').textContent=connectedPlatforms().length;$('scheduledCount').textContent=items.filter(x=>x.status==='scheduled').length;$('publishedCount').textContent=items.filter(x=>x.status==='published').length}
function renderPlatforms(){const list=connectedPlatforms();$('platformChoices').innerHTML=list.length?list.map(p=>`<button type="button" class="platform" data-platform="${p}">${logo(p)}<span>${p[0].toUpperCase()+p.slice(1)}</span></button>`).join(''):`<div class="platform-empty">No connected social accounts. Connect one in Settings.</div>`;document.querySelectorAll('#platformChoices .platform').forEach(b=>b.onclick=()=>{b.classList.toggle('on');renderPreviewTabs();updatePreview()});$('platformList').innerHTML=list.length?list.map(p=>`<div class="platform-row"><div class="platform-logo ${p}">${logo(p)}</div><div><strong>${p[0].toUpperCase()+p.slice(1)}</strong><small>Connected</small></div><span class="connected-dot"></span></div>`).join(''):`<div class="empty"><div class="empty-icon"><i data-lucide="link-2-off"></i></div><p>Connect a social account in Settings.</p></div>`;lucide.createIcons()}
function thumb(x){if(x.mediaUrl)return `<img src="${esc(x.mediaUrl)}" alt="">`;return `<i data-lucide="${x.mediaType==='video'?'video':'file-text'}"></i>`}
function renderContent(){
  if(!items.length){$('contentList').innerHTML='<div class="empty"><div class="empty-icon"><i data-lucide="notebook-pen"></i></div><p>No content yet. Create your first post.</p></div>';lucide.createIcons();return}
  $('contentList').innerHTML=items.map(x=>{
    const isDraft=x.status==='draft';
    const isScheduled=x.status==='scheduled';
    const isPublished=x.status==='published' && (x.externalPostUrn || x.externalPosts?.linkedin || x.externalPosts?.x || x.externalPosts?.tiktok || x.externalPosts?.youtube);
    const mediaIcon=x.mediaType==='video'?'video':x.mediaType==='image'?'image':'file-text';
    return `<article class="content-item"><div class="content-thumb"><i data-lucide="${mediaIcon}"></i></div><div><div class="content-title">${esc(x.body||'Untitled post')}</div><div class="meta">${(x.platforms||[]).map(p=>`<span class="pill">${esc(p)}</span>`).join('')}<span class="pill ${esc(x.status)}">${esc(x.status)}${x.scheduledFor?' · '+new Date(x.scheduledFor).toLocaleString():''}</span></div></div><div class="content-actions">${isDraft?`<button class="content-action draft-continue" data-continue="${x._id}"><i data-lucide="play"></i>Continue</button>`:''}${(isScheduled||isPublished)?`<button class="content-action" data-edit="${x._id}"><i data-lucide="pencil"></i>Edit</button>`:''}<button class="content-action danger" data-delete="${x._id}"><i data-lucide="trash-2"></i>Delete</button></div></article>`;
  }).join('');
  document.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>deleteContent(b.dataset.delete));
  document.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>editContent(b.dataset.edit));
  document.querySelectorAll('[data-continue]').forEach(b=>b.onclick=()=>continueDraft(b.dataset.continue));
  lucide.createIcons();
}
async function deleteContent(id){
  if(!confirm('Delete this post from Creovah and the connected platform?'))return;
  try{const r=await fetch('/api/content/'+id,{method:'DELETE',headers:{Authorization:'Bearer '+t}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||'The post could not be deleted.');items=items.filter(x=>x._id!==id);renderContent();updateStats();notice('Post deleted',d.message||'The post was removed.','success')}catch(e){notice('Delete failed',e.message,'failure')}
}
function populateModal(item,mode){
  composerMode=mode;editingId=item?._id||null;originalAltText=item?.mediaAltText||'';resetMedia(false);clearInlineError();$('body').value=item?.body||'';$('altText').value=item?.mediaAltText||'';$('count').textContent=$('body').value.length;
  document.querySelectorAll('#platformChoices .platform').forEach(x=>x.classList.toggle('on',(item?.platforms||[]).includes(x.dataset.platform)));
  if(!item){const list=connectedPlatforms();if(list.length)document.querySelector(`#platformChoices .platform[data-platform="${list[0]}"]`)?.classList.add('on')}
  const now=new Date(Date.now()+60000);$('scheduleDate').min=new Date().toISOString().slice(0,10);$('scheduleDate').value=item?.scheduledFor?new Date(item.scheduledFor).toISOString().slice(0,10):now.toISOString().slice(0,10);$('scheduleTime').value=item?.scheduledFor?new Date(item.scheduledFor).toTimeString().slice(0,5):now.toTimeString().slice(0,5);
  const scheduleMode=mode==='schedule'||mode==='scheduled-edit';
  const editMode=mode==='edit'||mode==='scheduled-edit';
  $('scheduleRow').classList.toggle('show',scheduleMode);
  $('draftBtn').style.display=(mode==='draft')?'inline-flex':'none';
  $('scheduleBtn').style.display=(mode==='schedule')?'inline-flex':'none';
  $('publishBtn').style.display=(mode==='edit'||mode==='scheduled-edit'||mode==='draft')?'inline-flex':'none';
  $('publishBtn').querySelector('.publish-label').innerHTML='<i data-lucide="'+(editMode?'save':'send')+'"></i>'+ (editMode?'Save changes':'Publish');
  $('modal').classList.add('open');
  $('composerTitle').textContent=mode==='edit'?'Edit post':mode==='scheduled-edit'?'Edit scheduled post':mode==='schedule'?'Schedule post':'Create post';
  $('composerSubtitle').textContent=mode==='edit'?'Change the text. Published media stays as it is.':mode==='scheduled-edit'?'Change the text or scheduled time. Media stays as it is.':mode==='schedule'?'Write the post and choose when it should go out.':'Write your post, then publish it or save it for later.';
  $('mediaFile').disabled=editMode;$('mediaFile').closest('.upload').style.display=editMode?'none':'';$('removeMedia').style.display=editMode?'none':'';
  const note=$('mediaEditNote');if(note) {note.textContent=mode==='scheduled-edit'?'Media is fixed for scheduled LinkedIn posts. Create a new post to use different media.':'Published LinkedIn media cannot be changed here. Create a new post if you want to use different media.';note.style.display=editMode?'block':'none'}
  renderPreviewTabs();updatePreview();lucide.createIcons();
}
function continueDraft(id){const item=items.find(x=>x._id===id);if(item)populateModal(item,'draft')}
async function editContent(id){const item=items.find(x=>x._id===id);if(!item)return;const mode=item.status==='scheduled'?'scheduled-edit':'edit';populateModal(item,mode);if(item.mediaAssets?.length||item.mediaUrn){$('mediaPreview').classList.add('show');$('mediaImg').style.display='none';$('mediaVideo').style.display='none';$('mediaStatus').textContent='Loading existing media…';try{const r=await fetch('/api/content/'+id+'/media-preview',{headers:{Authorization:'Bearer '+t}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||'Existing media is not available yet.');if(d.mediaType==='video'){$('mediaVideo').src=d.url;$('mediaVideo').style.display='block'}else{$('mediaImg').src=d.url;$('mediaImg').style.display='block'}$('mediaStatus').textContent='Existing media · this media cannot be changed here.'}catch(e){$('mediaPreview').classList.remove('show');$('mediaStatus').textContent=e.message||'Existing media could not be loaded.'}}}

function resetMedia(markRemoved=false){selectedFiles=[];if($('mediaImg').src)URL.revokeObjectURL($('mediaImg').src);if($('mediaVideo').src)URL.revokeObjectURL($('mediaVideo').src);$('mediaImg').src='';$('mediaVideo').src='';$('mediaImg').style.display='none';$('mediaVideo').style.display='none';$('mediaPreview').classList.remove('show');$('mediaFile').value='';selectedFile=null;uploadedMedia=null;$('uploadProgress').classList.remove('show');$('uploadBar').style.width='0';updatePreview()}
function selectedPlatforms(){return [...document.querySelectorAll('#platformChoices .platform.on')].map(x=>x.dataset.platform)}
function renderPreviewTabs(){const list=selectedPlatforms();if(!list.length){$('previewSwitch').innerHTML='<span style="font-size:9px;color:#9a9289">Select a platform</span>';selectedPreview='linkedin';return}if(!list.includes(selectedPreview))selectedPreview=list[0];$('previewSwitch').innerHTML=list.map(p=>`<button class="${p===selectedPreview?'on':''}" data-preview="${p}">${p[0].toUpperCase()+p.slice(1)}</button>`).join('');document.querySelectorAll('[data-preview]').forEach(b=>b.onclick=()=>{selectedPreview=b.dataset.preview;renderPreviewTabs();updatePreview()})}
function updatePreview(){const body=$('body').value.trim(),conn=user?.connections?.[selectedPreview]||{},name=selectedPreview==='youtube'?(conn.channelTitle||'Your YouTube channel'):(conn.name||conn.username||conn.igUsername||conn.pageName||user?.name||'Your profile');let media='';if($('mediaImg').style.display!=='none'&&$('mediaImg').src)media=`<img class="pv-media" src="${esc($('mediaImg').src)}" alt="">`;if($('mediaVideo').style.display!=='none'&&$('mediaVideo').src)media=`<video class="pv-media" src="${esc($('mediaVideo').src)}" controls playsinline></video>`;const label=selectedPreview==='linkedin'?'LinkedIn':selectedPreview==='facebook'?'Facebook':selectedPreview==='instagram'?'Instagram':selectedPreview==='x'?'X':selectedPreview==='youtube'?'YouTube':'TikTok';$('postPreview').innerHTML=`<div class="pv-head"><div class="pv-avatar"><i data-lucide="user"></i></div><div><div class="pv-name">${esc(name)}</div><div class="pv-sub">${label} · Preview</div></div></div><div class="pv-body">${esc(body||'Your caption will appear here.')}</div>${media}<div class="pv-actions"><span>Like</span><span>Comment</span><span>Share</span><span>Send</span></div>`;lucide.createIcons()}
function openModal(mode='draft'){populateModal(null,mode)}
function closeModal(){if($('publishBtn').classList.contains('is-loading'))return;$('modal').classList.remove('open');editingId=null;composerMode='draft';resetMedia()}
$('newPost').onclick=()=>openModal('draft');$('quickDraft').onclick=()=>openModal('draft');$('quickSchedule').onclick=()=>openModal('schedule');$('close').onclick=closeModal;$('cancel').onclick=closeModal;
$('body').oninput=()=>{$('count').textContent=$('body').value.length;updatePreview()};
async function prepareTikTokImage(file){
  if(file.type==='image/jpeg'||file.type==='image/webp')return file;
  return await new Promise((resolve,reject)=>{
    const img=new Image(); const url=URL.createObjectURL(file);
    img.onload=()=>{try{const max=1080;const scale=Math.min(1,max/Math.max(img.naturalWidth,img.naturalHeight));const w=Math.max(1,Math.round(img.naturalWidth*scale)),h=Math.max(1,Math.round(img.naturalHeight*scale));const c=document.createElement('canvas');c.width=w;c.height=h;const ctx=c.getContext('2d');ctx.drawImage(img,0,0,w,h);c.toBlob(blob=>{URL.revokeObjectURL(url);if(!blob)return reject(new Error('Could not prepare this image for TikTok.'));resolve(new File([blob],(file.name||'image').replace(/\.[^.]+$/,'')+'.jpg',{type:'image/jpeg'}));},'image/jpeg',0.92)}catch(e){URL.revokeObjectURL(url);reject(e)}};
    img.onerror=()=>{URL.revokeObjectURL(url);reject(new Error('Could not read this image.'))}; img.src=url;
  });
}
$('mediaFile').onchange=async()=>{const files=Array.from($('mediaFile').files||[]);if(!files.length)return;if(editingId)return;for(const f of files){if(!/^(image\/(jpeg|png|gif|webp)|video\/(mp4|quicktime|webm))$/.test(f.type))return notice('Unsupported media','Choose JPG, PNG, WEBP, GIF, MP4, MOV or WEBM files.','failure');if(f.size>200*1024*1024)return notice('File too large','Keep each media file under 200 MB.','failure')}if(files.some(f=>f.type.startsWith('video/'))&&files.length>1)return notice('One video at a time','TikTok supports one video per post. Use multiple images for a photo post.','failure');if(files.some(f=>f.type.startsWith('video/'))&&files.some(f=>f.type.startsWith('image/')))return notice('Choose one media type','Use either photos or one video for a TikTok post.','failure');if(files.length>35)return notice('Too many photos','TikTok supports up to 35 photos in one photo post.','failure');if($('mediaImg').src)URL.revokeObjectURL($('mediaImg').src);if($('mediaVideo').src)URL.revokeObjectURL($('mediaVideo').src);selectedFiles=files;selectedFile=files[0];uploadedMedia=null;const url=URL.createObjectURL(files[0]);if(files[0].type.startsWith('image/')){$('mediaImg').src=url;$('mediaImg').style.display='block';$('mediaVideo').style.display='none'}else{$('mediaVideo').src=url;$('mediaVideo').style.display='block';$('mediaImg').style.display='none'}$('mediaStatus').textContent=files.length>1?`${files.length} photos selected`:'';$('mediaPreview').classList.add('show');updatePreview()};$('removeMedia').onclick=()=>resetMedia(!!editingId);
async function uploadMedia(){
  if(!selectedFiles.length)return [];
  const status=$('uploadStatus'),bar=$('uploadStatusBar'),pct=$('uploadStatusPercent'),title=$('uploadStatusTitle'),msg=$('uploadStatusMessage');
  status.classList.add('show','busy'); title.textContent='Saving media'; msg.textContent='Your media is being securely saved to Creovah.'; bar.style.width='12%'; pct.textContent='12%'; $('uploadProgress').classList.add('show'); $('uploadBar').style.width='12%';
  const timer=setInterval(()=>{const current=parseInt(bar.style.width)||12;const next=Math.min(current+(current<55?7:current<82?3:1),90);bar.style.width=next+'%';pct.textContent=next+'%';$('uploadBar').style.width=next+'%'},700);
  try{
    const fd=new FormData(); selectedFiles.forEach(f=>fd.append('media',f));
    const r=await fetch('/api/media/upload',{method:'POST',headers:{Authorization:'Bearer '+t},body:fd});
    const d=await r.json().catch(()=>({})); if(!r.ok)throw new Error(d.message||'Media could not be saved.');
    clearInterval(timer); bar.style.width='100%';pct.textContent='100%';$('uploadBar').style.width='100%';title.textContent='Media saved';msg.textContent='Your media is ready for drafts, scheduling and publishing.';
    uploadedMedia=d.assets||[]; setTimeout(()=>status.classList.remove('show','busy'),900); return uploadedMedia;
  }catch(e){clearInterval(timer);bar.style.width='0';pct.textContent='0%';$('uploadBar').style.width='0';status.classList.remove('busy');title.textContent='Media save failed';msg.textContent=e.message||'The media could not be saved.';throw e}
}
function clientValidate(platforms,action){
  const errors=[]; const body=$('body').value.trim(); const files=selectedFiles||[]; const old=editingId?items.find(x=>x._id===editingId):null; const hasExisting=!!(old?.mediaAssets?.length||old?.mediaUrl||old?.mediaUrn); const hasMedia=files.length>0||hasExisting;
  const images=files.filter(f=>f.type.startsWith('image/')); const videos=files.filter(f=>f.type.startsWith('video/'));
  const add=(p,m)=>errors.push({platform:p,message:m});
  for(const p of platforms){
    const name=p==='x'?'X':p[0].toUpperCase()+p.slice(1);
    const max=p==='x'?280:p==='linkedin'?3000:p==='instagram'?2200:p==='facebook'?63206:p==='youtube'?5000:4000;
    if(body.length>max)add(p,`${name} allows up to ${max.toLocaleString()} characters. Your post has ${body.length.toLocaleString()}.`);
    if((p==='tiktok'||p==='instagram'||p==='youtube')&&!hasMedia)add(p,`${name} requires media for this post.`);
    if(p==='tiktok'){
      if(videos.length&&images.length)add(p,'Use photos or one video, not both, for a TikTok post.');
      if(videos.length>1)add(p,'TikTok video posts use one video at a time.');
      if(images.length>35)add(p,'TikTok photo posts support up to 35 images.');
      if(action==='schedule')add(p,'TikTok scheduling is not available yet. Publish TikTok posts now instead.');
    }
    if(p==='x'){if(images.length>4)add(p,'X allows up to 4 images in one post.');if(videos.length>1)add(p,'X allows one video in a post.');}
    if(p==='linkedin'&&(images.length>1||videos.length>1||images.length&&videos.length))add(p,'LinkedIn posts support one media item here. Use one photo or one video.');
    if(p==='youtube'){if(images.length)add(p,'YouTube posts require a video, not photos.');if(videos.length>1)add(p,'YouTube posts use one video at a time.');if(!videos.length&&!hasExisting)add(p,'YouTube requires a video for this post.');}
    if((p==='facebook'||p==='instagram')&&(action==='publish'||action==='schedule'))add(p,`${name} publishing is not available in this build yet.`);
  }
  return errors;
}
function showValidation(errors){
  if(!errors.length){clearInlineError();return false}
  const text=errors.map(e=>`${e.platform==='x'?'X':e.platform[0].toUpperCase()+e.platform.slice(1)}: ${e.message}`).join('\n');
  clearInlineError();
  notice('Fix these issues',text,'failure');
  return true;
}
async function submitContent(action){
  if(actionBusy)return;
  clearInlineError(); const platforms=selectedPlatforms();
  if(!platforms.length && (action==='publish'||action==='schedule')){showError('Platform required','Choose at least one connected platform.');return}
  if(action==='schedule'&&platforms.includes('tiktok')){if(showValidation([{platform:'tiktok',message:'TikTok scheduling is not available yet. Publish TikTok posts now instead.'}]))return}
  if((action==='publish'||action==='schedule')&&platforms.some(p=>!user.connections?.[p]?.connected)){const missing=platforms.filter(p=>!user.connections?.[p]?.connected).map(p=>({platform:p,message:`Connect ${p==='x'?'X':p[0].toUpperCase()+p.slice(1)} before publishing or scheduling.`}));if(showValidation(missing))return}
  if(!$('body').value.trim()){showError('Post is empty','Write something for your post.');return}
  const scheduledDate=localSchedule();
  if((action==='schedule'||action==='scheduled-edit')&&!scheduledDate){showError('Schedule time required','Choose a date and time.');return}
  if((action==='schedule'||action==='scheduled-edit')&&new Date(scheduledDate)<=new Date()){showError('Invalid schedule','Choose a future time.');return}
  if(action==='publish'||action==='schedule'){
    const validation=clientValidate(platforms,action); if(showValidation(validation))return;
  }
  if(action==='edit'||action==='scheduled-edit'){
    const editingItem=items.find(x=>x._id===editingId); const publishedTikTok=action==='edit'&&editingItem?.status==='published'&&editingItem?.platforms?.includes('tiktok')&&editingItem?.externalPosts?.tiktok;
    if(publishedTikTok&&!window.confirm('TikTok posts cannot be edited from Creovah. Your changes will be saved in Creovah, but the published TikTok caption will stay unchanged. Continue?'))return;
    try{const payload={body:$('body').value.trim()};if(action==='scheduled-edit')payload.scheduledFor=scheduledDate;if(editingItem?.status==='draft'&&selectedFiles.length)payload.mediaAssets=await uploadMedia();const r=await fetch('/api/content/'+editingId,{method:'PATCH',headers:{'Content-Type':'application/json',Authorization:'Bearer '+t},body:JSON.stringify(payload)});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||'Unable to update this post.');const i=items.findIndex(x=>x._id===editingId);if(i>=0)items[i]=d.item;renderContent();updateStats();closeModal();notice(action==='scheduled-edit'?'Schedule updated':'Post updated',d.message||'Your changes were saved.','success')}catch(e){notice('Update failed',e.message||'Unable to update this post.','failure')}return;
  }
  const btn=action==='publish'?$('publishBtn'):action==='schedule'?$('scheduleBtn'):$('draftBtn');actionBusy=true;btn?.classList.add('is-loading');
  try{
    let mediaAssets=[];
    if(selectedFiles.length)mediaAssets=await uploadMedia();
    else if(editingId){const existing=items.find(x=>x._id===editingId);mediaAssets=existing?.mediaAssets||[]}
    const payload={body:$('body').value.trim(),platforms,status:action==='schedule'?'scheduled':'draft',publishNow:action==='publish',scheduledFor:action==='schedule'?scheduledDate:null,mediaAssets,mediaAltText:$('altText').value.trim()};
    if(editingId&&action==='draft'){
      const r=await fetch('/api/content/'+editingId,{method:'PATCH',headers:{'Content-Type':'application/json',Authorization:'Bearer '+t},body:JSON.stringify({body:payload.body,mediaAssets})});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||'Unable to save the draft.');const i=items.findIndex(x=>x._id===editingId);if(i>=0)items[i]=d.item;renderContent();closeModal();notice('Draft saved','Your changes were saved.','success');return;
    }
    const r=await fetch('/api/content',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+t},body:JSON.stringify(payload)});const d=await r.json().catch(()=>({}));if(!r.ok){if(Array.isArray(d.errors)&&d.errors.length)showValidation(d.errors);throw new Error(d.message||'Unable to complete this action.');}items.unshift(d.item);renderContent();updateStats();closeModal();if(Array.isArray(d.errors)&&d.errors.length){notice('Published with issues',d.message+'\n\n'+d.errors.map(e=>`${e.platform}: ${e.message}`).join('\n'),'failure')}else notice(action==='publish'?'Published':action==='schedule'?'Scheduled':'Draft saved',action==='publish'?'Your post was published successfully.':action==='schedule'?'Your post is scheduled.':'Your draft has been saved.','success');
  }catch(e){console.error('Creovah action failed:',e);showError(action==='publish'?'Publish failed':action==='schedule'?'Schedule failed':'Draft failed',e.message||'Unable to complete this action.')}finally{actionBusy=false;btn?.classList.remove('is-loading');setTimeout(()=>$('uploadStatus').classList.remove('show','busy'),900)}
}

$('draftBtn').onclick=(e)=>{e.preventDefault();submitContent('draft')};$('scheduleBtn').onclick=(e)=>{e.preventDefault();submitContent('schedule')};$('publishBtn').onclick=(e)=>{e.preventDefault();submitContent(composerMode==='edit'?'edit':composerMode==='scheduled-edit'?'scheduled-edit':'publish')};
window.addEventListener('error',e=>{console.error(e.error||e.message);showError('Something went wrong','Something went wrong in the composer. Please refresh and try again.')});window.addEventListener('unhandledrejection',e=>{console.error(e.reason);showError('Something went wrong',e.reason?.message||'Something went wrong. Please try again.')});
const connectParams=new URLSearchParams(location.search);if((connectParams.get('connect')==='tiktok-success'||connectParams.get('connect')==='youtube-success')){history.replaceState({},'',location.pathname);setTimeout(()=>notice(connectParams.get('connect')==='youtube-success'?'YouTube connected':'TikTok connected',connectParams.get('message')|| (connectParams.get('connect')==='youtube-success'?'YouTube is ready to publish.':'TikTok is ready to publish.'),'success'),150)}else if(connectParams.get('connect')==='error'&&connectParams.get('reason')){history.replaceState({},'',location.pathname);setTimeout(()=>notice('Connection failed',connectParams.get('message')||'The social account could not be connected.','failure'),150)}
async function load(){try{const [u,c]=await Promise.all([fetch('/api/me',{headers:{Authorization:'Bearer '+t}}),fetch('/api/content',{headers:{Authorization:'Bearer '+t}})]);if(u.status===401)return location.href='/auth.html';const ud=await u.json(),cd=await c.json();user=ud.user;items=cd.items||[];$('menuName').textContent=user.name;$('sideName').textContent=user.name;updateStats();renderContent();renderPlatforms();renderPreviewTabs();updatePreview()}catch(e){notice('Unable to load','The workspace could not be loaded. Please refresh the page.','failure')}}
$('refreshBtn').onclick=load;$('menuBtn').onclick=e=>{$('menuDropdown').classList.toggle('open');e.stopPropagation()};document.addEventListener('click',e=>{if(!$('menuDropdown').contains(e.target)&&e.target!==$('menuBtn'))$('menuDropdown').classList.remove('open')});$('out').onclick=()=>{localStorage.removeItem('creovah_token');location.href='/'};lucide.createIcons();load();
