// CreatorHub API is same-origin; the frontend and backend are served by the same Express app.
const creatorHubToken = localStorage.getItem("creatorhub_token");
const state = {
  scheduled: [
    {title:"New beat teaser", date:"Today · 7:30 PM", platforms:["Instagram","TikTok"], status:"Scheduled"},
    {title:"Behind the scenes", date:"Tomorrow · 12:00 PM", platforms:["Instagram","Facebook"], status:"Scheduled"},
    {title:"Client campaign launch", date:"Sep 14 · 6:00 PM", platforms:["Facebook","TikTok"], status:"Scheduled"}
  ],
  published: [
    {title:"Studio session", date:"Sep 8 · 6:40 PM", platforms:["Instagram","TikTok"], status:"Published"},
    {title:"New project announcement", date:"Sep 7 · 1:00 PM", platforms:["Facebook"], status:"Published"},
    {title:"Weekend drop", date:"Sep 5 · 8:00 PM", platforms:["Instagram","TikTok","Facebook"], status:"Published"}
  ],
  failed: [
    {title:"Product launch clip", date:"Sep 6 · Instagram", platforms:["Instagram"], status:"Failed"}
  ],
  accounts: [
    {name:"Instagram", handle:"@zibvh", icon:"IG", cls:"ig"},
    {name:"Facebook", handle:"CreatorHub Page", icon:"f", cls:"fb"},
    {name:"TikTok", handle:"@zibvh", icon:"♪", cls:"tt"}
  ]
};

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

function renderPosts(items, target) {
  const el = $(target);
  if (!el) return;
  el.innerHTML = items.length ? items.map(p => `
    <div class="post">
      <div class="thumb">▶</div>
      <div class="post-body">
        <div class="post-title">${escapeHtml(p.title)}</div>
        <div class="post-meta">${escapeHtml(p.date)} · ${p.platforms.join(" · ")}</div>
      </div>
      <span class="status ${p.status === "Published" ? "green" : p.status === "Failed" ? "red" : ""}">${p.status}</span>
    </div>`).join("") : `<div class="empty">Nothing here yet.</div>`;
}

function renderAccounts(target) {
  const el = $(target);
  if (!el) return;
  el.innerHTML = state.accounts.map(a => `
    <div class="${target === "#accountsGrid" ? "account-card" : "account"}">
      <span class="platform-icon ${a.cls}">${a.icon}</span>
      <div>
        <h3>${target === "#accountsGrid" ? a.name : `<strong>${a.name}</strong>`}</h3>
        <p>${a.handle}</p>
        ${target === "#accountsGrid" ? `<div class="connected"><i class="dot"></i> Connected</div>` : `<small>Connected</small>`}
      </div>
    </div>`).join("");
}

function render() {
  $("#statScheduled").textContent = state.scheduled.length;
  $("#statPublished").textContent = 24 + state.published.length - 3;
  $("#statFailed").textContent = state.failed.length;
  $("#statAccounts").textContent = state.accounts.length;
  $("#scheduledBadge").textContent = state.scheduled.length;
  renderPosts(state.scheduled.slice(0,3), "#dashboardScheduled");
  renderPosts(state.scheduled, "#scheduledList");
  renderPosts(state.published, "#publishedList");
  renderPosts(state.failed, "#failedList");
  renderAccounts("#dashboardAccounts");
  renderAccounts("#accountsGrid");
}

function showView(name) {
  $$(".view").forEach(v => v.classList.remove("active"));
  const view = $("#" + name + "View");
  if (view) view.classList.add("active");
  $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === name));
  $("#mobileDrawer").classList.remove("open");
  window.scrollTo({top:0, behavior:"smooth"});
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}

document.addEventListener("click", e => {
  const button = e.target.closest("[data-view]");
  if (button) {
    e.preventDefault();
    showView(button.dataset.view);
  }
});

$("#menuBtn").addEventListener("click", () => $("#mobileDrawer").classList.add("open"));
$("#closeDrawer").addEventListener("click", () => $("#mobileDrawer").classList.remove("open"));
$("#drawerBackdrop").addEventListener("click", () => $("#mobileDrawer").classList.remove("open"));

$("#browseBtn").addEventListener("click", () => $("#mediaInput").click());
$("#mediaInput").addEventListener("change", e => {
  const file = e.target.files[0];
  $("#fileName").textContent = file ? `Selected: ${file.name}` : "";
});

$$('input[name="platform"]').forEach(input => {
  input.addEventListener("change", () => input.closest(".platform").classList.toggle("active", input.checked));
});

$("#selectAll").addEventListener("click", () => {
  $$('input[name="platform"]').forEach(i => { i.checked = true; i.closest(".platform").classList.add("active"); });
});

$$('input[name="publishMode"]').forEach(radio => {
  radio.addEventListener("change", () => {
    const scheduled = $('input[name="publishMode"]:checked').value === "schedule";
    $("#scheduleFields").classList.toggle("hidden", !scheduled);
    $("#submitPost").textContent = scheduled ? "Schedule post" : "Publish now";
  });
});

$("#postForm").addEventListener("submit", e => {
  e.preventDefault();
  const caption = $("#caption").value.trim();
  const platforms = $$('input[name="platform"]:checked').map(i => i.value);
  const mode = $('input[name="publishMode"]:checked').value;
  if (!caption) return alert("Add a caption first.");
  if (!platforms.length) return alert("Choose at least one platform.");

  const title = caption.length > 42 ? caption.slice(0,42) + "…" : caption;
  let date;
  if (mode === "schedule") {
    const d = $("#scheduleDate").value;
    const t = $("#scheduleTime").value;
    if (!d || !t) return alert("Choose a date and time.");
    date = `${d} · ${t}`;
    state.scheduled.unshift({title, date, platforms, status:"Scheduled"});
  } else {
    date = "Just now";
    state.published.unshift({title, date, platforms, status:"Published"});
  }

  render();
  $("#postForm").reset();
  $("#scheduleFields").classList.add("hidden");
  $("#submitPost").textContent = "Publish now";
  $("#fileName").textContent = "";
  $$('input[name="platform"]').forEach(i => i.closest(".platform").classList.toggle("active", i.checked));
  showView(mode === "schedule" ? "scheduled" : "published");
});

const tomorrow = new Date();
tomorrow.setDate(tomorrow.getDate() + 1);
$("#scheduleDate").value = tomorrow.toISOString().slice(0,10);

render();
