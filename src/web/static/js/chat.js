
/* ---------------------------
   Canonical Session ID (MUST BE FIRST)
---------------------------- */
if (!window.HCS_SESSION_ID) {
  window.HCS_SESSION_ID = Math.random().toString(36).substring(2, 10);
}

/* ---------------------------
   Inject Session ID into UI
---------------------------- */
document.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("sessionId");
  if (el) el.textContent = window.HCS_SESSION_ID;
});

/* =========================
   Demo data — Atlanta area
========================= */
const JOBS = [
  {
    title: "Crew Member",
    location: "Atlanta, GA 30303",
    type: "Part-time",
    pay: "$14–$16/hr",
    blurb: "Front counter & drive-thru support. Friendly guest service and quick line support.",
    role: "Crew",
    img: "../static/images/01-crew-member.png"
  },
  {
    title: "Line Cook",
    location: "Decatur, GA 30030",
    type: "Full-time",
    pay: "$16–$18/hr",
    blurb: "Prep & line — brisket, ribs, sides. Food safety and station cleanliness.",
    role: "Line Cook",
    img: "../static/images/02-line-cook.png"
  },
  {
    title: "Shift Manager",
    location: "Marietta, GA 30060",
    type: "Full-time",
    pay: "$18–$21/hr",
    blurb: "Lead shifts, coach crew, ensure food quality and guest satisfaction.",
    role: "Shift Manager",
    img: "../static/images/03-manager.png"
  },
  {
    title: "Cleaner (Evenings)",
    location: "Atlanta, GA 30303",
    type: "Part-time",
    pay: "$14–$16/hr",
    blurb: "Dining room & kitchen cleanup. Assist closing team.",
    role: "Cleaner",
    img: "../static/images/05-boh.png"
  },
  {
    title: "Line Cook (Weekends)",
    location: "Atlanta, GA 30303",
    type: "Part-time",
    pay: "$16–$18/hr",
    blurb: "Weekend rush coverage on the line. BBQ passion a plus.",
    role: "Line Cook",
    img: "../static/images/04-manager.png"
  }
];

/* ---------------------------
   DOM helpers
---------------------------- */
const $ = (sel, root = document) => root.querySelector(sel);

const jobGrid = $("#jobGrid");
const cardTpl = $("#jobCardTemplate");

/* ---------------------------
   Render job cards (SAFE)
---------------------------- */
function renderJobs(list) {
  if (!jobGrid || !cardTpl) return; // 🔒 Prevent crash on non-careers pages

  jobGrid.innerHTML = "";

  list.forEach(job => {
    const node = cardTpl.content.cloneNode(true);

    const title = $(".job-title", node);
    const location = $(".job-location", node);
    const type = $(".job-type", node);
    const pay = $(".job-pay", node);
    const blurb = $(".job-blurb", node);
    const img = $(".thumb", node);

    if (title) title.textContent = job.title;
    if (location) location.textContent = job.location;
    if (type) type.textContent = job.type;
    if (pay) pay.textContent = job.pay;
    if (blurb) blurb.textContent = job.blurb;

    if (img) {
      img.src = job.img;
      img.alt = job.title;
    }

    const viewBtn = $(".view-details", node);
    const applyBtn = $(".apply-btn", node);

    viewBtn?.addEventListener("click", () => openDetails(job));
    applyBtn?.addEventListener("click", () => openApply(job));

    jobGrid.appendChild(node);
  });
}

// Only render jobs if we are on the Careers page
if (jobGrid) {
  renderJobs(JOBS);
}

/* ---------------------------
   Details (chat)
---------------------------- */
function openDetails(job){
  openChat();
  biggieSay(`
    **${job.title} — ${job.location}**
    • Type: ${job.type}
    • Pay: ${job.pay}
    • ${job.blurb}
  `);
}

/* ---------------------------
   Apply flow
---------------------------- */
function openApply(job){
  localStorage.setItem("selectedJob", JSON.stringify(job));
  window.location.href = "/apply";
}

/* ---------------------------
   Chat Drawer behavior (SAFE)
---------------------------- */
const chatToggle = $("#chatToggle");
const chatDrawer = $("#chatDrawer");
const chatClose = $("#chatClose");
const chatForm = $("#chatForm");
const chatInput = $("#chatInput");
const chatLog = $("#chatLog");

function openChat(){
  if (!chatDrawer) return;
  chatDrawer.classList.add("open");
  chatInput?.focus();
  if (chatLog && !chatLog.children.length) {
    biggieSay("Hey! I’m Biggie. Ask me about roles or interviews.");
  }
}

function closeChat(){
  chatDrawer?.classList.remove("open");
}

chatToggle?.addEventListener("click", openChat);
chatClose?.addEventListener("click", closeChat);

/* ---------------------------
   Chat UI (SAFE)
---------------------------- */
function addMsg(text, who = "ai"){
  if (!chatLog) return;

  const row = document.createElement("div");
  row.className = `msg-row ${who}`;

  row.innerHTML = `
    ${who === "ai" ? `<img src="../static/images/brand/bigs-avatar.png" class="msg-avatar" />` : ``}
    <div class="msg-bubble">${text}</div>
  `;

  chatLog.appendChild(row);
}

function userSay(t){ addMsg(t, "user"); }
function biggieSay(t){ addMsg(t, "ai"); }

/* ---------------------------
   PII Sanitizer
---------------------------- */
function sanitizePII(text){
  return text
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, "XXX-XX-XXXX")
    .replace(/\b(\d{2}\/\d{2}\/\d{4})\b/g, "YYYY-MM-DD");
}

/* ---------------------------
   Chat submit logging (SAFE)
---------------------------- */
chatForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const msg = chatInput?.value.trim();
  if (!msg) return;

  const sanitized = sanitizePII(msg);
  userSay(sanitized);
  chatInput.value = "";

  if (window.HCS) {
    window.HCS.log("chat_message", { channel: "biggie" }, sanitized);
  }

  try {
    const response = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: sanitized })
    });

    const data = await response.json();
    biggieSay(data.reply);

  } catch (err) {
    biggieSay("Sorry, something went wrong.");
    console.error(err);
  }
});

/* ---------------------------
   Application Form Logging
---------------------------- */
const applyForm = document.getElementById("applyForm");

if (applyForm) {
  applyForm.addEventListener("submit", (e) => {
    e.preventDefault();

    const data = Object.fromEntries(new FormData(applyForm));

    Object.entries(data).forEach(([field, value]) => {
      const sanitized = sanitizePII(value);

      if (window.HCS) {
        window.HCS.log("apply_input", {
          field,
          channel: "application_form",
        }, sanitized);
      }
    });

    alert("Application submitted (demo).");
    applyForm.reset();
  });
}

const resumeUpload = document.getElementById("resumeUpload");

if (resumeUpload) {
  resumeUpload.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (window.HCS) {
      window.HCS.log("file_upload_attempt", {
        channel: "application_form",
        name: file.name,
        type: file.type,
        size: file.size
      }, file.name);
    }
  });
}
