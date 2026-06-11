// WTI Shield v9 — warning.js
// Threat blocking/warning page — shown instead of dangerous site

// ── Parse params from URL ────────────────────────────────────────
const p    = new URLSearchParams(window.location.search);
const url  = decodeURIComponent(p.get("url")    || "");
const tc   = p.get("threat")  || "phishing";
const risk = parseInt(p.get("risk") || "85");
const conf = parseFloat(p.get("conf") || "0.85");
const rule = p.get("rule") || "";
const sev  = p.get("sev")  || "HIGH";
const src  = p.get("source") || "rule_engine";

// ── Threat display data ──────────────────────────────────────────
const THREATS = {
  sql_injection: {
    name:"SQL INJECTION ATTACK", icon:"💉", color:"#ef4444",
    desc:"Database attack commands were found in this URL. If submitted, these commands could steal, modify, or destroy the website's entire database.",
    checks:[
      {bad:true,  txt:"SQL attack keywords detected in URL (UNION SELECT, DROP TABLE, etc.)"},
      {bad:true,  txt:"No HTTPS — data sent unencrypted"},
      {bad:false, txt:"No brand impersonation detected"},
    ]
  },
  xss: {
    name:"XSS ATTACK DETECTED", icon:"⚡", color:"#f97316",
    desc:"JavaScript injection code was found in this URL. If visited, this script will run in your browser and could steal your session, cookies, or passwords.",
    checks:[
      {bad:true,  txt:"JavaScript injection code in URL (<script> tags / event handlers)"},
      {bad:true,  txt:"Encoded characters used to hide malicious payload"},
      {bad:false, txt:"No SQL keywords detected"},
    ]
  },
  phishing: {
    name:"WEB THREAT / PHISHING", icon:"🕸️", color:"#a855f7",
    desc:"This site is impersonating a trusted brand to steal your login credentials, credit card, or personal information. The domain is fake.",
    checks:[
      {bad:true,  txt:"Suspicious domain extension (.tk / .xyz / .ml) detected"},
      {bad:true,  txt:"Brand name found in domain — possible impersonation"},
      {bad:true,  txt:"No HTTPS — unencrypted connection"},
    ]
  },
  ddos: {
    name:"DDOS ATTACK PATTERN", icon:"🌊", color:"#3b82f6",
    desc:"Abnormal traffic patterns from this source indicate a DDoS flooding attack targeting server resources.",
    checks:[
      {bad:true,  txt:"Abnormally high request rate detected"},
      {bad:true,  txt:"High error rate — server being overwhelmed"},
      {bad:true,  txt:"Multiple unique source IPs — botnet pattern"},
    ]
  },
};

const info = THREATS[tc] || THREATS.phishing;

// ── Render page ──────────────────────────────────────────────────
document.getElementById("mainIcon").textContent      = info.icon;
document.getElementById("mainTitle").textContent     = info.name;
document.getElementById("tcIcon").textContent        = info.icon;
document.getElementById("tcIcon").style.color        = info.color;
document.getElementById("tcName").textContent        = info.name;
document.getElementById("tcSub").textContent         =
  "Detected by WTI Shield · " + (src === "ml_model" ? "ML Model" : "Rule Engine");
document.getElementById("tcUrl").textContent         = url || "Unknown URL";
document.getElementById("statRisk").textContent      = risk + "%";
document.getElementById("statConf").textContent      = Math.round(conf * 100) + "%";
document.getElementById("statSev").textContent       = sev;
document.getElementById("bbSub").textContent         =
  "Risk Score: " + risk + "% · Click Go Back to stay safe";

// ── Why detected rows ────────────────────────────────────────────
const whyData = {
  sql_injection: [
    {ico:"💉", txt: "SQL keywords detected: " + (rule || "UNION SELECT, DROP TABLE patterns found")},
    {ico:"🔓", txt: "No HTTPS encryption — connection is insecure"},
    {ico:"📏", txt: "URL contains encoded attack payload characters"},
  ],
  xss: [
    {ico:"⚡", txt: "Script injection: <script> tags or event handlers (onerror=) in URL"},
    {ico:"🔀", txt: "Encoded characters used to hide JavaScript attack code"},
    {ico:"🔓", txt: "No HTTPS — your data is not encrypted"},
  ],
  phishing: [
    {ico:"🎭", txt: "Brand name found in domain — impersonating a trusted site"},
    {ico:"⚠️", txt: "Suspicious domain extension (.tk, .xyz, .ml) — free scam domain"},
    {ico:"➖", txt: "Multiple hyphens in domain (paypal-login-secure pattern)"},
  ],
  ddos: [
    {ico:"🌊", txt: "Request rate far above normal threshold"},
    {ico:"❌", txt: "High error rate — server under attack"},
    {ico:"🌐", txt: "Requests coming from many unique IP addresses"},
  ],
};

const rows = whyData[tc] || whyData.phishing;
if (rule) rows[0].txt = rule; // Use actual detected rule if available

document.getElementById("whyRows").innerHTML = rows.map(function(r) {
  return "<div class='why-row'>" +
    "<span class='why-ico'>" + r.ico + "</span>" +
    "<span class='why-bad'>" + r.txt + "</span>" +
    "</div>";
}).join("");

// ── Safety checks ────────────────────────────────────────────────
const checks = info.checks;
document.getElementById("checkRows").innerHTML = checks.map(function(c) {
  return "<div class='chk'>" +
    "<div class='chk-dot " + (c.bad ? "red" : "green") + "'></div>" +
    "<span>" + c.txt + "</span>" +
    "</div>";
}).join("");

// ── GEMINI AI ASSISTANT ──────────────────────────────────────────
const GEMINI_API_KEY = "AIzaSyCu6BdI1XTcuspa56SFMgEyRERfUpsMPCE"; // Replace with your key

const GEMINI_CONTEXT =
  "You are the AI Security Assistant for WTI Shield, a Chrome extension (final-year AI project). " +
  "Be natural and conversational — answer like a helpful security expert, not a scripted bot.\n\n" +
  "BLOCKED THREAT DETAILS:\n" +
  "URL: " + url + "\n" +
  "Threat: " + info.name + " | Risk: " + risk + "% | Confidence: " + Math.round(conf * 100) + "% | Severity: " + sev + "\n" +
  "Detection: " + (rule || "ML Model (Random Forest)") + "\n" +
  "Engine: " + (src === "ml_model" ? "Flask ML Model — 32 features, ~99% accuracy" : "Rule-Based Engine") + "\n\n" +
  "WTI Shield: Detects SQL Injection, XSS, Web Threat/Phishing, DDoS. " +
  "Uses Random Forest + SHAP/LIME XAI. Dataset: 10,000 samples, anti-overfit.\n\n" +
  "Answer the user's EXACT question directly using the threat data above. " +
  "Be concise (3-5 sentences). Use **bold** naturally. " +
  "Never refuse cybersecurity education questions.\n\n" +
  "User question: ";

// Chat history for multi-turn conversation
const chatHistory = [];

async function callGemini(userMsg) {
  if (!GEMINI_API_KEY || GEMINI_API_KEY === "YOUR_GEMINI_API_KEY") return null;

  // Build multi-turn conversation history
  const contents = [];

  // Add conversation history
  chatHistory.forEach(function(m) {
    contents.push({
      role: m.role === "bot" ? "model" : "user",
      parts: [{ text: m.text }]
    });
  });

  // Add current message with context
  const fullMsg = chatHistory.length === 0
    ? GEMINI_CONTEXT + "\n\nUser's first question: " + userMsg
    : userMsg;

  contents.push({ role: "user", parts: [{ text: fullMsg }] });

  const endpoint =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" +
    GEMINI_API_KEY;

  try {
    const ctrl = new AbortController();
    setTimeout(function() { ctrl.abort(); }, 9000);
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: contents,
        generationConfig: { maxOutputTokens: 400, temperature: 1.0 }
      }),
      signal: ctrl.signal
    });
    if (!res.ok) return null;
    const data = await res.json();
    const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text || null;
    if (reply) {
      chatHistory.push({ role: "user", text: userMsg });
      chatHistory.push({ role: "bot",  text: reply });
      if (chatHistory.length > 20) chatHistory.splice(0, 2);
    }
    return reply;
  } catch (e) {
    return null;
  }
}

function offlineFallback(msg) {
  const q = msg.toLowerCase();
  if (/why|reason|how|detected|flagged/.test(q))
    return "🔍 **Detected because:** " + (rule || info.name + " patterns were found in the URL.") +
      " The AI model analyzed 32 URL features and found clear attack signatures with " +
      Math.round(conf * 100) + "% confidence.";
  if (/what.*" + tc.replace("_"," ") + "|what is/.test(q))
    return "💡 " + info.desc;
  if (/safe|proceed|visit|go|continue/.test(q))
    return "❌ **Do NOT proceed to this site!** Risk score is " + risk + "% — this is a confirmed " +
      info.name + ". " + info.desc + " Click **Go Back to Safety** immediately.";
  if (/risk|score|percent/.test(q))
    return "📊 **Risk Score: " + risk + "%** — " + sev + " severity. " +
      "0-49% = Low, 50-79% = Medium, 80-100% = High. " +
      "This URL scored " + risk + "% indicating a high-confidence " + info.name.toLowerCase() + ".";
  if (/shap|xai|explainable|feature/.test(q))
    return "🧠 **SHAP** (SHapley Additive exPlanations) shows WHY the AI classified this as " +
      info.name + ". Each of the 32 URL features gets an impact score. " +
      "The detection rule was: " + (rule || "ML model confidence above threshold") + ".";
  if (/block|why block|stop/.test(q))
    return "🛡️ WTI Shield blocked this site because the risk score (" + risk + "%) exceeds the " +
      "safety threshold (65%). This protects you from " + info.name.toLowerCase() + " attacks " +
      "before any damage occurs.";
  return "🤖 Ask me anything about this " + info.name + " threat, what it means, " +
    "what you should do, or anything about WTI Shield and cybersecurity.";
}

// ── Chat functions ───────────────────────────────────────────────
function getTime() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function fmt(txt) {
  return txt
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/`(.*?)`/g, "<code>$1</code>")
    .replace(/\n/g, "<br>");
}

function addMsg(role, text) {
  chatHistory.push({ role, text });
  const d = document.createElement("div");
  d.className = "cmsg " + role;
  d.innerHTML = "<div class='cmsg-b'>" + fmt(text) + "</div>" +
    "<div class='cmsg-time'>" + (role === "bot" ? "WTI AI · " : "") + getTime() + "</div>";
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop = 9999;
}

function showTyping() {
  const d = document.createElement("div");
  d.className = "cmsg bot"; d.id = "typ";
  d.innerHTML = "<div class='typing'><span></span><span></span><span></span></div>";
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop = 9999;
  return d;
}

function renderChips() {
  const chips = [
    "Why was this blocked?",
    "What is " + (tc === "sql_injection" ? "SQL injection?" : tc === "xss" ? "XSS?" : tc === "phishing" ? "phishing?" : "DDoS?"),
    "Is it safe to proceed?",
    "What should I do?",
    "Explain the risk score"
  ];
  document.getElementById("chatChips").innerHTML = chips.map(function(c) {
    return "<button class='chip' data-chip='" + c.replace(/'/g, "&#39;") + "'>" + c + "</button>";
  }).join("");
}

async function sendMsg(text) {
  if (!text || !text.trim()) return;
  addMsg("user", text);
  document.getElementById("chatIn").value = "";
  const typing = showTyping();
  try {
    let reply = await callGemini(text);
    if (!reply) reply = offlineFallback(text);
    typing.remove();
    addMsg("bot", reply);
    renderChips();
  } catch (e) {
    typing.remove();
    addMsg("bot", offlineFallback(text));
  }
}

// ── Init ─────────────────────────────────────────────────────────
function init() {
  const modeEl = document.getElementById("chatMode");
  if (modeEl) {
    modeEl.textContent = (GEMINI_API_KEY && GEMINI_API_KEY !== "YOUR_GEMINI_API_KEY")
      ? "✨ Gemini AI · Ask me anything"
      : "📴 Offline · Built-in knowledge";
  }

  // Welcome message — explains the threat
  addMsg("bot",
    info.icon + " **" + info.name + " detected!**\n\n" +
    info.desc + "\n\n" +
    "Risk: **" + risk + "%** · Confidence: **" + Math.round(conf * 100) + "%**\n\n" +
    "I recommend clicking **Go Back to Safety**. Ask me anything about this threat!"
  );
  renderChips();
}

// ── Wire buttons ─────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function() {

  // Go back buttons
  ["btnBack", "bbBack"].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener("click", function() {
      history.back();
      // If no history, close tab
      setTimeout(function() { window.close(); }, 300);
    });
  });

  // View report
  var rptBtn = document.getElementById("btnReport");
  if (rptBtn) rptBtn.addEventListener("click", function() {
    chrome.runtime.sendMessage({
      type:   "OPEN_REPORT",
      url:    url,
      threat: tc,
      risk:   risk,
      conf:   conf,
      rule:   rule,
      sev:    sev,
      source: src,
    });
  });

  // Proceed anyway (unsafe)
  var proceedBtn = document.getElementById("btnProceed");
  if (proceedBtn) proceedBtn.addEventListener("click", function() {
    if (confirm("⚠️ WARNING: This site has been flagged as " + info.name + " with " + risk +
                "% risk. Are you absolutely sure you want to proceed?")) {
      window.location.href = url;
    }
  });

  // Ignore warning (bottom bar)
  var ignoreBtn = document.getElementById("bbIgnore");
  if (ignoreBtn) ignoreBtn.addEventListener("click", function() {
    if (confirm("This site is flagged as a threat. Proceed anyway?")) {
      window.location.href = url;
    }
  });

  // Chat
  var sendBtn = document.getElementById("chatSend");
  if (sendBtn) sendBtn.addEventListener("click", function() {
    var val = document.getElementById("chatIn").value.trim();
    if (val) sendMsg(val);
  });

  var chatIn = document.getElementById("chatIn");
  if (chatIn) chatIn.addEventListener("keydown", function(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      document.getElementById("chatSend").click();
    }
  });

  var chips = document.getElementById("chatChips");
  if (chips) chips.addEventListener("click", function(e) {
    var chip = e.target.closest("[data-chip]");
    if (chip) sendMsg(chip.dataset.chip);
  });

  init();
});
