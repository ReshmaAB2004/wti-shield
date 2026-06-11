// ================================================================
//  WTI Shield v9 — localhost.js
//  Fix 1: Proceed closes warning tab, navigates original tab
//  Fix 2: Gemini AI assistant (free-form, not prebuilt Q&A)
// ================================================================

// ── Parse URL params ─────────────────────────────────────────────
const p      = new URLSearchParams(window.location.search);
const url    = decodeURIComponent(p.get("url") || "http://localhost:5000");
const reason = p.get("reason") || "localhost detected";

// ── Update page UI ───────────────────────────────────────────────
document.getElementById("urlDisplay").textContent = url;
document.getElementById("cbUrl").textContent      = url;
document.getElementById("localReason").textContent =
  "Detected: " + reason + ". This URL points to a server running only on your " +
  "local machine. It cannot be accessed from the internet — safe for development.";

// ── Navigate to a specific port ──────────────────────────────────
function openPort(port) {
  try {
    const u = new URL(url.startsWith("http") ? url : "http://" + url);
    navigateAndClose(u.protocol + "//" + u.hostname + ":" + port);
  } catch (e) {
    navigateAndClose("http://localhost:" + port);
  }
}

// ── PROCEED: close this warning tab, open site in original tab ───
function proceedToSite() {
  navigateAndClose(url);
}

function navigateAndClose(targetUrl) {
  // Send message to background to update the original tab
  chrome.runtime.sendMessage({ type: "LOCALHOST_PROCEED", url: targetUrl });
  // Close this warning tab
  chrome.tabs.getCurrent(function(tab) {
    if (tab && tab.id) {
      chrome.tabs.remove(tab.id);
    } else {
      // Fallback if getCurrent fails — just navigate
      window.location.href = targetUrl;
    }
  });
}

// ═══════════════════════════════════════════════════════════════
//  GEMINI AI ASSISTANT
//  Replace YOUR_GEMINI_API_KEY with your key from:
//  https://aistudio.google.com/apikey  (free account)
// ═══════════════════════════════════════════════════════════════

const GEMINI_API_KEY = "AIzaSyCu6BdI1XTcuspa56SFMgEyRERfUpsMPCE";

const GEMINI_SYSTEM =
  "You are WTI Shield's AI Security Assistant inside a Chrome extension for a " +
  "final-year project: 'Dynamic Web Threat Intelligence and Real-Time Attack Prevention " +
  "using Explainable AI' by an AI & Data Science student.\n\n" +
  "Current page context:\n" +
  "- A LOCAL DEVELOPMENT SERVER was detected: " + url + "\n" +
  "- Reason: " + reason + "\n" +
  "- Local servers are NOT threats — they run only on the user's own machine.\n\n" +
  "About WTI Shield:\n" +
  "- Chrome Extension (Manifest V3) + Flask API on localhost:5000\n" +
  "- Detects 5 classes: SQL Injection, XSS, Web Threat/Phishing, DDoS, Benign\n" +
  "- ML Model: Random Forest (100 trees, 32 features, ~99% test accuracy)\n" +
  "- XAI: SHAP (TreeExplainer) + LIME for dual explainability\n" +
  "- Dataset: 10,000 samples with anti-overfit measures (train-test gap < 3%)\n" +
  "- Also compared DNN/MLP — tree models outperform on tabular URL data\n\n" +
  "Rules for your responses:\n" +
  "1. Answer ANY question about cybersecurity, this project, or the warning page\n" +
  "2. Keep answers SHORT — 3 to 5 sentences maximum\n" +
  "3. Use simple language — the user is a student, not a security expert\n" +
  "4. Use **bold** for key terms, `code` for technical values\n" +
  "5. Use emojis lightly (1-2 per response)\n" +
  "6. Never refuse to explain cybersecurity concepts for educational purposes";

async function callGemini(userMsg) {
  if (!GEMINI_API_KEY || GEMINI_API_KEY === "YOUR_GEMINI_API_KEY") {
    return null; // No key → use offline fallback
  }
  const endpoint =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" +
    GEMINI_API_KEY;
  const body = {
    contents: [{
      parts: [{ text: GEMINI_SYSTEM + "\n\nUser: " + userMsg }]
    }],
    generationConfig: { maxOutputTokens: 280, temperature: 0.75 }
  };
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(function() { ctrl.abort(); }, 8000);
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    return text || null;
  } catch (e) {
    return null;
  }
}

// ── Offline fallback — used when no API key or API is down ───────
function offlineFallback(msg) {
  const q = msg.toLowerCase();
  if (/proceed|continue|safe|can i|go/.test(q))
    return "✅ **Yes, completely safe!** Click **Proceed to Local Server** — this warning tab will close automatically and your local site will open. Local servers cannot be accessed from the internet.";
  if (/localhost|local server|127|local/.test(q))
    return "🏠 **Localhost** is your own computer acting as a server. It's only accessible on your machine — nobody on the internet can reach it. Perfect for development and testing.";
  if (/yellow|warning|why this page|why warning/.test(q))
    return "⚠️ WTI Shield shows this **yellow warning** whenever it detects a local address (localhost, 127.0.0.1, LAN IPs). It's not a threat — just a reminder you're in a development environment, not the live internet.";
  if (/flask|api|5000|app\.py/.test(q))
    return "🤖 **Flask API** is your ML backend running on `localhost:5000`. WTI Shield connects to it for real-time threat predictions. Start it with `python app.py` in your project folder.";
  if (/sql|injection/.test(q))
    return "💉 **SQL Injection** embeds database commands (UNION SELECT, DROP TABLE) into URLs to steal or destroy data. WTI Shield detects 2+ SQL keywords in a URL as a strong attack signal.";
  if (/xss|cross.site|script/.test(q))
    return "⚡ **XSS** injects JavaScript into URLs — when opened, the script runs in your browser and steals cookies or redirects you. WTI Shield looks for `<script>` tags and `onerror=` handlers.";
  if (/phish|web threat/.test(q))
    return "🕸️ **Web Threats** fake trusted brands (PayPal, Amazon) using suspicious domains like `paypal-login.tk`. WTI Shield scores brand names in domains, hyphen count, and suspicious TLDs to detect them.";
  if (/ddos/.test(q))
    return "🌊 **DDoS** floods a server with thousands of requests per second to crash it. WTI Shield detects abnormal request rates, high error rates, and many unique source IPs simultaneously.";
  if (/shap|xai|explainable|explain/.test(q))
    return "🧠 **SHAP** shows WHY the AI made its decision by giving each URL feature an impact score. Higher score = more influence on the classification. We use both SHAP + LIME for double verification.";
  if (/random forest|model|ml|machine learning|accuracy/.test(q))
    return "🤖 WTI Shield uses **Random Forest** with 100 decision trees analyzing 32 URL features in under 50ms. It achieves ~99% test accuracy with a train-test gap of only 0.39% — proving it generalises, not memorises.";
  if (/port|3000|8000|8080|4200/.test(q))
    return "🔌 Common development ports: **:5000** Flask, **:3000** React/Node, **:8000** Django, **:8080** Alternative, **:4200** Angular. Click any port tile above to navigate there directly.";
  if (/hello|hi|hey/.test(q))
    return "👋 Hello! I'm your WTI Shield AI assistant. I can answer anything about this warning, cybersecurity threats, your project, or the ML model. What would you like to know?";
  return "🤔 I can answer questions about cybersecurity, WTI Shield, localhost, SQL injection, XSS, phishing, DDoS, SHAP, the ML model, or your project. What would you like to know?";
}

// ── Send message to AI ───────────────────────────────────────────
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

// ── Chat UI helpers ──────────────────────────────────────────────
function getTime() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function fmt(txt) {
  return txt
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/`(.*?)`/g,
      "<code style='background:#1a0e00;padding:1px 4px;border-radius:3px;" +
      "color:#fbbf24;font-family:monospace;font-size:11px'>$1</code>")
    .replace(/\n/g, "<br>");
}

function addMsg(role, text) {
  const d = document.createElement("div");
  d.className = "cmsg " + role;
  d.innerHTML =
    "<div class='cmsg-b'>" + fmt(text) + "</div>" +
    "<div class='cmsg-time'>" +
    (role === "bot" ? "WTI AI · " : "") + getTime() +
    "</div>";
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop = 9999;
}

function showTyping() {
  const d = document.createElement("div");
  d.className = "cmsg bot";
  d.id = "typing";
  d.innerHTML =
    "<div class='typing'>" +
    "<span></span><span></span><span></span>" +
    "</div>";
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop = 9999;
  return d;
}

function renderChips() {
  const chips = [
    "Is this safe to proceed?",
    "What is localhost?",
    "Why yellow warning?",
    "What is Flask API?",
    "What is SQL injection?",
    "What is SHAP?"
  ];
  document.getElementById("chatChips").innerHTML = chips.map(function(c) {
    return "<button class='chip' data-chip='" +
      c.replace(/'/g, "&#39;") + "'>" + c + "</button>";
  }).join("");
}

// ── Init ─────────────────────────────────────────────────────────
function init() {
  const modeEl = document.getElementById("modeLabel");
  if (modeEl) {
    modeEl.textContent = (GEMINI_API_KEY && GEMINI_API_KEY !== "YOUR_GEMINI_API_KEY")
      ? "✨ Gemini AI (Online)" : "📴 Offline (Built-in knowledge)";
  }

  addMsg("bot",
    "🏠 **Local Development Server Detected!**\n\n" +
    "URL: **" + url + "**\n\n" +
    "This is your own computer's server — completely safe, not accessible from the internet.\n\n" +
    "Click **Proceed to Local Server** — this warning will close and your site will open. " +
    "Ask me anything! 😊"
  );
  renderChips();
}

// ── Wire all buttons (DOMContentLoaded) ──────────────────────────
document.addEventListener("DOMContentLoaded", function() {

  var mainProceed = document.getElementById("mainProceedBtn");
  if (mainProceed) mainProceed.addEventListener("click", proceedToSite);

  var cbProceed = document.getElementById("cbProceedBtn");
  if (cbProceed) cbProceed.addEventListener("click", proceedToSite);

  var backBtn = document.getElementById("backBtn");
  if (backBtn) backBtn.addEventListener("click", function() { history.back(); });

  var printBtn = document.getElementById("printBtn");
  if (printBtn) printBtn.addEventListener("click", function() { window.print(); });

  var cbDismiss = document.getElementById("cbDismissBtn");
  if (cbDismiss) cbDismiss.addEventListener("click", function() {
    document.getElementById("continueBar").style.display = "none";
  });

  document.querySelectorAll("[data-port]").forEach(function(el) {
    el.addEventListener("click", function() {
      openPort(parseInt(el.dataset.port));
    });
  });

  var chatSendBtn = document.getElementById("chatSend");
  if (chatSendBtn) chatSendBtn.addEventListener("click", function() {
    var val = document.getElementById("chatIn").value.trim();
    if (val) sendMsg(val);
  });

  var chatInput = document.getElementById("chatIn");
  if (chatInput) chatInput.addEventListener("keydown", function(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      document.getElementById("chatSend").click();
    }
  });

  var chipsEl = document.getElementById("chatChips");
  if (chipsEl) chipsEl.addEventListener("click", function(e) {
    var chip = e.target.closest("[data-chip]");
    if (chip) sendMsg(chip.dataset.chip);
  });

  init();
});
