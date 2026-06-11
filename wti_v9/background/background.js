// ============================================================
//  WTI Shield v5 — Background Service Worker
//  NOW CONNECTED TO FLASK ML MODEL (model_training.py)
//  Fallback: rule-based engine if Flask server is offline
// ============================================================

// ── Flask API Configuration ───────────────────────────────────────────────────
const API_URL     = "http://localhost:5000/predict";   // Your Flask server
const API_HEALTH  = "http://localhost:5000/health";    // Health check endpoint
const API_TIMEOUT = 4000;                              // 4 seconds max wait

// ── ML API Status (tracked live) ─────────────────────────────────────────────
let mlApiOnline   = false;   // true = Flask is running, false = use fallback
let mlApiChecked  = false;   // have we checked at least once?
let lastHealthCheck = 0;     // timestamp of last health check

// ── Constants ─────────────────────────────────────────────────────────────────
const CLASSES      = ["benign","sql_injection","xss","phishing","ddos"];
const TRUSTED      = ["google.com","youtube.com","apple.com","amazon.com","microsoft.com",
  "facebook.com","instagram.com","linkedin.com","twitter.com","x.com","github.com",
  "stackoverflow.com","wikipedia.org","reddit.com","netflix.com","dropbox.com",
  "ebay.com","paypal.com","steam.com","bing.com","whatsapp.com","office.com"];
const BRAND_KW     = ["paypal","appleid","amazon","microsoft","facebook","netflix",
  "instagram","whatsapp","wellsfargo","citibank","hsbc","barclays","dropbox","steam",
  "roblox","chase","bankofamerica"];
const SUSP_TLDS    = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",
  ".online",".site",".biz",".club",".work",".live",".pw",".cc",".ws"];
const SQL_KW       = ["union select","union+select","1=1","1 = 1","insert into",
  "drop table","drop database","--","/**/","xp_cmd","exec(","cast(0x",
  "benchmark(","sleep(","' or '",'\" or \"',"or 1=1","or+1=1"];
const PHISH_BRANDS = ["paypal","amazon","appleid","microsoft","netflix","facebook",
  "instagram","wellsfargo","chase","citibank","barclays","steam","roblox"];
const PHISH_TLDS   = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".info",".biz"];
const PHISH_KW     = ["login","signin","verify","secure","update","account",
  "password","confirm","credential","wallet","suspended","billing","support"];

const SKIP_PREFIXES = ["chrome://","chrome-extension://","about:","edge://",
                       "data:","devtools://","moz-extension://"];

// ── Helper: is this a URL we should skip? ─────────────────────────────────────
function shouldSkip(url) {
  return !url || SKIP_PREFIXES.some(p => url.startsWith(p));
}

// ── Helper: detect localhost / LAN / development server ──────────────────────
function isLocalhost(url) {
  if (!url) return { local: false, reason: "" };
  try {
    const u    = new URL(url.startsWith("http") ? url : "http://" + url);
    const host = (u.hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
    const port = u.port;
    // Exact local addresses
    if (["localhost","127.0.0.1","::1","0.0.0.0"].includes(host))
      return { local: true, reason: `localhost${port?":"+port:""}` };
    // Private IP ranges
    if (/^192\.168\.\d+\.\d+$/.test(host))
      return { local: true, reason: `LAN address (${host})` };
    if (/^10\.\d+\.\d+\.\d+$/.test(host))
      return { local: true, reason: `private network (${host})` };
    if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host))
      return { local: true, reason: `private network (${host})` };
    // Local dev TLDs
    const localSuffixes = [".local",".localhost",".internal",".dev",".test",".lan",".home"];
    for (const s of localSuffixes) {
      if (host === s.slice(1) || host.endsWith(s))
        return { local: true, reason: `local dev domain (${host})` };
    }
  } catch {}
  return { local: false, reason: "" };
}

// ── Helper: is this a trusted real domain? ────────────────────────────────────
function isTrusted(host) {
  const h = host.replace(/^www\./, "");
  return TRUSTED.some(d => h === d || h.endsWith("." + d));
}

// ── Helper: Shannon entropy of a string ──────────────────────────────────────
function entropy(s) {
  if (!s) return 0;
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  return -Object.values(f).reduce((t, v) => t + (v / s.length) * Math.log2(v / s.length), 0);
}

// ── Helper: normalise array to sum=1 ─────────────────────────────────────────
function norm(arr) {
  const t = arr.reduce((a, b) => a + b, 0) || 1;
  return arr.map(v => v / t);
}

// ─────────────────────────────────────────────────────────────────────────────
//  FEATURE EXTRACTION  (mirrors model_training.py exactly — 26 base features)
//  Used both for fallback prediction AND to send features to Flask API
// ─────────────────────────────────────────────────────────────────────────────
function extractFeatures(url) {
  let host = "", scheme = "http", domain = "";
  try {
    const u = new URL(url.startsWith("http") ? url : "http://" + url);
    host   = u.hostname.toLowerCase();
    scheme = u.protocol.replace(":", "");
  } catch { host = url; }

  const parts  = host.split(".");
  domain       = parts.length >= 2 ? parts[parts.length - 2] : host;
  const subs   = parts.length > 2  ? parts.slice(0, -2) : [];
  const low    = url.toLowerCase();
  const trusted = isTrusted(host);

  return {
    url_length          : url.length,
    num_special_chars   : (url.match(/[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]/g) || []).length,
    has_ip              : /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 1 : 0,
    num_subdomains      : subs.length,
    has_https           : scheme === "https" ? 1 : 0,
    entropy             : +entropy(url).toFixed(4),
    num_digits          : (url.match(/\d/g) || []).length,
    num_params          : (url.match(/[?&]/g) || []).length,
    payload_length      : url.length,
    num_encoded_chars   : (url.match(/%[0-9a-fA-F]{2}/g) || []).length,
    num_sql_keywords    : SQL_KW.filter(k => low.includes(k)).length,
    num_script_tags     : (low.match(/<script/g) || []).length,
    num_event_handlers  : (low.match(/on\w+\s*=/g) || []).length,
    brand_keyword_count : trusted ? 0 : BRAND_KW.filter(b => low.includes(b)).length,
    has_brand_in_domain : trusted ? 0 : (BRAND_KW.some(b => domain.includes(b)) ? 1 : 0),
    has_suspicious_tld  : SUSP_TLDS.some(t => host.endsWith(t)) ? 1 : 0,
    num_hyphens_domain  : (domain.match(/-/g) || []).length,
    domain_length       : host.length,
    has_at_symbol       : url.includes("@") ? 1 : 0,
    has_double_slash    : url.replace("://", "").includes("//") ? 1 : 0,
    num_dots            : (url.match(/\./g) || []).length,
    req_per_second      : 1,
    avg_payload_size    : 300,
    unique_ips          : 1,
    error_rate          : 0,
    req_size_variance   : 20,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  RULE-BASED FALLBACK PREDICTOR
//  Runs locally in JS when Flask server is offline.
//  Exactly mirrors the rule overrides in model_training.py
// ─────────────────────────────────────────────────────────────────────────────
function predictRuleBased(url) {
  if (shouldSkip(url)) return null;

  const feats = extractFeatures(url);
  const low   = url.toLowerCase();
  let probs   = [0.90, 0.04, 0.03, 0.02, 0.01];
  let cls     = "benign", conf = 0.90, rule = null;

  // ── SQL Injection ─────────────────────────────────────────────────────────
  const sqlN = SQL_KW.filter(k => low.includes(k)).length;
  if (sqlN >= 2) {
    conf  = Math.min(0.55 + sqlN * 0.08, 0.97);
    probs = norm([1 - conf, conf, 0.01, 0.01, 0.01]);
    cls   = "sql_injection";
    rule  = `SQL rule (${sqlN} keywords) [fallback]`;
  }

  // ── XSS ──────────────────────────────────────────────────────────────────
  const xssN = (low.match(/<script/g)    || []).length * 2
             + (low.match(/on\w+\s*=/g)  || []).length
             + (low.match(/javascript:/g) || []).length * 2;
  if (xssN >= 2 && !rule) {
    conf  = Math.min(0.55 + xssN * 0.07, 0.97);
    probs = norm([1 - conf, 0.01, conf, 0.01, 0.01]);
    cls   = "xss";
    rule  = `XSS rule (${xssN} signals) [fallback]`;
  }

  // ── Phishing — enhanced detection ────────────────────────────────────────
  let host = "";
  try { host = new URL(url.startsWith("http") ? url : "http://" + url).hostname.toLowerCase(); } catch {}
  let ps = 0;
  const phishWhy = [];
  if (!isTrusted(host)) {
    // Brand in domain (e.g. paypal-login.com, amazon-secure.net)
    if (PHISH_BRANDS.some(b => host.includes(b) && !host.endsWith(b + ".com"))) {
      ps += 5; phishWhy.push("brand in domain");
    }
    // Suspicious free TLD
    if (PHISH_TLDS.some(t => host.endsWith(t))) {
      ps += 4; phishWhy.push("suspicious TLD");
    }
    // Multiple hyphens in domain (paypal-login-secure)
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 2) { ps += 3; phishWhy.push(hyphenCount + " hyphens"); }
    else if (hyphenCount === 1) { ps += 1; }
    // IP address used
    if (feats.has_ip) { ps += 4; phishWhy.push("IP address"); }
    // Suspicious subdomains (login.secure.paypal.evil.com)
    if (feats.num_subdomains >= 3) { ps += 3; phishWhy.push("deep subdomains"); }
    // @ symbol in URL
    if (feats.has_at_symbol) { ps += 4; phishWhy.push("@ symbol"); }
    // Phishing keywords in URL path (login, verify, secure, account etc.)
    const kwHits = PHISH_KW.filter(k => low.includes(k)).length;
    ps += kwHits;
    if (kwHits > 0) phishWhy.push(kwHits + " phish keywords");
    // Long domain (attackers use long domains to look legitimate)
    if (host.length > 30) { ps += 1; }
    // No HTTPS on a site with phishing keywords — extra suspicious
    if (feats.has_https === 0 && kwHits > 0) { ps += 2; phishWhy.push("no HTTPS + keywords"); }
    // Domain contains numbers (secure123.paypal-login.tk)
    if (/\d/.test(host.split(".")[0])) { ps += 1; }
  }
  if (ps >= 3 && !rule) {   // FIX: lowered threshold 4 → 3
    conf  = Math.min(0.50 + ps * 0.055, 0.97);
    probs = norm([1 - conf, 0.01, 0.01, conf, 0.01]);
    cls   = "phishing";
    rule  = `Web Threat (score=${ps}: ${phishWhy.join(", ")}) [fallback]`;
  }

  // ── DDoS (browser can't measure req/s, so always LOW unless forced) ───────
  if (feats.req_per_second > 500 && !rule) {
    conf  = Math.min(0.70 + feats.error_rate * 0.25, 0.97);
    probs = norm([1 - conf, 0.01, 0.01, 0.01, conf]);
    cls   = "ddos";
    rule  = `DDoS rule (${feats.req_per_second} req/s) [fallback]`;
  }

  return {
    url,
    threat_class   : cls,
    confidence     : +conf.toFixed(4),
    risk_score     : Math.round(conf * 1000) / 10,
    is_malicious   : cls !== "benign",
    severity       : conf >= 0.80 ? "HIGH" : conf >= 0.50 ? "MEDIUM" : "LOW",
    rule_triggered : rule,
    all_probs      : Object.fromEntries(CLASSES.map((c, i) => [c, +probs[i].toFixed(4)])),
    source         : "fallback",   // ← tells popup this came from rule-based
    feats,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  HEALTH CHECK — ping Flask API every 30 seconds
//  Sets mlApiOnline = true/false so we always know if Flask is running
// ─────────────────────────────────────────────────────────────────────────────
async function checkApiHealth() {
  const now = Date.now();
  // FIX: Reduced cache from 30s → 5s so Flask starts are detected quickly
  if (now - lastHealthCheck < 5000) return;
  lastHealthCheck = now;

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    const resp  = await fetch(API_HEALTH, { signal: ctrl.signal });
    clearTimeout(timer);
    const wasOffline = !mlApiOnline;
    mlApiOnline  = resp.ok;
    mlApiChecked = true;
    if (wasOffline && mlApiOnline) {
      console.log("[WTI Shield v9] ✅ Flask ML API ONLINE — ML model active");
    }
  } catch {
    const wasOnline = mlApiOnline;
    mlApiOnline  = false;
    mlApiChecked = true;
    if (wasOnline) {
      console.warn("[WTI Shield v9] ⚠️ Flask ML API went OFFLINE — rule engine active");
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ML API CALL — sends URL to Flask, gets back ML model prediction + SHAP
//  Falls back to rule-based if Flask is offline or times out
// ─────────────────────────────────────────────────────────────────────────────
async function predictViaML(url) {
  if (shouldSkip(url)) return null;

  // Always check health first (cached for 30s)
  await checkApiHealth();

  // If offline, use fallback immediately — no waiting
  if (!mlApiOnline) {
    console.log("[WTI] Flask offline → rule-based fallback for:", url.slice(0, 60));
    return predictRuleBased(url);
  }

  // ── Call Flask API ────────────────────────────────────────────────────────
  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), API_TIMEOUT);

    const response = await fetch(API_URL, {
      method  : "POST",
      headers : { "Content-Type": "application/json" },
      body    : JSON.stringify({
        url     : url,
        traffic : {
          req_per_second   : 1,
          avg_payload_size : 300,
          unique_ips       : 1,
          error_rate       : 0,
          req_size_variance: 20,
        },
      }),
      signal: ctrl.signal,
    });

    clearTimeout(timer);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();

    // Attach source label so popup can show "ML Model" badge
    data.source = "ml_model";

    console.log(`[WTI] ML model → ${data.threat_class} (${data.risk_score}%) for`, url.slice(0, 60));
    return data;

  } catch (err) {
    // Timeout or network error — mark offline and use fallback
    mlApiOnline = false;
    console.warn("[WTI] Flask API error, switching to fallback:", err.message);
    const fallback = predictRuleBased(url);
    return fallback;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────────────────────────────────────
const tabResults = {};
const reported   = {};
const stats      = {
  scanned : 0,
  threats : { sql_injection: 0, xss: 0, phishing: 0, ddos: 0 },
  recent  : [],
  api_mode: "unknown",   // "ml_model" | "fallback" | "unknown"
};

const BADGE_COLOR = { sql_injection:"#e53935", xss:"#f57c00", phishing:"#8e24aa", ddos:"#1565c0" };
const BADGE_TEXT  = { sql_injection:"SQL",     xss:"XSS",     phishing:"⚠",       ddos:"DDoS"   };

// ─────────────────────────────────────────────────────────────────────────────
//  UI HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function setBadge(tabId, result) {
  try {
    if (!result || result.threat_class === "benign") {
      chrome.action.setBadgeText({ text: "", tabId });
    } else {
      chrome.action.setBadgeText({ text: BADGE_TEXT[result.threat_class] || "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR[result.threat_class] || "#e53935", tabId });
    }
  } catch {}
}

function openReport(result, tab) {
  if (!result || !result.is_malicious)          return;
  if (result.confidence < 0.65)                 return;
  if (reported[tab.id] === tab.url)             return;
  reported[tab.id] = tab.url;

  const q = new URLSearchParams({
    url   : tab.url,
    threat: result.threat_class,
    risk  : result.risk_score,
    conf  : result.confidence,
    rule  : result.rule_triggered || "",
    sev   : result.severity,
    source: result.source || "fallback",
  });

  // BLOCK: Replace the dangerous site tab with the warning page
  // This actually stops the user from seeing the threat site
  const warnUrl = chrome.runtime.getURL("warning/warning.html") + "?" + q.toString();
  try {
    chrome.tabs.update(tab.id, { url: warnUrl });
  } catch {
    // Fallback: open warning in new tab if update fails
    chrome.tabs.create({ url: warnUrl, index: tab.index + 1, active: true });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  TAB LISTENER — fires every time a URL changes in any tab
//  Now uses Flask ML model (with automatic fallback to rule-based)
// ─────────────────────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!changeInfo.url) return;
  const url = changeInfo.url;
  if (shouldSkip(url)) return;

  // ── Localhost / LAN detection → yellow warning page ──────────────────────
  const { local, reason } = isLocalhost(url);
  if (local) {
    // Store a benign result for popup display
    tabResults[tabId] = {
      url, threat_class:"benign", confidence:0.95, risk_score:0,
      is_malicious:false, severity:"LOCAL", rule_triggered:"localhost",
      all_probs:{benign:0.95,sql_injection:0.01,xss:0.01,phishing:0.02,ddos:0.01},
      source:"local_check", is_local:true, local_reason:reason,
    };
    // Set yellow badge
    try {
      chrome.action.setBadgeText({ text:"LOC", tabId });
      chrome.action.setBadgeBackgroundColor({ color:"#f59e0b", tabId });
    } catch {}
    // Open yellow localhost warning page (only once per URL)
    if (reported[tabId] !== url) {
      reported[tabId] = url;
      const q = new URLSearchParams({ url, reason });
      const warnUrl = chrome.runtime.getURL("localhost/localhost.html") + "?" + q;
      chrome.tabs.create({ url: warnUrl, index: (tab.index||0) + 1, active: true });
    }
    return;
  }

  // ── Get prediction from ML model (or fallback) ────────────────────────────
  const result = await predictViaML(url);
  if (!result) return;

  // ── Update state & badge ──────────────────────────────────────────────────
  tabResults[tabId]  = result;   // ✅ Store result for ALL URLs (safe + threat)
  stats.scanned++;
  stats.api_mode     = result.source || "fallback";
  setBadge(tabId, result);

  // ✅ For safe URLs — clear reported flag but KEEP result in tabResults
  if (!result.is_malicious) {
    delete reported[tabId];
    return;   // don't auto-open report for safe URLs
  }

  // ── Track threat stats ────────────────────────────────────────────────────
  stats.threats[result.threat_class] = (stats.threats[result.threat_class] || 0) + 1;
  stats.recent.unshift({
    url   : url.slice(0, 100),
    label : result.threat_class,
    conf  : result.confidence,
    risk  : result.risk_score,
    source: result.source,
    time  : Date.now(),
  });
  if (stats.recent.length > 20) stats.recent.pop();

  // ── Open threat report tab ────────────────────────────────────────────────
  openReport(result, { id: tabId, url, index: tab.index || 0 });

  // ── Browser notification ──────────────────────────────────────────────────
  const sourceLabel = result.source === "ml_model" ? "ML Model" : "Rule Engine";
  try {
    await chrome.notifications.create("wti-" + tabId + "-" + Date.now(), {
      type    : "basic",
      iconUrl : chrome.runtime.getURL("icons/icon48.png"),
      title   : `⚠️ ${result.threat_class.replace(/_/g, " ").toUpperCase()} DETECTED`,
      message : `Risk: ${result.risk_score}% · ${result.rule_triggered || sourceLabel}`,
    });
  } catch {}
});

// ── Cleanup on tab close ──────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(tabId => {
  delete tabResults[tabId];
  delete reported[tabId];
});

// ─────────────────────────────────────────────────────────────────────────────
//  MESSAGE HANDLER — popup.html talks to background via these messages
// ─────────────────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {

  // ── Popup asking for current tab's result ─────────────────────────────────
  if (msg.type === "GET_RESULT") {
    // Wrap in async IIFE — onMessage listener is NOT async so await needs a wrapper
    (async () => {
      // Force fresh health check every time popup opens
      lastHealthCheck = 0;
      await checkApiHealth();

      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab  = tabs[0];
      if (!tab || !tab.url) { reply({ result: null, stats, mlApiOnline }); return; }

      // Re-predict if no cached result
      let result = tabResults[tab.id];
      if (!result) {
        result = await predictViaML(tab.url);
        if (result) tabResults[tab.id] = result;
      }

      const fallback = {
        threat_class : "benign", confidence: 1, risk_score: 0,
        is_malicious : false, severity: "LOW", rule_triggered: null,
        all_probs    : { benign:1, sql_injection:0, xss:0, phishing:0, ddos:0 },
        source       : "fallback",
      };

      reply({ result: result || fallback, url: tab.url, stats, mlApiOnline });
    })();
    return true;   // keep channel open for async reply
  }

  // ── Popup manually scanning a custom URL ─────────────────────────────────
  if (msg.type === "SCAN_URL") {
    (async () => {
      const result = await predictViaML(msg.url) || {
        threat_class : "benign", confidence: 1, risk_score: 0,
        is_malicious : false, severity: "LOW", rule_triggered: null,
        all_probs    : { benign:1, sql_injection:0, xss:0, phishing:0, ddos:0 },
        source       : "fallback",
      };
      reply({ result, mlApiOnline });
    })();
    return true;   // keep channel open for async reply
  }

  // ── Popup asking if ML API is online ─────────────────────────────────────
  if (msg.type === "CHECK_API") {
    checkApiHealth().then(() => reply({ mlApiOnline, mlApiChecked }));
    return true;
  }

  // ── Warning page: open the full report in a new tab ──────────────────────
  // Look up the full cached ML result so report shows ML data not rule defaults
  if (msg.type === "OPEN_REPORT") {
    const targetUrl = msg.url || "";
    // Find cached result for this URL across all tabs
    let cachedResult = null;
    for (const [tabId, res] of Object.entries(tabResults)) {
      if (res && res.url === targetUrl) { cachedResult = res; break; }
    }
    const r = cachedResult || {};
    const q = new URLSearchParams({
      url   : targetUrl,
      threat: r.threat_class || msg.threat || "phishing",
      risk  : r.risk_score   || msg.risk   || 85,
      conf  : r.confidence   || msg.conf   || 0.85,
      rule  : r.rule_triggered || "",
      sev   : r.severity     || "HIGH",
      source: r.source       || "rule_engine",
      probs : JSON.stringify(r.all_probs || {}),
    });
    const rUrl = chrome.runtime.getURL("report/report.html") + "?" + q.toString();
    chrome.tabs.create({ url: rUrl, active: true });
    reply({});
    return true;
  }

  // ── Localhost proceed: navigate original tab to the local URL ─────────────
  // Called when user clicks Proceed on the yellow localhost warning page.
  // We find the tab that originally triggered the warning and navigate it.
  if (msg.type === "LOCALHOST_PROCEED") {
    const targetUrl = msg.url;
    if (!targetUrl) { reply({}); return; }

    // Find the tab that opened this warning (the one before the warning tab)
    // The sender tab is the localhost.html warning page itself
    const warningTabId = sender?.tab?.id;

    chrome.tabs.query({}, function(allTabs) {
      // Find the most recent tab with a localhost URL (not the warning page itself)
      let originalTab = null;
      for (const tab of allTabs) {
        if (tab.id === warningTabId) continue;            // skip warning tab
        if (!tab.url) continue;
        // Check if this tab has a localhost/local URL
        try {
          const h = new URL(tab.url).hostname;
          const isLocal = ["localhost","127.0.0.1","::1"].includes(h) ||
            h.startsWith("192.168.") || h.startsWith("10.") ||
            h.endsWith(".local") || h.endsWith(".test");
          if (isLocal) { originalTab = tab; break; }
        } catch {}
      }

      if (originalTab) {
        // Navigate the original local tab to the target URL
        chrome.tabs.update(originalTab.id, { url: targetUrl, active: true });
      } else {
        // No original local tab found — create a new tab
        chrome.tabs.create({ url: targetUrl, active: true });
      }
      reply({});
    });
    return true; // async
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  STARTUP — check Flask health immediately on extension load
// ─────────────────────────────────────────────────────────────────────────────
checkApiHealth().then(() => {
  console.log(`[WTI Shield v5] Ready. Flask API: ${mlApiOnline ? "✅ ONLINE" : "⚠️ OFFLINE (fallback active)"}`);
});

// Re-check Flask health every 30 seconds automatically
setInterval(checkApiHealth, 10000);   // FIX: check every 10s, not 30s

console.log("[WTI Shield v5] Background service worker loaded");
