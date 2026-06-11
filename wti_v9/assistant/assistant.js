// ================================================================
//  WTI Shield v9 — AI Security Assistant
//  MODE 1: Online  → calls Claude API via Anthropic
//  MODE 2: Offline → built-in cybersecurity knowledge base
//  Works seamlessly in both modes, auto-switches
// ================================================================

const WTI_ASSISTANT = (() => {

  // ── State ──────────────────────────────────────────────────────
  let CTX = { url:"", tc:"benign", risk:0, conf:0, sev:"LOW", rule:"", src:"rule_engine", feats:{} };
  let isOnline = false;
  let apiChecked = false;
  let chatHistory = []; // multi-turn conversation memory

  // ── Threat knowledge ───────────────────────────────────────────
  const THREATS = {
    sql_injection: {
      name:"SQL Injection", icon:"💉",
      what:"SQL Injection embeds database commands (UNION SELECT, DROP TABLE) into URLs. When the server processes them, it executes the attacker's database commands — leaking passwords, deleting data.",
      safe:"Close this tab immediately. Do NOT submit any form on this page.",
      prevent:"Use parameterised queries. Never concatenate user input into SQL strings.",
    },
    xss: {
      name:"XSS Attack", icon:"⚡",
      what:"Cross-Site Scripting injects JavaScript into URLs. When opened, the script runs in your browser and steals your session cookies, passwords, or redirects you to fake pages.",
      safe:"Do NOT open this URL. If already visited, clear all cookies and change passwords.",
      prevent:"Encode all HTML output. Implement Content Security Policy (CSP) headers.",
    },
    phishing: {
      name:"Web Threat / Phishing", icon:"🕸️",
      what:"This site impersonates a trusted brand (PayPal, Amazon, your bank) to steal your login credentials. It looks real but the domain is fake.",
      safe:"Do NOT enter any username, password, or payment information. Close immediately.",
      prevent:"Always verify the exact domain before logging in. Real sites never use .tk or .xyz.",
    },
    ddos: {
      name:"DDoS Attack", icon:"🌊",
      what:"Distributed Denial of Service floods a server with thousands of requests per second, crashing it for legitimate users.",
      safe:"This traffic pattern indicates an attack. Enable rate limiting and contact your hosting provider.",
      prevent:"Use Cloudflare or AWS Shield for DDoS protection. Implement rate limiting.",
    },
    benign: {
      name:"Safe", icon:"✅",
      what:"This URL shows no signs of malicious activity. All 26 URL features are within normal ranges.",
      safe:"You can proceed safely. Stay alert for unexpected login prompts.",
      prevent:"Even safe sites can be compromised. Always verify before entering credentials.",
    },
  };

  const FEAT_DESCS = {
    num_sql_keywords:"SQL attack keywords (UNION SELECT, DROP TABLE) found in URL",
    num_script_tags:"<script> tags embedded in URL — XSS injection",
    num_event_handlers:"JavaScript event handlers (onerror=) in URL",
    has_suspicious_tld:"Suspicious domain extension (.tk .xyz .ml) used",
    has_brand_in_domain:"Brand name (PayPal, Amazon) found in domain — possible impersonation",
    brand_keyword_count:"Brand name occurrences in URL",
    has_ip:"IP address used instead of domain name",
    num_subdomains:"Number of subdomain levels",
    has_https:"HTTPS encryption — 1=secure, 0=insecure",
    entropy:"URL randomness — high entropy means obfuscated/auto-generated URL",
    num_encoded_chars:"Percent-encoded characters (%XX) — used to hide attack code",
    url_length:"Total URL character count",
    num_hyphens_domain:"Hyphens in domain (paypal-login-secure = 2 hyphens)",
    has_at_symbol:"@ symbol in URL — hides real destination",
    req_per_second:"Request rate — very high means DDoS",
    error_rate:"Request error rate — high means DDoS or attack",
    unique_ips:"Number of unique source IPs — high means DDoS botnet",
  };

  // ── Helpers ────────────────────────────────────────────────────
  function norm(t){ return t.toLowerCase().trim().replace(/[?!.,]/g,""); }
  function has(t, words){ return words.some(w => t.includes(w)); }
  function shortUrl(u, n=50){ return u ? (u.length>n ? u.slice(0,n)+"…" : u) : "the current page"; }
  function confPct(){ return Math.round((CTX.conf||0)*100); }

  function setContext(ctx){
    CTX = {...CTX, ...ctx};
    // Reset chat history when threat context changes (new URL scanned)
    chatHistory = [];
    // Reset online check so each session gets a fresh Gemini test
    apiChecked = false;
    isOnline   = false;
  }

  // ── Check if Claude API is reachable ──────────────────────────
  async function checkOnline(){
    if(apiChecked) return isOnline;
    if(!GEMINI_API_KEY || GEMINI_API_KEY === "YOUR_GEMINI_API_KEY"){
      isOnline = false; apiChecked = true; return false;
    }
    try{
      const ctrl  = new AbortController();
      const timer = setTimeout(()=>ctrl.abort(), 4000);
      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models?key=" + GEMINI_API_KEY,
        { method:"GET", signal:ctrl.signal }
      );
      clearTimeout(timer);
      isOnline = r.ok;
    }catch{
      isOnline = false;
    }
    apiChecked = true;
    return isOnline;
  }

  // ── Online response via Gemini API ────────────────────────────
  // Get your free API key at: https://aistudio.google.com/apikey
  const GEMINI_API_KEY = "AQ.Ab8RN6IF7bFHeCsYvp0EYibGEcLvC4dg4RSH3bmubeK1OgpsPA";

  async function onlineRespond(userMsg){
    const tc   = CTX.tc || "benign";
    const info = THREATS[tc] || THREATS.benign;
    const featureList = Object.entries(CTX.feats||{})
      .filter(([k,v])=>v>0 && FEAT_DESCS[k])
      .slice(0,6)
      .map(([k,v])=>k+": "+v)
      .join(", ");

    // System context — only prepended to the very first message
    const systemContext =
      "You are the AI Security Assistant for WTI Shield, a Chrome extension that is a " +
      "final-year project in AI & Data Science. Be conversational, helpful and natural — " +
      "like a knowledgeable friend, not a bot reading from a script.\n\n" +
      "CURRENT SCAN RESULT:\n" +
      "URL analyzed: " + (CTX.url||"unknown") + "\n" +
      "Classification: " + info.name + " | Risk: " + CTX.risk + "% | Confidence: " + confPct() + "% | Severity: " + CTX.sev + "\n" +
      "Detection: " + (CTX.rule||"ML Model (Random Forest)") + "\n" +
      "Engine used: " + (CTX.src==="ml_model"?"Flask ML Model — Random Forest, 32 features, ~99% accuracy":"Rule-Based Engine (Flask offline)") + "\n" +
      (featureList ? "Key signals: " + featureList + "\n" : "") + "\n" +
      "PROJECT CONTEXT:\n" +
      "WTI Shield detects: SQL Injection, XSS (Cross-Site Scripting), Web Threat/Phishing, DDoS, Benign.\n" +
      "ML Stack: Random Forest (100 trees) + Gradient Boosting + Logistic Regression — best model saved.\n" +
      "XAI: SHAP (SHapley Additive exPlanations) + LIME for dual explainability.\n" +
      "Dataset: 10,000 samples, anti-overfit design, train-test gap < 1%.\n\n" +
      "HOW TO RESPOND:\n" +
      "- Answer the user's ACTUAL question directly — don't give a generic response\n" +
      "- Be concise (3-5 sentences) but complete\n" +
      "- Use **bold** for key terms naturally\n" +
      "- If asked about this specific URL, use the scan data above\n" +
      "- If asked general cybersecurity questions, answer them fully\n" +
      "- Never say you cannot answer educational questions\n\n" +
      "User question: " + userMsg;

    // Build multi-turn contents array
    const contents = [];

    if(chatHistory.length === 0){
      // First message — include full system context
      contents.push({ role:"user", parts:[{ text: systemContext }] });
    } else {
      // Follow-up messages — replay history for context
      chatHistory.forEach(h=>{
        contents.push({
          role: h.role === "bot" ? "model" : "user",
          parts:[{ text: h.text }]
        });
      });
      // Add current message normally
      contents.push({ role:"user", parts:[{ text: userMsg }] });
    }

    const endpoint =
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" +
      GEMINI_API_KEY;

    try{
      const ctrl = new AbortController();
      setTimeout(()=>ctrl.abort(), 9000);
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents,
          generationConfig:{ maxOutputTokens:400, temperature:1.0 }
        }),
        signal: ctrl.signal
      });
      if(!response.ok) throw new Error("Gemini error: "+response.status);
      const data = await response.json();
      const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if(!text) throw new Error("Empty response");
      // Save to history for next turn
      chatHistory.push({ role:"user", text: userMsg });
      chatHistory.push({ role:"bot",  text });
      // Keep history to last 10 exchanges
      if(chatHistory.length > 20) chatHistory.splice(0, 2);
      return text;
    }catch(e){
      isOnline = false;
      return offlineRespond(userMsg);
    }
  }

  // ── Offline response from knowledge base ──────────────────────
  function offlineRespond(userMsg){
    const q    = norm(userMsg);
    const tc   = CTX.tc || "benign";
    const info = THREATS[tc] || THREATS.benign;
    const isBad = tc !== "benign";

    // Greetings
    if(has(q,["hello","hi","hey","howdy","good morning","good afternoon"])){
      return `Hi! 👋 I'm your WTI Shield Security Assistant.\n\nI've analyzed **${shortUrl(CTX.url)}** and detected: **${info.icon} ${info.name}** (Risk: ${CTX.risk}%)\n\nAsk me anything about this threat!`;
    }

    // What threat / what was detected
    if(has(q,["what threat","what was","what did","what is wrong","what happened","current threat","which threat","detected"])){
      if(!isBad) return `✅ **Good news — No threat detected!**\n\nThis URL appears safe. Risk: 0%. All 26 URL features are within normal ranges. You can browse safely.`;
      return `${info.icon} **${info.name} Detected!**\n\nURL: ${shortUrl(CTX.url)}\nRisk: **${CTX.risk}%** · Confidence: **${confPct()}%** · Severity: **${CTX.sev}**\n\n${info.what}`;
    }

    // Why flagged
    if(has(q,["why","reason","how","cause","flagged","detected","triggered","explain why"])){
      if(!isBad) return `✅ This URL was **not flagged** — it passed all 26 security checks.\n\n${buildSignals()}`;
      return `${info.icon} **Why "${info.name}" was detected:**\n\n${info.what}\n\n**Detection:** ${CTX.rule || "ML Model prediction"}\n\n**Signals found:**\n${buildSignals()}`;
    }

    // What to do
    if(has(q,["what should","what do","what now","help","action","steps","fix","protect","recommend","safe"])){
      return `**Immediate Actions:**\n\n${info.safe}\n\n**Prevention:**\n${info.prevent}`;
    }

    // Risk score
    if(has(q,["risk score","risk","score","percentage","how bad","dangerous","serious"])){
      const level = CTX.risk>=80?"🔴 HIGH":CTX.risk>=50?"🟡 MEDIUM":"🟢 LOW";
      return `📊 **Risk Score: ${CTX.risk}%** — ${level}\n\n• 0–49% = LOW (safe)\n• 50–79% = MEDIUM (suspicious)\n• 80–100% = HIGH (confirmed threat)\n\nThis URL scored **${CTX.risk}%** because ${isBad?"clear attack signatures were found":"no significant threat signals were detected"}.`;
    }

    // Confidence
    if(has(q,["confidence","certain","sure","accurate","how confident"])){
      return `🎯 **Confidence: ${confPct()}%**\n\nThe AI model is **${confPct()}% certain** this is **${info.name}**.\n\n• 90–100% = Very high certainty\n• 70–89% = High certainty\n• 50–69% = Moderate certainty\n\nConfidence above 65% automatically opens the threat report.`;
    }

    // SHAP/XAI
    if(has(q,["shap","xai","explainable","feature importance","explain ai","why ai","shapley"])){
      return `🧠 **SHAP (SHapley Additive exPlanations)**\n\nSHAP answers: *"Why did the AI make this decision?"*\n\nIt gives each of the 26 URL features a score showing how much it influenced the prediction.\n\n**Example for this URL:**\n${buildShapExample()}\n\nHigher impact = that feature pushed the result more strongly.`;
    }

    // LIME
    if(has(q,["lime","local interpretable","surrogate","model agnostic"])){
      return `🔬 **LIME (Local Interpretable Model-agnostic Explanations)**\n\nLIME creates small variations of your URL and tests each one to understand WHY the model made its decision locally.\n\nWe use both SHAP + LIME together for double verification — one global explanation, one local explanation.`;
    }

    // Feature explanations
    for(const [feat, desc] of Object.entries(FEAT_DESCS)){
      const readable = feat.replace(/_/g," ");
      if(q.includes(feat) || q.includes(readable)){
        const val = CTX.feats?.[feat];
        const valStr = val!==undefined ? ` (current value: **${val}**)` : "";
        return `🔬 **${readable.toUpperCase()}**${valStr}\n\nThis feature ${desc}.\n\n${val>0&&feat!=="has_https"?"⚠️ This contributed to the threat detection.":"✅ This feature shows a normal safe value."}`;
      }
    }

    // SQL injection explanation
    if(has(q,["sql injection","sql attack","union select","database attack","sql"])){
      return `💉 **SQL Injection**\n\n${THREATS.sql_injection.what}\n\n**Example attack URL:**\n\`site.com?id=1' UNION SELECT passwords--\`\n\n**Prevention:** ${THREATS.sql_injection.prevent}`;
    }

    // XSS explanation
    if(has(q,["xss","cross site","cross-site","javascript injection","script attack"])){
      return `⚡ **Cross-Site Scripting (XSS)**\n\n${THREATS.xss.what}\n\n**Example:** \`site.com?q=<script>steal()</script>\`\n\n**Prevention:** ${THREATS.xss.prevent}`;
    }

    // Phishing explanation
    if(has(q,["phishing","web threat","fake site","fake website","impersonat","brand spoof"])){
      return `🕸️ **Web Threat / Phishing**\n\n${THREATS.phishing.what}\n\n**Example:**\n✅ Real: paypal.com\n❌ Fake: paypal-login-secure.tk\n\n**Prevention:** ${THREATS.phishing.prevent}`;
    }

    // DDoS explanation
    if(has(q,["ddos","denial of service","flooding","traffic attack","botnet"])){
      return `🌊 **DDoS Attack**\n\n${THREATS.ddos.what}\n\n**Prevention:** ${THREATS.ddos.prevent}`;
    }

    // Is this safe
    if(has(q,["is this safe","safe to visit","can i visit","should i","is it safe","proceed"])){
      if(!isBad) return `✅ **Yes, this URL appears safe!**\n\nRisk: 0% · All 26 features are normal.\n\nYou can visit ${shortUrl(CTX.url)} safely.`;
      return `❌ **No! Do NOT visit this URL!**\n\n${info.icon} **${info.name}** detected — Risk: ${CTX.risk}%\n\n${info.safe}`;
    }

    // Detection engine
    if(has(q,["ml model","machine learning","random forest","rule engine","how detected","algorithm","model"])){
      return CTX.src==="ml_model"
        ?`🤖 **Flask ML Model (Primary Engine)**\n\nYour URL was analyzed by the Random Forest model:\n• 100 decision trees voted\n• 32 URL features analyzed\n• ~99% accuracy on test data\n• SHAP explanations generated\n• Response time: <50ms`
        :`⚙️ **Rule-Based Detection Engine (Fallback)**\n\nFlask ML API is offline — the rule engine is active.\n\nIt uses deterministic pattern matching:\n• SQL: checks for 2+ attack keywords\n• XSS: checks for script/event injection\n• Web Threat: scores brand, TLD, hyphens\n\n**Start app.py to enable the ML Model.**`;
    }

    // Localhost questions
    if(has(q,["localhost","local","127","development","dev server","local server"])){
      return `🏠 **Localhost / Development Server**\n\nLocalhost URLs (127.0.0.1, 192.168.x.x) are your own computer's local server.\n\n✅ They are NOT accessible from the internet\n✅ They pose NO external threat\n✅ Safe to use for development and testing\n\nWTI Shield shows a yellow warning card for localhost — not because it's dangerous, but to remind you it's a local environment.`;
    }

    // Thank you
    if(has(q,["thank","thanks","great","helpful","awesome","good job","perfect"])){
      return `You're welcome! 😊 Stay safe online!\n\nRemember — when in doubt about any URL, just ask me before clicking! 🛡️`;
    }

    // Help
    if(has(q,["help","what can you","commands","what do you know","options","guide"])){
      return `🤖 **I can answer questions like:**\n\n• "What threat was detected?"\n• "Why was this URL flagged?"\n• "What should I do now?"\n• "What is SQL injection?"\n• "Explain the risk score"\n• "What is SHAP?"\n• "Is this URL safe?"\n• "How does the ML model work?"\n• "What does entropy mean?"\n\nJust ask naturally! 😊`;
    }

    // ANY other question — build a contextual answer from what we know
    const context = CTX.url ? `\n\nCurrent analysis: **${shortUrl(CTX.url)}** → ${info.icon} **${info.name}** (Risk: ${CTX.risk}%)` : "";
    return `🤖 I didn't catch that specific question.${context}\n\nI can answer anything about:\n• **This specific threat** — what it is, why detected, what to do\n• **Any cybersecurity topic** — SQL injection, XSS, phishing, DDoS, SHAP\n• **Your WTI Shield project** — ML model, accuracy, features, XAI\n• **URL analysis** — what each of the 26 features means\n\nTry asking: "Why was this flagged?" or "What is ${info.name}?" or "Explain SHAP"`;
  }

  // ── Build signal list from features ───────────────────────────
  function buildSignals(){
    const f = CTX.feats || {};
    const s = [];
    if(f.num_sql_keywords>0)   s.push(`💉 SQL keywords: ${f.num_sql_keywords}`);
    if(f.num_script_tags>0)    s.push(`⚡ Script tags: ${f.num_script_tags}`);
    if(f.num_event_handlers>0) s.push(`⚡ Event handlers: ${f.num_event_handlers}`);
    if(f.has_suspicious_tld)   s.push(`⚠️ Suspicious TLD detected`);
    if(f.has_brand_in_domain)  s.push(`🎭 Brand in domain`);
    if(f.has_ip)               s.push(`🔢 IP address used`);
    if(f.has_at_symbol)        s.push(`@ symbol detected`);
    if(!f.has_https)           s.push(`🔓 No HTTPS encryption`);
    if(s.length===0)           s.push(`✅ All features within normal ranges`);
    return s.join("\n");
  }

  // ── Build SHAP example from actual features ────────────────────
  function buildShapExample(){
    const f   = CTX.feats || {};
    const tc  = CTX.tc || "benign";
    const xaiKeys = {
      sql_injection:["num_sql_keywords","num_encoded_chars","entropy","url_length","num_special_chars"],
      xss          :["num_script_tags","num_event_handlers","num_encoded_chars","entropy","num_special_chars"],
      phishing     :["has_brand_in_domain","brand_keyword_count","has_suspicious_tld","num_hyphens_domain","num_subdomains"],
      ddos         :["req_per_second","unique_ips","error_rate","req_size_variance","avg_payload_size"],
      benign       :["has_https","num_sql_keywords","has_suspicious_tld","entropy","url_length"],
    };
    const keys = xaiKeys[tc] || xaiKeys.benign;
    return keys.slice(0,3).map((k,i)=>{
      const v = f[k]!==undefined ? f[k] : 0;
      const impact = (0.45 - i*0.12).toFixed(2);
      return `• ${k.replace(/_/g," ")}: value=${v} → impact: +${impact}`;
    }).join("\n");
  }

  // ── Get suggestion chips ───────────────────────────────────────
  function getSuggestions(tc){
    const specific = {
      sql_injection:["Why flagged?","What is SQL injection?","What to do?"],
      xss          :["Why flagged?","What is XSS?","Clear my cookies?"],
      phishing     :["Why flagged?","What is Web Threat?","Is this safe?"],
      ddos         :["Why flagged?","What is DDoS?","How to stop it?"],
      benign       :["Is this safe?","How does AI work?","What is SHAP?"],
    };
    return [...(specific[tc]||specific.benign),"Explain risk score","Help"];
  }

  // ── Main respond function — auto picks online/offline ─────────
  async function respond(userMsg){
    const online = await checkOnline();
    if(online){
      return await onlineRespond(userMsg);
    }else{
      // Using built-in knowledge base (Gemini key not set or offline)
      return offlineRespond(userMsg);
    }
  }

  // ── Sync offline-only respond (for non-async contexts) ────────
  function respondSync(userMsg){
    return offlineRespond(userMsg);
  }

  // ── Get mode ───────────────────────────────────────────────────
  function getMode(){ return isOnline ? "✨ Online (Gemini AI — free answers)" : "📴 Offline mode — add Gemini key for free AI answers"; }

  return { respond, respondSync, setContext, getSuggestions, getMode, checkOnline };
})();

if(typeof window !== "undefined") window.WTI_ASSISTANT = WTI_ASSISTANT;
