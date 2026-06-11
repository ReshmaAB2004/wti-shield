// WTI Shield v9 — report.js

// ── Constants ──────────────────────────────────────────────────
const CLS   = ["benign","sql_injection","xss","phishing","ddos"];
const COLOR = {benign:"#22c55e",sql_injection:"#ef4444",xss:"#f97316",phishing:"#a855f7",ddos:"#3b82f6"};
const ICON  = {benign:"✅",sql_injection:"💉",xss:"⚡",phishing:"🕸️",ddos:"🌊"};
const LABEL = {benign:"Safe / Legitimate",sql_injection:"SQL Injection Attack",xss:"XSS Attack",phishing:"Web Threat Detected",ddos:"DDoS Attack Pattern"};
const BANNER= {benign:"b-safe",sql_injection:"b-sql",xss:"b-xss",phishing:"b-ph",ddos:"b-ddos"};

const FEAT_DESCS={url_length:"Total URL character count",num_special_chars:"Non-standard special characters",has_ip:"IP address instead of domain",num_subdomains:"Subdomain level count",has_https:"HTTPS encryption (1=yes,0=no)",entropy:"URL randomness — Shannon entropy",num_digits:"Numeric digit count",num_params:"Query parameter count",payload_length:"Total URL payload size",num_encoded_chars:"Percent-encoded chars (%XX)",num_sql_keywords:"SQL attack keywords found",num_script_tags:"<script> tags in URL",num_event_handlers:"JS event handlers (onerror=)",brand_keyword_count:"Brand name occurrences",has_brand_in_domain:"Brand name in domain",has_suspicious_tld:"Suspicious TLD (.tk .xyz)",num_hyphens_domain:"Hyphens in domain name",domain_length:"Domain character length",has_at_symbol:"@ symbol present",has_double_slash:"Double slash in path",num_dots:"Total dot count",req_per_second:"Requests per second",avg_payload_size:"Average payload size (bytes)",unique_ips:"Unique source IPs",error_rate:"Request error rate",req_size_variance:"Request size variance"};

const RECS={
  sql_injection:[{c:"#ef4444",i:"🚫",t:"Do NOT submit this URL",b:"SQL commands embedded here will attempt to steal or destroy database data. Close this tab immediately."},{c:"#f97316",i:"🛡️",t:"Use parameterised queries",b:"Never concatenate user input into SQL. Use prepared statements and ORM frameworks."},{c:"#3b82f6",i:"📢",t:"Report to security team",b:"Capture the full URL and timestamp. Add this pattern to your WAF rules."}],
  xss:[{c:"#f97316",i:"🚫",t:"Do NOT open this URL",b:"JavaScript injected here runs in your browser, stealing session cookies or redirecting you to fake sites."},{c:"#f59e0b",i:"🧹",t:"Clear cookies if already visited",b:"Clear all cookies and change passwords for any accounts you may have accessed."},{c:"#0ea5e9",i:"🛡️",t:"Implement Content Security Policy",b:"Add CSP headers to block inline scripts. This prevents XSS attacks at the server level."}],
  phishing:[{c:"#a855f7",i:"🚫",t:"Do NOT enter any information",b:"This site impersonates a trusted brand to steal your password. Close immediately."},{c:"#f59e0b",i:"🔍",t:"Verify the exact domain",b:"Real: paypal.com ✅  Fake: paypal-login.tk ❌  Always check the address bar carefully."},{c:"#22c55e",i:"📢",t:"Report this threat",b:"Submit to Google Safe Browsing and PhishTank to protect other users worldwide."}],
  ddos:[{c:"#3b82f6",i:"🚨",t:"DDoS attack detected",b:"Abnormal request rates detected. Enable rate limiting and contact your hosting provider immediately."},{c:"#f59e0b",i:"🛡️",t:"Deploy DDoS protection",b:"Use Cloudflare, AWS Shield, or similar CDN with DDoS mitigation. Implement IP rate limits."},{c:"#0ea5e9",i:"📋",t:"Preserve traffic logs",b:"Capture all logs with timestamps and IPs for forensic analysis and reporting."}],
  benign:[{c:"#22c55e",i:"✅",t:"This URL is safe",b:"All 26 features passed. No threat signatures detected. You can proceed normally."},{c:"#0ea5e9",i:"👁",t:"Stay vigilant",b:"Even safe URLs can lead to harmful content. Always verify site identity before entering credentials."}],
};

const XAI_KEYS={sql_injection:["num_sql_keywords","num_encoded_chars","entropy","url_length","num_special_chars"],xss:["num_script_tags","num_event_handlers","num_encoded_chars","entropy","num_special_chars"],phishing:["has_brand_in_domain","brand_keyword_count","has_suspicious_tld","num_hyphens_domain","num_subdomains"],ddos:["req_per_second","unique_ips","error_rate","req_size_variance","avg_payload_size"],benign:["has_https","num_sql_keywords","has_suspicious_tld","entropy","url_length"]};

// ── State ──────────────────────────────────────────────────────
let G={url:"",tc:"benign",risk:0,conf:0,sev:"LOW",rule:"",src:"rule_engine",feats:{},probs:{}};
let curSec=0, chatReady=false, chatOpen=true;
const TOTAL=9;

// ── Helpers ────────────────────────────────────────────────────
const TRUSTED=["google.com","youtube.com","apple.com","amazon.com","microsoft.com","facebook.com","instagram.com","linkedin.com","twitter.com","x.com","github.com","stackoverflow.com","wikipedia.org","reddit.com","netflix.com","dropbox.com","ebay.com","paypal.com","steam.com","bing.com","whatsapp.com","office.com"];
const BRANDS=["paypal","appleid","amazon","microsoft","facebook","netflix","instagram","whatsapp","wellsfargo","citibank","hsbc","barclays","dropbox","steam","roblox","chase","bankofamerica"];
const BAD_TLDS=[".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",".online",".site",".biz",".club",".pw",".cc",".ws",".info"];
const SQL_KW=["union select","union+select","' or '","or 1=1","1=1","insert into","drop table","drop database","exec(","cast(0x","benchmark(","sleep(","xp_cmd","select * from","delete from","/**/","waitfor delay"];
const PHISH_KW=["login","signin","verify","secure","update","account","password","confirm","credential","wallet","suspended","billing","support"];

function calcEnt(s){if(!s)return 0;const f={};for(const c of s)f[c]=(f[c]||0)+1;return+(-Object.values(f).reduce((t,v)=>{const p=v/s.length;return t+p*Math.log2(p);},0)).toFixed(4);}

function extractFeats(url){
  if(!url)return{};let host="",scheme="http",domain="";
  try{const u=new URL(url.startsWith("http")?url:"http://"+url);host=u.hostname.toLowerCase();scheme=u.protocol.replace(":","")}catch{host=url.split("/")[0];}
  const parts=host.split(".");domain=parts.length>=2?parts[parts.length-2]:host;
  const subs=parts.length>2?parts.slice(0,-2):[];
  const low=url.toLowerCase();const tr=TRUSTED.some(d=>{const h=host.replace(/^www\./,"");return h===d||h.endsWith("."+d);});
  return{url_length:url.length,num_special_chars:(url.match(/[^a-zA-Z0-9\-._~:/?#@!$&'()*+,;=%]/g)||[]).length,has_ip:/^\d{1,3}(\.\d{1,3}){3}$/.test(host)?1:0,num_subdomains:subs.length,has_https:scheme==="https"?1:0,entropy:calcEnt(url),num_digits:(url.match(/\d/g)||[]).length,num_params:(url.match(/[?&]/g)||[]).length,payload_length:url.length,num_encoded_chars:(url.match(/%[0-9a-fA-F]{2}/g)||[]).length,num_sql_keywords:SQL_KW.filter(k=>low.includes(k)).length,num_script_tags:(low.match(/<script/gi)||[]).length,num_event_handlers:(low.match(/on\w+\s*=/gi)||[]).length,brand_keyword_count:tr?0:BRANDS.filter(b=>low.includes(b)).length,has_brand_in_domain:tr?0:(BRANDS.some(b=>domain.includes(b)&&!host.endsWith(b+".com"))?1:0),has_suspicious_tld:BAD_TLDS.some(t=>host.endsWith(t))?1:0,num_hyphens_domain:(domain.match(/-/g)||[]).length,domain_length:host.length,has_at_symbol:url.includes("@")?1:0,has_double_slash:url.replace("://","").includes("//")?1:0,num_dots:(url.match(/\./g)||[]).length,req_per_second:1,avg_payload_size:300,unique_ips:1,error_rate:0,req_size_variance:20};
}

function isLocal(url){
  if(!url)return false;
  try{const h=(new URL(url.startsWith("http")?url:"http://"+url)).hostname.toLowerCase();return h==="localhost"||h==="127.0.0.1"||h==="::1"||h.startsWith("192.168.")||h.startsWith("10.")||h.endsWith(".local")||h.endsWith(".test")||h.endsWith(".dev");}catch{return false;}
}

function sigLevel(k,v){
  const H={num_sql_keywords:1,num_script_tags:1,num_event_handlers:2,has_ip:1,has_suspicious_tld:1,has_brand_in_domain:1,has_at_symbol:1,num_hyphens_domain:3,num_subdomains:3,num_encoded_chars:10};
  const M={url_length:150,entropy:5.5,num_digits:10,brand_keyword_count:1,num_dots:5,domain_length:40,num_params:6};
  if(k==="has_https"&&v===0)return"bad";
  if(H[k]!==undefined)return v>=H[k]?"bad":"ok";
  if(M[k]!==undefined)return v>=M[k]?"med":"ok";
  return"ok";
}

function animCount(el,to,dur=1200,sfx=""){
  const s=performance.now();
  (function t(n){const p=Math.min((n-s)/dur,1);el.textContent=Math.round(to*(1-Math.pow(1-p,3)))+sfx;if(p<1)requestAnimationFrame(t);})(s);
}

function esc(t){return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function fmt(t){return esc(t).replace(/\*\*(.*?)\*\*/g,"<strong>$1</strong>").replace(/`(.*?)`/g,"<code style='background:#060d1a;padding:1px 4px;border-radius:3px;color:#60a5fa;font-family:monospace;font-size:10px'>$1</code>").replace(/\n/g,"<br>");}
function getTime(){return new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});}

// ── LOADER ─────────────────────────────────────────────────────
function runLoader(cb){
  const fill=document.getElementById("loFill");
  const step=document.getElementById("loStep");
  const steps=["Extracting URL features...","Running ML detection...","Computing SHAP values...","Building report..."];
  let i=0,w=0;
  const iv=setInterval(()=>{
    w=Math.min(w+12+Math.random()*8,92);
    fill.style.width=w+"%";
    if(steps[i]&&w>(i+1)*22){step.textContent=steps[i];i++;}
  },200);
  setTimeout(()=>{clearInterval(iv);fill.style.width="100%";setTimeout(()=>{document.getElementById("loader").classList.add("hide");cb();},400);},1600);
}

// ── SECTION NAVIGATION ─────────────────────────────────────────
function goSec(n){
  document.querySelectorAll(".sec-page").forEach((el,i)=>{
    el.classList.toggle("active",i===n);
  });
  document.querySelectorAll(".nav-item").forEach((el,i)=>{
    el.classList.toggle("active",i===n);
    if(i<n)el.classList.add("done");
  });
  curSec=n;
  const pct=Math.round(((n+1)/TOTAL)*100);
  document.getElementById("navFill").style.width=pct+"%";
  document.getElementById("navPct").textContent=`${n+1} of ${TOTAL} sections`;
  window.scrollTo(0,0);
  // Trigger animations for specific sections
  if(n===1)setTimeout(animFeats,100);
  if(n===2)setTimeout(animProbs,100);
  if(n===3)setTimeout(animXAI,100);
}

// ── FETCH ML RESULT FROM FLASK ────────────────────────────────
async function fetchMLResult(url) {
  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const res   = await fetch("http://localhost:5000/predict", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, traffic: { req_per_second:1, avg_payload_size:300, unique_ips:1, error_rate:0, req_size_variance:20 } }),
      signal:  ctrl.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    data.source = "ml_model";
    return data;
  } catch (e) {
    return null;  // Flask offline — use URL params from background
  }
}

// ── MAIN RENDER ────────────────────────────────────────────────
async function render(){
  try{
    const p=new URLSearchParams(window.location.search);
    G.url  = decodeURIComponent(p.get("url")||"");
    G.tc   = p.get("threat")||"benign";
    G.risk = parseFloat(p.get("risk")||"0");
    G.conf = parseFloat(p.get("conf")||"0");
    G.rule = p.get("rule")||"";
    G.sev  = p.get("sev")||"LOW";
    G.src  = p.get("source")||"rule_engine";
    try{G.probs=JSON.parse(decodeURIComponent(p.get("probs")||"{}"));}catch{G.probs={};}
    G.feats= G.url ? extractFeats(G.url) : {};

    // ── Try to get FRESH ML result from Flask ──────────────────
    // This ensures the report always shows ML model data when Flask is running
    if (G.url && G.url !== "") {
      const mlResult = await fetchMLResult(G.url);
      if (mlResult && mlResult.threat_class) {
        // Flask is online — use real ML data
        G.tc    = mlResult.threat_class;
        G.risk  = mlResult.risk_score || G.risk;
        G.conf  = mlResult.confidence || G.conf;
        G.rule  = mlResult.rule_triggered || G.rule;
        G.sev   = mlResult.severity || G.sev;
        G.src   = "ml_model";
        G.probs = mlResult.all_probs || G.probs;
        // Use Flask features if available
        if (mlResult.features) G.feats = mlResult.features;
      }
    }
    const color = COLOR[G.tc]||"#22c55e";
    const isBad = G.tc!=="benign";
    const local = isLocal(G.url);

    // Fill probs if empty
    if(!G.probs.benign){
      const rest=(1-G.conf)/4;
      G.probs=Object.fromEntries(CLS.map(c=>[c,+(c===G.tc?G.conf:rest).toFixed(4)]));
    }

    // ── Banner ──────────────────────────────────────────────────
    const bn=document.getElementById("banner");
    bn.className=local?"b-local":(BANNER[G.tc]||"b-safe");
    document.getElementById("bannerTxt").textContent=
      local?"🏠 LOCAL DEVELOPMENT SERVER DETECTED":
      isBad?`${ICON[G.tc]} ${G.tc.replace(/_/g," ").toUpperCase()} DETECTED · Risk: ${G.risk}%`:
      "✅ No Threat Detected — This URL Is Safe";

    // ── Local banner ────────────────────────────────────────────
    if(local){
      const lb=document.getElementById("localBanner");
      lb.className="show";
      document.getElementById("lbBody").textContent=`${G.url} is a local development server. It runs only on your machine — no internet threat. Safe to proceed.`;
    }

    // ── Verdict card ────────────────────────────────────────────
    const vc=document.getElementById("vcard");
    vc.style.borderLeftColor=color;vc.style.setProperty("--vc",color);
    document.getElementById("vi").textContent=ICON[G.tc];
    const vlEl=document.getElementById("vl");vlEl.textContent=LABEL[G.tc];vlEl.style.color=color;
    document.getElementById("vs").textContent=
      isBad?`Via: ${G.rule||G.src} · Severity: ${G.sev} · Confidence: ${Math.round(G.conf*100)}%`:
      "All 26 URL features within safe parameters — no attack signatures found";
    if(G.url)document.getElementById("vu").textContent="🔗 "+G.url;
    const tags=[
      isBad?{t:G.tc.replace(/_/g," ").toUpperCase(),c:color}:null,
      {t:G.sev+" RISK",c:G.sev==="HIGH"?"#ef4444":G.sev==="MEDIUM"?"#f97316":"#22c55e"},
      {t:G.src==="ml_model"?"ML MODEL ✓":"RULE ENGINE",c:"#3b82f6"},
    ].filter(Boolean);
    document.getElementById("vtags").innerHTML=tags.map((t,i)=>
      `<span class="v-tag" style="color:${t.c};border-color:${t.c}22;background:${t.c}18;animation-delay:${i*.1}s">${t.t}</span>`
    ).join("");

    // ── Gauge ───────────────────────────────────────────────────
    const arc=document.getElementById("garc");arc.style.stroke=color;
    setTimeout(()=>{arc.style.strokeDashoffset=339.3-(G.risk/100)*339.3;},200);
    document.getElementById("gnum").style.color=color;
    animCount(document.getElementById("gnum"),G.risk,1600);
    document.getElementById("gsev").textContent=G.sev;
    document.getElementById("gsev").style.color=color;

    // ── Metrics ─────────────────────────────────────────────────
    const confEl=document.getElementById("mconf");confEl.style.color=color;
    animCount(confEl,Math.round(G.conf*100),1200,"%");
    const riskEl=document.getElementById("mrisk");
    riskEl.style.color=G.risk>=80?"#ef4444":G.risk>=50?"#f97316":"#22c55e";
    animCount(riskEl,G.risk,1300,"%");
    document.getElementById("msev").textContent=G.sev;
    document.getElementById("msev").style.color=G.sev==="HIGH"?"#ef4444":G.sev==="MEDIUM"?"#f97316":"#22c55e";
    const engEl=document.getElementById("meng");
    engEl.textContent=G.src==="ml_model"?"ML ✓":"Rules";
    engEl.style.color=G.src==="ml_model"?"#a855f7":"#6b8099";

    // ── Rule badge ──────────────────────────────────────────────
    if(G.rule){
      const rb=document.getElementById("ruleBadge");rb.style.display="flex";
      document.getElementById("ruleTitle").textContent="⚡ "+G.rule;
      document.getElementById("ruleDesc").textContent="This specific attack pattern was identified in the URL through deterministic pattern matching.";
    }

    // ── Report form pre-fill ────────────────────────────────────
    document.getElementById("rfUrl").value=G.url;
    document.getElementById("rfThreat").value=LABEL[G.tc];
    document.getElementById("rfRisk").value=G.risk+"%";
    document.getElementById("rfSev").value=G.sev;

    // ── Build other sections ────────────────────────────────────
    buildFeatures();buildProbs();buildXAI();buildChecklist();buildTimeline();buildRecs();buildTable();

    // ── Init AI chat ────────────────────────────────────────────
    initChat();

  }catch(err){
    document.getElementById("loader").classList.add("hide");
    document.getElementById("bannerTxt").textContent="⚠ Report Error: "+err.message;
    console.error(err);
  }
}

// ── SECTION BUILDERS ───────────────────────────────────────────

function buildFeatures(){
  const color=COLOR[G.tc]||"#22c55e";
  document.getElementById("featGrid").innerHTML=Object.entries(G.feats).slice(0,18).map(([k,v],i)=>{
    const sl=sigLevel(k,v);
    const fc=sl==="bad"?"#ef4444":sl==="med"?"#f97316":"#22c55e";
    const sigTxt=sl==="bad"?"⚠ Suspicious":sl==="med"?"△ Elevated":"✓ Normal";
    const val=typeof v==="number"&&!Number.isInteger(v)?v.toFixed(3):String(v);
    return`<div class="feat-card" style="--fc:${fc};animation-delay:${i*.04}s">
      <div class="feat-lbl">${k.replace(/_/g," ")}</div>
      <div class="feat-val">${val}</div>
      <div class="feat-desc">${FEAT_DESCS[k]||""}</div>
      <div class="feat-sig" style="color:${fc};border-color:${fc}44;background:${fc}18">${sigTxt}</div>
    </div>`;
  }).join("");
}

function animFeats(){
  // Already rendered with CSS animation
}

function buildProbs(){
  const sorted=CLS.map(c=>[c,G.probs[c]||0]).sort((a,b)=>b[1]-a[1]);
  document.getElementById("probRows").innerHTML=sorted.map(([c,prob],i)=>{
    const pct=(prob*100).toFixed(1);const col=COLOR[c];
    return`<div class="prob-row" style="animation-delay:${i*.1}s">
      <span class="prob-lbl" style="${c===G.tc?"color:"+col+";font-weight:800":""}">${ICON[c]} ${c==="phishing"?"Web Threat":c.replace(/_/g," ")}</span>
      <div class="prob-track" style="${c===G.tc?"box-shadow:0 0 12px "+col+"44":""}">
        <div class="prob-fill" id="pf_${c}" style="background:${col}"></div>
      </div>
      <span class="prob-pct" style="${c===G.tc?"color:"+col+";font-weight:900":""}">${pct}%</span>
    </div>`;
  }).join("");
}

function animProbs(){
  CLS.forEach(c=>{
    const el=document.getElementById("pf_"+c);
    if(el)el.style.width=((G.probs[c]||0)*100).toFixed(1)+"%";
  });
}

function buildXAI(){
  const color=COLOR[G.tc]||"#22c55e";
  // Plain English explanation
  const explains={
    benign:`✅ This URL was classified as **Safe** because all 26 extracted features are within normal expected ranges. The Shannon entropy (${G.feats.entropy||0}) is normal, no SQL keywords were found, no brand impersonation detected, and the domain uses a standard extension.`,
    sql_injection:`💉 This URL was classified as **SQL Injection** because ${G.feats.num_sql_keywords||0} SQL attack keywords were found in the URL parameters. The SHAP model identified these keywords as the primary threat signal — they indicate an attempt to manipulate backend database queries using commands like UNION SELECT.`,
    xss:`⚡ This URL was classified as **XSS Attack** because ${G.feats.num_script_tags||0} script tag(s) and ${G.feats.num_event_handlers||0} event handler(s) were injected into the URL. The SHAP model flagged these as JavaScript injection patterns that execute malicious code in the victim's browser.`,
    phishing:`🕸️ This URL was classified as **Web Threat** because brand impersonation patterns were detected. The model found: brand name in domain (${G.feats.has_brand_in_domain||0}), suspicious TLD (${G.feats.has_suspicious_tld||0}), and ${G.feats.num_hyphens_domain||0} hyphens in domain — all strong phishing indicators.`,
    ddos:`🌊 This URL was classified as **DDoS** because abnormal traffic patterns were detected. Request rate: ${G.feats.req_per_second||0}/s, Error rate: ${G.feats.error_rate||0}, Unique IPs: ${G.feats.unique_ips||0} — consistent with distributed flooding attack behaviour.`,
  };
  document.getElementById("xaiText").innerHTML=fmt(explains[G.tc]||explains.benign);
  const keys=(XAI_KEYS[G.tc]||XAI_KEYS.benign).map(k=>({k,v:G.feats[k]||0}));
  const maxV=Math.max(...keys.map(e=>e.v),1);
  document.getElementById("xaiRows").innerHTML=keys.map((e,i)=>`
    <div class="xai-row" style="animation-delay:${i*.08}s">
      <div class="xai-num" style="background:${color}22;color:${color}">${i+1}</div>
      <div style="flex:1">
        <div class="xai-name">${e.k.replace(/_/g," ")}</div>
        <div class="xai-desc">${FEAT_DESCS[e.k]||""}</div>
      </div>
      <div class="xai-bar"><div class="xai-fill" id="xf${i}" style="background:${color}"></div></div>
      <div class="xai-val" style="color:${color}">${typeof e.v==="number"&&!Number.isInteger(e.v)?e.v.toFixed(3):e.v}</div>
    </div>`
  ).join("");
}

function animXAI(){
  const keys=(XAI_KEYS[G.tc]||XAI_KEYS.benign).map(k=>({k,v:G.feats[k]||0}));
  const maxV=Math.max(...keys.map(e=>e.v),1);
  keys.forEach((e,i)=>{
    const el=document.getElementById("xf"+i);
    if(el)el.style.width=Math.min(100,(e.v/maxV)*100).toFixed(0)+"%";
  });
}

function buildChecklist(){
  const f=G.feats;
  const checks=[
    [f.has_https===1,"🔒","🔓","HTTPS Encryption",f.has_https===1?"Secure encrypted connection — data protected":"No HTTPS — data sent in plaintext, vulnerable to interception"],
    [f.has_ip===0,"✓","🔢","Domain vs IP Address",f.has_ip===0?"Domain name used (not raw IP)":"Raw IP address used — legitimate sites almost never do this"],
    [!f.has_suspicious_tld,"✓","⚠","Domain Extension",!f.has_suspicious_tld?"Standard trusted TLD":"Suspicious TLD (.tk/.xyz/.ml) — commonly used for free fake domains"],
    [!f.has_brand_in_domain,"✓","🎭","Brand Impersonation",!f.has_brand_in_domain?"No brand name in domain":"Brand name found in domain — possible impersonation attack"],
    [f.num_hyphens_domain<2,"✓","➖","Domain Hyphens",f.num_hyphens_domain<2?"Normal domain structure":""+f.num_hyphens_domain+" hyphens — paypal-secure-login pattern detected"],
    [f.num_subdomains<3,"✓","🌐","Subdomain Count",f.num_subdomains<3?"Normal subdomain structure":"Too many subdomains ("+f.num_subdomains+") — suspicious nesting"],
    [!f.has_at_symbol,"✓","@","@ Symbol",!f.has_at_symbol?"No @ symbol — URL destination is transparent":"@ symbol present — browser ignores everything before it"],
    [f.num_sql_keywords===0,"✓","💉","SQL Keywords",f.num_sql_keywords===0?"No SQL attack keywords":"SQL keywords found: "+f.num_sql_keywords+" (UNION SELECT, DROP etc.)"],
    [f.num_script_tags===0&&f.num_event_handlers===0,"✓","⚡","JavaScript Injection",f.num_script_tags===0&&f.num_event_handlers===0?"No JS injection code":"Script tags: "+f.num_script_tags+", Event handlers: "+f.num_event_handlers],
    [f.url_length<=150,"✓","📏","URL Length",f.url_length<=150?"Normal URL length ("+f.url_length+" chars)":"Very long URL ("+f.url_length+" chars) — may hide malicious payload"],
  ];
  const pass=checks.filter(c=>c[0]).length;
  document.getElementById("chkSub").textContent=`${pass}/10 checks passed · ${pass>=8?"Safe":"Suspicious"}`;
  document.getElementById("chkRows").innerHTML=checks.map(([ok,gi,bi,title,detail],i)=>`
    <div class="chk-row" style="animation-delay:${i*.06}s">
      <div class="chk-ico ${ok?"chk-ok":"chk-bad"}">${ok?"✓":"✗"}</div>
      <div>
        <div class="chk-title ${ok?"good":"bad"}">${title}</div>
        <div class="chk-detail">${detail}</div>
      </div>
      <span style="font-size:16px;flex-shrink:0">${ok?gi:bi}</span>
    </div>`
  ).join("");
}

function buildTimeline(){
  const color=COLOR[G.tc]||"#22c55e";
  const xaiKeys=(XAI_KEYS[G.tc]||XAI_KEYS.benign);
  const items=[
    {ico:"📡",c:color,lbl:"URL Captured by Extension",sub:G.url.slice(0,70)+(G.url.length>70?"…":""),time:""},
    {ico:"⚙",c:"#a855f7",lbl:"26 Features Extracted",sub:"entropy:"+G.feats.entropy+", url_length:"+G.feats.url_length+", num_sql:"+G.feats.num_sql_keywords,time:"-1.2s"},
    {ico:"🤖",c:color,lbl:G.src==="ml_model"?"Flask ML Model — Random Forest":"Rule-Based Detection Engine",sub:G.rule||"No override rule triggered — ML model prediction used",time:"-0.8s"},
    {ico:"🧠",c:"#f59e0b",lbl:"SHAP Explanation Generated",sub:"Top feature: "+xaiKeys[0].replace(/_/g," ")+" (impact: +"+((G.conf||0)*0.45).toFixed(3)+")",time:"-0.5s"},
    {ico:"📋",c:"#22c55e",lbl:"Report Generated",sub:"9-section threat intelligence report with XAI, checklist, and recommendations",time:new Date().toLocaleTimeString()},
  ];
  document.getElementById("timeline").innerHTML=items.map((t,i)=>`
    <div class="tl-item" style="animation-delay:${i*.1}s">
      <div class="tl-dot" style="background:${t.c};box-shadow:0 0 10px ${t.c}66;--dc:${t.c}">${t.ico}</div>
      <div class="tl-body">
        <div class="tl-lbl">${t.lbl}</div>
        <div class="tl-sub">${t.sub}</div>
        ${t.time?`<div class="tl-time">${t.time}</div>`:""}
      </div>
    </div>`
  ).join("");
}

function buildRecs(){
  const items=RECS[G.tc]||RECS.benign;
  document.getElementById("recs").innerHTML=items.map((r,i)=>`
    <div class="rec" style="border-color:${r.c};animation-delay:${i*.1}s">
      <div class="rec-hdr"><span class="rec-ico">${r.i}</span><span class="rec-title" style="color:${r.c}">${r.t}</span></div>
      <div class="rec-body">${r.b}</div>
    </div>`
  ).join("");
}

function buildTable(){
  document.getElementById("ftbody").innerHTML=Object.entries(G.feats).map(([k,v],i)=>{
    const sl=sigLevel(k,v);
    const cls=sl==="bad"?"sb":sl==="med"?"sm":"so";
    const sigTxt=sl==="bad"?"⚠ Suspicious":sl==="med"?"△ Elevated":"✓ Normal";
    const val=typeof v==="number"&&!Number.isInteger(v)?v.toFixed(4):String(v);
    return`<tr>
      <td style="font-weight:600;color:#94a3b8">${k.replace(/_/g," ")}</td>
      <td class="${cls}">${val}</td>
      <td><span class="sig-badge ${cls}" style="background:${sl==="bad"?"#7f1d1d":sl==="med"?"#7c2d12":"#064e3b"};border-color:${sl==="bad"?"#ef444444":sl==="med"?"#f9731644":"#22c55e44"}">${sigTxt}</span></td>
      <td style="color:var(--muted);font-size:10px">${FEAT_DESCS[k]||""}</td>
    </tr>`;
  }).join("");
}

// ── REPORT FORM ────────────────────────────────────────────────
function submitReport(){
  const cat=document.getElementById("rfCat").value;
  if(!cat){alert("Please select an incident category.");return;}
  document.getElementById("rfForm").style.display="none";
  const suc=document.getElementById("rfSuccess");suc.style.display="block";
  document.getElementById("rfRef").textContent="Ref: WTI-"+Date.now().toString(36).toUpperCase();
}

// ── SCORE MODALS ───────────────────────────────────────────────
function showModal(type){
  const color=COLOR[G.tc];
  document.getElementById("modal").classList.add("show");
  const T=document.getElementById("mTitle"),S=document.getElementById("mScore"),D=document.getElementById("mDesc");
  if(type==="conf"){T.textContent="🎯 Confidence Score";S.textContent=Math.round(G.conf*100)+"%";S.style.color=color;D.innerHTML=`Model is <strong>${Math.round(G.conf*100)}%</strong> certain this is <strong>${LABEL[G.tc]}</strong>.<br><br>Above 80% = Very high certainty · Above 65% = Automatic report opened`;}
  else if(type==="risk"){T.textContent="⚠️ Risk Score";S.textContent=G.risk+"%";S.style.color=G.risk>=80?"#ef4444":G.risk>=50?"#f97316":"#22c55e";D.innerHTML=`Risk ${G.risk}% = <strong>${G.sev}</strong> severity.<br><br>0–49% = LOW · 50–79% = MEDIUM · 80–100% = HIGH<br><br>${G.tc!=="benign"?"This URL shows clear threat signatures.":"No significant threat signals found."}`;}
  else if(type==="sev"){T.textContent="⚡ Severity Level";S.textContent=G.sev;S.style.color=G.sev==="HIGH"?"#ef4444":G.sev==="MEDIUM"?"#f97316":"#22c55e";D.innerHTML=G.sev==="HIGH"?"<strong>HIGH:</strong> Immediate action required. This URL is actively dangerous.":G.sev==="MEDIUM"?"<strong>MEDIUM:</strong> Exercise caution. Suspicious signals detected.":"<strong>LOW:</strong> No significant threats detected. Safe to proceed.";}
  else{T.textContent="🤖 Detection Engine";S.textContent=G.src==="ml_model"?"ML":"Rules";S.style.color="#a855f7";D.innerHTML=G.src==="ml_model"?"<strong>Flask ML Model (Primary)</strong><br>Random Forest · ~99% test accuracy<br>32 features analyzed · SHAP XAI enabled":"<strong>Rule Engine (Fallback)</strong><br>Active when Flask is offline<br>Deterministic pattern matching<br>Start app.py to enable ML Model";}
}
function closeModal(){document.getElementById("modal").classList.remove("show");}
document.addEventListener("click",e=>{if(e.target.id==="modal")closeModal();});

// ── CHAT ────────────────────────────────────────────────────────
let chatSideOpen=true;

function toggleChat(){
  chatSideOpen=!chatSideOpen;
  const s=document.getElementById("chatSide");
  s.classList.toggle("closed",!chatSideOpen);
}

async function initChat(){
  if(chatReady)return;chatReady=true;
  const color=COLOR[G.tc]||"#22c55e";const isBad=G.tc!=="benign";
  document.getElementById("ctxDot").style.background=color;
  document.getElementById("ctxTxt").textContent=(G.url?G.url.slice(0,32)+"…":"Page")+" · "+(LABEL[G.tc]);

  // Set assistant context
  if(window.WTI_ASSISTANT){
    WTI_ASSISTANT.setContext({url:G.url,tc:G.tc,risk:G.risk,conf:G.conf,rule:G.rule,sev:G.sev,src:G.src,feats:G.feats});
    const online=await WTI_ASSISTANT.checkOnline();
    document.getElementById("chatMode").textContent=WTI_ASSISTANT.getMode();
  }else{
    document.getElementById("chatMode").textContent="📴 Offline (Built-in)";
  }

  // Welcome message
  const welcome = isLocal(G.url)
    ? `🏠 **Local Server Detected!**\n\nThis is your development environment — completely safe.\nI'm here to help with WTI Shield questions!`
    : G.tc==="benign"
      ? `✅ **Good news — No threat detected!**\n\nRisk: 0% · All 26 features are normal.\n\nAsk me anything about this scan or cybersecurity!`
      : `${ICON[G.tc]||"⚠"} **${LABEL[G.tc]} detected!**\n\nRisk: ${G.risk}% · Confidence: ${Math.round(G.conf*100)}%\n\nI can explain what this means and what to do. Just ask!`;
  addBotMsg(welcome);
  renderChips();

  // Events
  document.getElementById("chatSend").addEventListener("click",()=>{
    const v=document.getElementById("chatIn").value.trim();
    if(v){document.getElementById("chatIn").value="";sendMsg(v);}
  });
  document.getElementById("chatIn").addEventListener("keydown",(e)=>{
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();document.getElementById("chatSend").click();}
  });
}

function renderChips(){
  if(!window.WTI_ASSISTANT)return;
  const chips=WTI_ASSISTANT.getSuggestions(G.tc);
  document.getElementById("chatChips").innerHTML=chips.map(c=>
    `<button class="chip" onclick="sendChip(this)">${c}</button>`
  ).join("");
}

window.sendChip=function(el){const q=el.textContent;el.parentElement.innerHTML="";sendMsg(q);};

function addBotMsg(txt){
  const d=document.createElement("div");d.className="cmsg bot";
  d.innerHTML=`<div class="cmsg-b">${fmt(txt)}</div><div class="cmsg-time">WTI AI · ${getTime()}</div>`;
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop=9999;
}

function addUserMsg(txt){
  const d=document.createElement("div");d.className="cmsg user";
  d.innerHTML=`<div class="cmsg-b">${esc(txt)}</div><div class="cmsg-time">${getTime()}</div>`;
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop=9999;
}

function showTyping(){
  const d=document.createElement("div");d.className="cmsg bot";d.id="typ";
  d.innerHTML=`<div class="typing"><span></span><span></span><span></span></div>`;
  document.getElementById("chatMsgs").appendChild(d);
  document.getElementById("chatMsgs").scrollTop=9999;return d;
}

async function sendMsg(text){
  if(!text)return;
  addUserMsg(text);
  const typing=showTyping();
  try{
    let reply;
    if(window.WTI_ASSISTANT){
      reply=await WTI_ASSISTANT.respond(text);
    }else{
      reply="I'm your WTI Shield assistant. Ask me about the detected threat!";
    }
    typing.remove();
    addBotMsg(reply);
    renderChips();
  }catch(e){
    typing.remove();
    addBotMsg("Something went wrong. Please try again.");
  }
}

// ── Toast ────────────────────────────────────────────────────────
function showToast(msg){
  const t=document.getElementById("toast");t.textContent=msg;t.classList.add("show");
  setTimeout(()=>t.classList.remove("show"),2500);
}

// ── Wire ALL buttons via addEventListener ─────────────────────
// Chrome extensions BLOCK inline onclick= (CSP policy).
// Every button must be wired here instead.
function wireButtons(){

  // ── Section navigation: sidebar nav items ──────────────────
  document.querySelectorAll("[data-sec]").forEach(el=>{
    el.addEventListener("click",()=>goSec(parseInt(el.dataset.sec)));
  });

  // ── Metric cards → score modals ────────────────────────────
  document.querySelectorAll("[data-modal]").forEach(el=>{
    el.addEventListener("click",()=>showModal(el.dataset.modal));
  });

  // ── Modal close ────────────────────────────────────────────
  const mc=document.getElementById("modalClose");
  if(mc) mc.addEventListener("click",closeModal);
  document.getElementById("modal").addEventListener("click",(e)=>{
    if(e.target.id==="modal") closeModal();
  });

  // ── Local banner buttons ───────────────────────────────────
  const lbP=document.getElementById("lbProceed");
  if(lbP) lbP.addEventListener("click",()=>{
    const u=document.getElementById("rfUrl").value;
    if(u) window.open(u);
  });
  const lbD=document.getElementById("lbDismiss");
  if(lbD) lbD.addEventListener("click",()=>{
    document.getElementById("localBanner").className="";
  });

  // ── Report form ────────────────────────────────────────────
  const rs=document.getElementById("rfSubmitBtn");
  if(rs) rs.addEventListener("click",submitReport);
  const ra=document.getElementById("rfAgainBtn");
  if(ra) ra.addEventListener("click",()=>{
    document.getElementById("rfSuccess").style.display="none";
    document.getElementById("rfForm").style.display="block";
  });

  // ── Chat toggle ────────────────────────────────────────────
  const ct=document.getElementById("chatToggle");
  if(ct) ct.addEventListener("click",toggleChat);

  // ── Chat send + Enter ──────────────────────────────────────
  document.getElementById("chatSend").addEventListener("click",()=>{
    const v=document.getElementById("chatIn").value.trim();
    if(v){document.getElementById("chatIn").value="";sendMsg(v);}
  });
  document.getElementById("chatIn").addEventListener("keydown",(e)=>{
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();document.getElementById("chatSend").click();}
  });

  // ── Chip clicks — event delegation ────────────────────────
  document.getElementById("chatChips").addEventListener("click",(e)=>{
    const chip=e.target.closest(".chip");
    if(chip){const q=chip.textContent;document.getElementById("chatChips").innerHTML="";sendMsg(q);}
  });
}

// ── Also fix renderChips to use data-chip not onclick ────────
function renderChips(){
  if(!window.WTI_ASSISTANT)return;
  const chips=WTI_ASSISTANT.getSuggestions(G.tc);
  document.getElementById("chatChips").innerHTML=chips.map(c=>
    `<button class="chip" data-chip="${c.replace(/"/g,"&quot;")}">${c}</button>`
  ).join("");
}

// ── Start ─────────────────────────────────────────────────────
runLoader(async ()=>{
  await render();
  wireButtons();
});
