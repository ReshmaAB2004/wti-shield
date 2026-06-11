// WTI Shield v9 — popup.js

const COLORS={benign:"#22c55e",sql_injection:"#ef4444",xss:"#f97316",phishing:"#a855f7",ddos:"#3b82f6",local:"#f59e0b"};
const ICONS ={benign:"✅",sql_injection:"💉",xss:"⚡",phishing:"🕸️",ddos:"🌊",local:"🏠"};
const LABELS={benign:"✓ SAFE",sql_injection:"🚨 SQL INJECTION",xss:"🚨 XSS ATTACK",phishing:"⚠️ WEB THREAT",ddos:"🚨 DDoS ATTACK",local:"🏠 LOCAL SERVER"};
const CARD  ={benign:"card-safe",sql_injection:"card-sql",xss:"card-xss",phishing:"card-phishing",ddos:"card-ddos",local:"card-local"};

let curResult=null, curUrl="", chatReady=false;

// ── Detection (rule-based fallback) ────────────────────────────
const TRUSTED=["google.com","youtube.com","apple.com","amazon.com","microsoft.com","facebook.com","instagram.com","linkedin.com","twitter.com","x.com","github.com","stackoverflow.com","wikipedia.org","reddit.com","netflix.com","dropbox.com","ebay.com","paypal.com","steam.com","bing.com","whatsapp.com","office.com","yahoo.com","gmail.com","outlook.com"];
const BRANDS=["paypal","appleid","amazon","microsoft","facebook","netflix","instagram","whatsapp","wellsfargo","citibank","hsbc","barclays","dropbox","steam","roblox","chase","bankofamerica"];
const BAD_TLDS=[".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",".online",".site",".biz",".club",".pw",".cc",".ws",".info"];
const SQL_KW=["union select","union+select","' or '","or 1=1","1=1","insert into","drop table","drop database","exec(","cast(0x","benchmark(","sleep(","xp_cmd","select * from","delete from","/**/","waitfor delay"];
const PHISH_KW=["login","signin","verify","secure","update","account","password","confirm","credential","wallet","suspended","billing","support","authenticate","recover","unlock"];

function calcEnt(s){if(!s)return 0;const f={};for(const c of s)f[c]=(f[c]||0)+1;return+(-Object.values(f).reduce((t,v)=>{const p=v/s.length;return t+p*Math.log2(p);},0)).toFixed(4);}

function extractFeats(url){
  if(!url)return{};
  let host="",scheme="http",domain="";
  try{const u=new URL(url.startsWith("http")?url:"http://"+url);host=u.hostname.toLowerCase();scheme=u.protocol.replace(":","")}catch{host=url.split("/")[0];}
  const parts=host.split(".");domain=parts.length>=2?parts[parts.length-2]:host;
  const subs=parts.length>2?parts.slice(0,-2):[];
  const low=url.toLowerCase();const tr=TRUSTED.some(d=>{const h=host.replace(/^www\./,"");return h===d||h.endsWith("."+d);});
  return{url_length:url.length,has_ip:/^\d{1,3}(\.\d{1,3}){3}$/.test(host)?1:0,num_subdomains:subs.length,has_https:scheme==="https"?1:0,entropy:calcEnt(url),num_digits:(url.match(/\d/g)||[]).length,num_params:(url.match(/[?&]/g)||[]).length,payload_length:url.length,num_encoded_chars:(url.match(/%[0-9a-fA-F]{2}/g)||[]).length,num_sql_keywords:SQL_KW.filter(k=>low.includes(k)).length,num_script_tags:(low.match(/<script/gi)||[]).length,num_event_handlers:(low.match(/on\w+\s*=/gi)||[]).length,brand_keyword_count:tr?0:BRANDS.filter(b=>low.includes(b)).length,has_brand_in_domain:tr?0:(BRANDS.some(b=>domain.includes(b)&&!host.endsWith(b+".com"))?1:0),has_suspicious_tld:BAD_TLDS.some(t=>host.endsWith(t))?1:0,num_hyphens_domain:(domain.match(/-/g)||[]).length,domain_length:host.length,has_at_symbol:url.includes("@")?1:0,req_per_second:1,avg_payload_size:300,unique_ips:1,error_rate:0,req_size_variance:20};
}

function detect(url){
  if(!url)return null;
  const feats=extractFeats(url);const low=url.toLowerCase();
  const sqlHits=feats.num_sql_keywords;const xss=feats.num_script_tags*2+feats.num_event_handlers;
  let tc="benign",conf=0.91,rule=null;
  if(sqlHits>=2){tc="sql_injection";conf=Math.min(0.55+sqlHits*0.09,0.97);rule="SQL: "+sqlHits+" keywords";}
  else if(xss>=2){tc="xss";conf=Math.min(0.55+xss*0.08,0.97);rule="XSS: "+xss+" signals";}
  else if(!TRUSTED.some(d=>{const h=(url.replace(/^https?:\/\//,"").split("/")[0]||"").replace(/^www\./,"");return h===d||h.endsWith("."+d);})){
    let ps=0;if(feats.has_brand_in_domain)ps+=5;if(feats.has_suspicious_tld)ps+=4;if(feats.num_hyphens_domain>=2)ps+=3;if(feats.has_ip)ps+=4;if(url.includes("@"))ps+=4;if(feats.num_subdomains>=3)ps+=3;ps+=PHISH_KW.filter(k=>low.includes(k)).length;
    if(ps>=4){tc="phishing";conf=Math.min(0.50+ps*0.055,0.97);rule="Web Threat (score "+ps+")";}
  }
  const risk=tc==="benign"?0:Math.round(conf*100);
  const rest=(1-conf)/4;
  return{url,threat_class:tc,confidence:+conf.toFixed(4),risk_score:risk,is_malicious:tc!=="benign",severity:risk>=80?"HIGH":risk>=50?"MEDIUM":"LOW",rule_triggered:rule,all_probs:Object.fromEntries(["benign","sql_injection","xss","phishing","ddos"].map(c=>[c,+(c===tc?conf:rest).toFixed(4)])),source:"rule_engine",feats};
}

// ── Render result ───────────────────────────────────────────────
function render(r, url){
  curResult=r; curUrl=url;
  const tc = r.is_local ? "local" : r.threat_class;
  document.getElementById("card").className = "card "+(CARD[tc]||"card-safe");
  document.getElementById("ci").textContent  = ICONS[tc]||"✅";
  document.getElementById("cl").textContent  = LABELS[tc]||tc;
  document.getElementById("cu").textContent  = url||"";
  document.getElementById("cs").textContent  = r.source==="ml_model"?"🤖 ML Model":"⚙ Rule Engine";
  const pct = Math.round((r.confidence||0)*100);
  document.getElementById("cfill").style.width = pct+"%";
  document.getElementById("ctxt").textContent  = r.is_local ? "Local Dev Server — Safe" : "Confidence: "+pct+"% · Risk: "+(r.risk_score||0)+"%";

  // Buttons
  const btns = document.getElementById("btns");
  if(r.is_local){
    btns.innerHTML = `
      <button class="btn btn-local" id="localBtn">🏠 View Local Warning</button>
      <button class="btn btn-chat"  id="chatBtn">🤖 Ask AI</button>`;
    document.getElementById("localBtn").addEventListener("click",()=>{
      const q=new URLSearchParams({url:curUrl,reason:r.local_reason||"localhost"});
      chrome.tabs.create({url:chrome.runtime.getURL("localhost/localhost.html")+"?"+q});
    });
  } else {
    btns.innerHTML = `
      <button class="btn btn-report" id="reportBtn">📋 View Report</button>
      <button class="btn btn-chat"   id="chatBtn">🤖 Ask AI
        <span class="chat-notif" id="chatNotif" style="${r.is_malicious?"display:flex":"display:none"}">!</span>
      </button>`;
    document.getElementById("reportBtn").addEventListener("click", openReport);
  }
  document.getElementById("chatBtn").addEventListener("click", openChat);

  // Set assistant context
  if(window.WTI_ASSISTANT){
    WTI_ASSISTANT.setContext({url,tc:r.threat_class,risk:r.risk_score,conf:r.confidence,rule:r.rule_triggered||"",sev:r.severity,src:r.source,feats:r.feats||{}});
  }
}

function renderStats(s){
  if(!s)return;
  document.getElementById("nScanned").textContent=s.scanned||0;
  const t=s.threats||{};
  document.getElementById("nThreats").textContent=Object.values(t).reduce((a,b)=>a+b,0);
  document.getElementById("c-sql").textContent=t.sql_injection||0;
  document.getElementById("c-xss").textContent=t.xss||0;
  document.getElementById("c-ph").textContent=t.phishing||0;
  document.getElementById("c-ddos").textContent=t.ddos||0;
}

function openReport(){
  if(!curResult||!curUrl)return;
  const q=new URLSearchParams({url:curUrl,threat:curResult.threat_class,risk:curResult.risk_score,conf:curResult.confidence,rule:curResult.rule_triggered||"",sev:curResult.severity,source:curResult.source,probs:JSON.stringify(curResult.all_probs||{})});
  chrome.tabs.create({url:chrome.runtime.getURL("report/report.html")+"?"+q});
}

// ── CHAT ────────────────────────────────────────────────────────
function openChat(){
  document.getElementById("chatPanel").classList.add("open");
  if(!chatReady) initChat();
  else document.getElementById("chatIn").focus();
}

function closeChat(){
  document.getElementById("chatPanel").classList.remove("open");
}

async function initChat(){
  chatReady=true;
  const tc=curResult?.threat_class||"benign";
  const color=COLORS[curResult?.is_local?"local":tc]||"#22c55e";
  document.getElementById("ctxDot").style.background=color;
  document.getElementById("ctxTxt").textContent=(curUrl?curUrl.slice(0,42)+"…":"Current page")+" · "+(curResult?.is_local?"🏠 LOCAL":LABELS[tc]||"Safe");

  // Check online mode
  let mode = "📴 Offline";
  if(window.WTI_ASSISTANT){
    const online = await WTI_ASSISTANT.checkOnline();
    mode = WTI_ASSISTANT.getMode();
  }
  document.getElementById("chatMode").textContent = mode;

  // Welcome
  const welcome = curResult?.is_local
    ? `🏠 **Local server detected!**\n\nThis is your development environment — completely safe.\nAsk me anything about WTI Shield or localhost!`
    : tc==="benign"
      ? `✅ **This URL appears safe!** Risk: ${curResult?.risk_score||0}%\n\nAsk me anything about this scan or cybersecurity!`
      : `${ICONS[tc]||"⚠"} **Threat detected!** Risk: ${curResult?.risk_score||0}%\n\nI can explain what this means and what to do. Just ask!`;
  addBotMsg(welcome);
  renderChips(tc);
  document.getElementById("chatIn").focus();
}

function renderChips(tc){
  if(!window.WTI_ASSISTANT)return;
  const s=WTI_ASSISTANT.getSuggestions(tc);
  document.getElementById("chips").innerHTML=s.map(c=>
    `<button class="chip" onclick="sendChip(this)">${c}</button>`
  ).join("");
}

function sendChip(el){const q=el.textContent;el.parentElement.innerHTML="";sendMessage(q);}

function addUserMsg(txt){
  const d=document.createElement("div");d.className="cmsg user";
  d.innerHTML=`<div class="cmsg-b">${escHtml(txt)}</div><div class="cmsg-time">${getTime()}</div>`;
  document.getElementById("chatMsgs").appendChild(d);scrollChat();
}

function addBotMsg(txt){
  const d=document.createElement("div");d.className="cmsg bot";
  d.innerHTML=`<div class="cmsg-b">${fmtMsg(txt)}</div><div class="cmsg-time">WTI AI · ${getTime()}</div>`;
  document.getElementById("chatMsgs").appendChild(d);scrollChat();
}

function showTyping2(){
  const d=document.createElement("div");d.className="cmsg bot";d.id="typ2";
  d.innerHTML=`<div class="typing2"><span></span><span></span><span></span></div>`;
  document.getElementById("chatMsgs").appendChild(d);scrollChat();return d;
}

async function sendMessage(text){
  if(!text||!text.trim())return;
  if(!chatReady)await initChat();
  addUserMsg(text);
  const typing=showTyping2();
  try{
    let reply;
    if(window.WTI_ASSISTANT){
      reply = await WTI_ASSISTANT.respond(text);
    }else{
      reply = "I'm your security assistant. Try asking about the detected threat!";
    }
    typing.remove();
    addBotMsg(reply);
    renderChips(curResult?.threat_class||"benign");
  }catch(e){
    typing.remove();
    addBotMsg("Sorry, something went wrong. Please try again.");
  }
}

function scrollChat(){const el=document.getElementById("chatMsgs");setTimeout(()=>el.scrollTop=el.scrollHeight,50);}
function escHtml(t){return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function fmtMsg(t){return escHtml(t).replace(/\*\*(.*?)\*\*/g,"<strong>$1</strong>").replace(/`(.*?)`/g,"<code>$1</code>").replace(/\n/g,"<br>");}
function getTime(){return new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});}

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded",()=>{
  chrome.runtime.sendMessage({type:"GET_RESULT"},(resp)=>{
    if(chrome.runtime.lastError){
      chrome.tabs.query({active:true,currentWindow:true},tabs=>{
        if(tabs[0]?.url){const r=detect(tabs[0].url);if(r)render(r,tabs[0].url);}
      });return;
    }
    if(resp?.result)render(resp.result,resp.url||"");
    else if(resp?.url){const r=detect(resp.url);if(r)render(r,resp.url);}
    if(resp?.stats)renderStats(resp.stats);
    const on=resp?.mlApiOnline||false;
    document.getElementById("apiDot").className="api-dot "+(on?"on":"off");
    document.getElementById("apiLbl").textContent=on?"🤖 ML Model connected":"⚙ Rule Engine active";
  });

  // Chat events
  document.getElementById("chatClose").addEventListener("click",closeChat);
  document.getElementById("chatGo").addEventListener("click",()=>{
    const v=document.getElementById("chatIn").value.trim();
    if(v){document.getElementById("chatIn").value="";sendMessage(v);}
  });
  document.getElementById("chatIn").addEventListener("keydown",(e)=>{
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();document.getElementById("chatGo").click();}
  });

  // Manual scan
  const doScan=()=>{
    const url=document.getElementById("scanIn").value.trim();
    if(!url)return;
    const r=detect(url);if(r)render(r,url);
  };
  document.getElementById("scanBtn").addEventListener("click",doScan);
  document.getElementById("scanIn").addEventListener("keydown",e=>{if(e.key==="Enter")doScan();});
});

// Global chip handler
window.sendChip = sendChip;
