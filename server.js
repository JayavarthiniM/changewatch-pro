const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const cron = require('node-cron');
const { chromium } = require('playwright');
const cheerio = require('cheerio');
const nodemailer = require('nodemailer');
const { cleanText, extractNumbers, diffText, summarizeChange, matchesKeywords, shouldAlert, significance, explainChange } = require('./intelligence');
const { isPrivateAddress, normalizeHostname, MAX_REDIRECT_HOPS } = require('./security');
const { isQuietHours } = require('./notification-policy');
const { normalizeAlertRules, evaluateAlertRules } = require('./alert-rules');
const { runReliabilityBenchmark } = require('./reliability-benchmark');
const { buildConfigExport, validateConfigImport } = require('./config-transfer');
const { readJsonWithBackup, writeJsonAtomic } = require('./json-storage');
const { validateSettingsPatch } = require('./settings-validation');
const { validateSitePatch } = require('./site-validation');
const { retainRecentJobs } = require('./job-retention');
const { createRateLimiter } = require('./api-rate-limit');
const { apiErrorHandler } = require('./api-error-handler');
const { normalizeStore } = require('./store-normalization');
const { createSqliteStorage, assertSafeSqliteBootstrap } = require('./sqlite-storage');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname, DATA = path.join(ROOT, 'data', 'store.json'), SHOTS = path.join(ROOT, 'snapshots');
fs.mkdirSync(path.dirname(DATA), {recursive:true}); fs.mkdirSync(SHOTS,{recursive:true});
app.use(helmet({contentSecurityPolicy:false})); app.use(express.json({limit:'1mb'}));
// Apply API rate limiting only to API routes; static dashboard assets remain unaffected.
const apiRateLimit = createRateLimiter({ max: Number(process.env.API_RATE_LIMIT_PER_MINUTE || 120) });
app.use('/api', apiRateLimit);
const AUTH_USER=process.env.CW_AUTH_USER||'',AUTH_PASSWORD=process.env.CW_AUTH_PASSWORD||'';
function safeEqual(a,b){const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y);}
app.use((req,res,next)=>{
  if(!(AUTH_USER&&AUTH_PASSWORD))return next();
  const h=String(req.headers.authorization||'');
  if(h.startsWith('Basic ')){try{const raw=Buffer.from(h.slice(6),'base64').toString();const i=raw.indexOf(':');if(i>=0&&safeEqual(raw.slice(0,i),AUTH_USER)&&safeEqual(raw.slice(i+1),AUTH_PASSWORD))return next();}catch{}}
  res.setHeader('WWW-Authenticate','Basic realm="ChangeWatch Pro", charset="UTF-8"');res.status(401).send('Authentication required');
});
app.use(express.static(path.join(ROOT,'public')));
const initial = {sites:[], snapshots:[], events:[], pendingNotifications:[], settings:{theme:'dark', email:'', telegramToken:'', telegramChatId:'', discordWebhook:'', quietStart:'22:00', quietEnd:'08:00', digest:false, sensitivity:20}, jobs:[], reports:[], schemaVersion:2};
const storageMode = String(process.env.CW_STORAGE || 'json').toLowerCase();
if (!['json', 'sqlite'].includes(storageMode)) throw new Error('CW_STORAGE must be json or sqlite');
const sqliteStorage = storageMode === 'sqlite'
  ? createSqliteStorage({ filename: process.env.CW_SQLITE_PATH || path.join(ROOT, 'data', 'changewatch.sqlite') })
  : null;
const loadedStore = sqliteStorage
  ? { ...sqliteStorage.load(initial), recoveredFromBackup: false, source: sqliteStorage.filename }
  : readJsonWithBackup(DATA, initial);
if (sqliteStorage && loadedStore.empty) {
  assertSafeSqliteBootstrap({ sqliteEmpty: true, legacyJsonPath: DATA, allowEmpty: process.env.CW_SQLITE_ALLOW_EMPTY === 'true' });
}
const normalizedStore = normalizeStore(loadedStore.value, initial);
let db = normalizedStore.value;
for (const warning of normalizedStore.warnings) console.warn(`ChangeWatch Pro store normalization: ${warning}`);
if (sqliteStorage) {
  if (loadedStore.empty || normalizedStore.warnings.length) sqliteStorage.save(db);
} else if (loadedStore.recoveredFromBackup || normalizedStore.warnings.length) {
  console.error(`ChangeWatch Pro recovered its data store from backup: ${loadedStore.source}`);
  // Keep the corrupt original for manual inspection and restore a valid active store.
  try { if (fs.existsSync(DATA)) fs.renameSync(DATA, `${DATA}.corrupt-${Date.now()}`); } catch {}
  writeJsonAtomic(DATA, db);
}
function save(){ if (sqliteStorage) sqliteStorage.save(db); else writeJsonAtomic(DATA, db); }
const storageLabel = sqliteStorage ? 'sqlite-app-state' : 'local-json-with-backup';
const queueDurabilityLabel = sqliteStorage ? 'recoverable-sqlite-state-document' : 'recoverable-json-records';
function id(){return crypto.randomUUID();}
function sha(s){return crypto.createHash('sha256').update(s).digest('hex');}
function privateAddressGuard(ip){ return isPrivateAddress(ip); }
async function validateUrl(raw){let u;try{u=new URL(raw)}catch{throw Error('Enter a valid URL');}if(!['http:','https:'].includes(u.protocol))throw Error('Only HTTP and HTTPS URLs are allowed');if(u.username||u.password)throw Error('URLs with embedded credentials are not allowed');u.hostname=normalizeHostname(u.hostname);if(u.hostname==='localhost'||u.hostname.endsWith('.localhost')||u.hostname.endsWith('.local')||u.hostname.endsWith('.internal')||(net.isIP(u.hostname)&&privateAddressGuard(u.hostname)))throw Error('Private and local network addresses are blocked for security');let ips=[];try{ips=await dns.lookup(u.hostname,{all:true});}catch{throw Error('Hostname could not be resolved');}if(ips.some(x=>privateAddressGuard(x.address)))throw Error('URL resolves to a private network address');return u.toString();}
async function notify(site,event){
  const msg=`ChangeWatch: ${site.name}\\n${event.summaryLine||event.summary}\\n${site.url}\\nSeverity: ${event.severity}\\n${new Date(event.time).toISOString()}`;
  const tasks=[];
  const discord=site.discordWebhook||db.settings.discordWebhook;
  if(discord){
    try {
      const u=new URL(discord);
      if(u.protocol!=='https:'||!['discord.com','discordapp.com','canary.discord.com','ptb.discord.com'].includes(u.hostname)) throw Error('Discord webhook must use an official HTTPS Discord host');
      const r=await fetch(discord,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({content:msg}),signal:AbortSignal.timeout(5000)});
      if(!r.ok) tasks.push({channel:'discord',ok:false,error:`HTTP ${r.status}`}); else tasks.push({channel:'discord',ok:true});
    } catch(e){tasks.push({channel:'discord',ok:false,error:String(e.message).slice(0,200)});}
  }
  const token=db.settings.telegramToken,chat=db.settings.telegramChatId;
  if(token&&chat){
    try {
      const r=await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chat,text:msg}),signal:AbortSignal.timeout(5000)});
      const body=await r.json().catch(()=>({}));
      tasks.push({channel:'telegram',ok:r.ok&&body.ok===true,...(!r.ok||body.ok!==true?{error:String(body.description||`HTTP ${r.status}`).slice(0,200)}:{})});
    } catch(e){tasks.push({channel:'telegram',ok:false,error:String(e.message).slice(0,200)});}
  }
  if(db.settings.email){
    if(process.env.SMTP_HOST&&process.env.SMTP_FROM){
      try{
        const transport=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE||'false')==='true',auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS||''}:undefined,connectionTimeout:5000,greetingTimeout:5000,socketTimeout:8000});
        await transport.sendMail({from:process.env.SMTP_FROM,to:db.settings.email,subject:`ChangeWatch: ${event.summaryLine||event.summary}`,text:msg});tasks.push({channel:'email',ok:true});
      }catch(e){tasks.push({channel:'email',ok:false,error:String(e.message).slice(0,200)});}
    }else tasks.push({channel:'email',ok:false,error:'Email recipient configured, but SMTP_HOST and SMTP_FROM environment variables are missing'});
  }
  event.notifications=tasks;
  return tasks;
}
const lastRun=new Map(), domainLocks=new Map(), inFlight=new Map();
// Job records live in the configured application-state store. The runtime queue
// contains job IDs, so queued work can be reconstructed after a process restart.
const jobQueue=[];const jobWaiters=new Map();let activeJobs=0;const MAX_CONCURRENT_JOBS=Math.max(1,Number(process.env.MAX_CONCURRENT_JOBS)||2);
if(!Array.isArray(db.jobs))db.jobs=[];
for(const job of db.jobs){if(job.status==='running'||job.status==='queued'){job.status='queued';job.recoveredAt=Date.now();jobQueue.push(job.id);}}
if(jobQueue.length)save();
function trimJobs(){
  if(db.jobs.length>500) db.jobs=retainRecentJobs(db.jobs,500);
}
function pumpQueue(){
  while(activeJobs<MAX_CONCURRENT_JOBS&&jobQueue.length){
    const jobId=jobQueue.shift();
    const record=db.jobs.find(j=>j.id===jobId);
    if(!record||record.status!=='queued')continue;
    const site=db.sites.find(s=>s.id===record.siteId);
    if(!site||site.paused){record.status='cancelled';record.finishedAt=Date.now();save();continue;}
    activeJobs++;record.status='running';record.startedAt=Date.now();record.attempts=(record.attempts||0)+1;save();
    Promise.resolve().then(()=>runCheckSite(record.siteId)).then(result=>{
      record.status=record.cancelRequested||result&&result.skipped?'cancelled':'completed';record.resultStatus=result?.status||'ok';record.finishedAt=Date.now();record.error=null;
      const waiter=jobWaiters.get(record.id);if(waiter){waiter.resolve(result);jobWaiters.delete(record.id);}
    },error=>{
      record.status=record.cancelRequested?'cancelled':'failed';record.finishedAt=Date.now();record.error=record.cancelRequested?'Site deleted while the check was running':String(error?.message||error).slice(0,300);
      const waiter=jobWaiters.get(record.id);if(waiter){waiter.resolve({status:'error',error:record.error,jobId:record.id});jobWaiters.delete(record.id);}
    }).finally(()=>{
      activeJobs--;trimJobs();save();pumpQueue();
    });
  }
}
function checkSite(siteId){
  if(inFlight.has(siteId)) return inFlight.get(siteId);
  const work=new Promise(resolve=>{
    const job={id:id(),type:'site-check',siteId,status:'queued',createdAt:Date.now(),attempts:0};
    jobWaiters.set(job.id,{resolve});db.jobs.push(job);jobQueue.push(job.id);save();pumpQueue();
  }).finally(()=>inFlight.delete(siteId));
  inFlight.set(siteId,work);return work;
}
async function waitForDomain(host, delayMs){
  const previous=domainLocks.get(host)||Promise.resolve();
  let release;
  const current=new Promise(resolve=>{release=resolve;});
  domainLocks.set(host,previous.then(()=>current));
  await previous;
  try {
    const wait=Math.max(0,delayMs-(Date.now()-(lastRun.get(host)||0)));
    if(wait>0) await new Promise(resolve=>setTimeout(resolve,Math.min(wait,10000)));
    lastRun.set(host,Date.now());
  } finally { release(); }
}
async function runCheckSite(siteId, attempt = 0){
  const site=db.sites.find(s=>s.id===siteId);
  if(!site||site.paused)return {skipped:true};
  const host=new URL(site.url).hostname;
  await waitForDomain(host,Number(site.domainDelay||3000));
  let browser;
  try {
    const safe=await validateUrl(site.url);
    browser=await chromium.launch({headless:true});
    const page=await browser.newPage({viewport:{width:1280,height:800},deviceScaleFactor:1});
    page.setDefaultNavigationTimeout(20000);
    await page.route('**/*', async route => {
      try {
        const request=route.request();
        const requestUrl=request.url();
        if(!/^https?:/i.test(requestUrl))return route.abort();
        let hops=0, previous=request;
        while(previous.redirectedFrom()){hops++;previous=previous.redirectedFrom();}
        if(hops>MAX_REDIRECT_HOPS)return route.abort();
        await validateUrl(requestUrl);
        return route.continue();
      } catch { return route.abort(); }
    });
    const response=await page.goto(safe,{waitUntil:'domcontentloaded',timeout:20000});
    // Validate the final navigation URL too; redirect destinations must never bypass the SSRF guard.
    await validateUrl(page.url());
    await page.waitForTimeout(700);
    const status=response?.status()||0;
    const html=await page.content();
    const $=cheerio.load(html);
    $('script,style,noscript,svg,iframe,nav,footer,header,[aria-hidden="true"]').remove();
    // Apply ignored regions before reading text so the option actually affects the hash.
    if(site.ignoreSelector){try{$(site.ignoreSelector).remove();}catch{}}
    let text='';
    if(site.watchSelector){
      try { const selected=$(site.watchSelector); text=selected.length?selected.text():$('body').text(); }
      catch { text=$('body').text(); }
    } else text=$('body').text();
    text=cleanText(text);
    const blocked=status===403||status===429||/captcha|verify you are human|access denied|temporarily blocked|unusual traffic/i.test(text.slice(0,8000));
    const outage=status>=500||status===0;
    if(blocked||outage){
      site.lastChecked=Date.now();site.lastStatus=blocked?'blocked':'error';site.lastError=blocked?'Page appears blocked or requires CAPTCHA':`HTTP ${status||'navigation failure'}`;site.failureCount=(site.failureCount||0)+1;const backoff=Math.min(24*60,Math.max(site.interval,site.interval*Math.pow(2,Math.min(site.failureCount-1,6))));site.nextCheck=Date.now()+backoff*60000;site.runs=(site.runs||0)+1;site.health=Math.max(0,(site.health??100)-10);save();
      return {status:site.lastStatus,error:site.lastError,snapshot:null,event:null};
    }
    const hash=sha(text);
    const prior=db.snapshots.filter(s=>s.siteId===site.id).sort((a,b)=>b.createdAt-a.createdAt)[0];
    site.lastChecked=Date.now();site.lastStatus='ok';site.lastError=null;site.failureCount=0;site.health=Math.min(100,Math.round((site.health??100)*.9+10));site.nextCheck=Date.now()+site.interval*60000;site.runs=(site.runs||0)+1;
    if(prior&&prior.hash===hash){
      // Do not persist a new version or screenshot for identical content.
      site.unchanged=(site.unchanged||0)+1;
      if(site.adaptive&&site.unchanged>=3){site.adaptiveMultiplier=Math.min(4,Number(site.adaptiveMultiplier||1)*1.25);site.nextCheck=Date.now()+Math.min(1440,site.interval*site.adaptiveMultiplier)*60000;}
      save();return {snapshot:prior,event:null,status:site.lastStatus,unchanged:true,adaptiveMultiplier:site.adaptiveMultiplier||1};
    }
    site.unchanged=0;
    if(site.adaptive)site.adaptiveMultiplier=Math.max(1,Number(site.adaptiveMultiplier||1)*0.75);
    const screenshot=path.join(SHOTS,`${site.id}-${Date.now()}.png`);
    await page.screenshot({path:screenshot,fullPage:true,animations:'disabled',timeout:10000}).catch(()=>{});
    const snap={id:id(),siteId:site.id,url:site.url,status,hash,text:text.slice(0,200000),numbers:extractNumbers(text).slice(0,500),screenshot:fs.existsSync(screenshot)?path.relative(ROOT,screenshot):null,createdAt:Date.now(),blocked:false,outage:false};
    let event=null;
    if(prior&&shouldAlert(prior.hash,hash)){
      const diff=diffText(prior.text,text),sig=significance(diff,prior.text,text);
      const threshold=Math.max(0,Math.min(100,Number(site.sensitivity??db.settings.sensitivity??20)));
      const severity=sig.score>=80?'critical':sig.score>=60?'high':sig.score>=25?'medium':'low';
      const ruleResult=evaluateAlertRules({score:sig.score,severity,added:diff.added,removed:diff.removed,rules:site.alertRules||{},legacyKeywords:site.keywords||''});
      site.lastRuleEvaluation={time:Date.now(),allowed:ruleResult.allowed,reason:ruleResult.reason,matchedKeywords:ruleResult.matchedKeywords||[]};
      if(ruleResult.allowed&&sig.score>=threshold&&site.lastAlertHash!==hash){
        event={id:id(),siteId:site.id,oldSnapshotId:prior.id,newSnapshotId:snap.id,time:Date.now(),summary:`${diff.added.length} added and ${diff.removed.length} removed tokens`,severity,score:sig.score,explanation:sig.explanation,alertRuleEvaluation:ruleResult,diff,summaryLine:`${site.name}: ${summarizeChange(diff.added,diff.removed)}`,numbersBefore:prior.numbers||extractNumbers(prior.text),numbersAfter:snap.numbers,notifications:[]};
        db.events.unshift(event);site.lastAlertHash=hash;
        // Quiet hours suppress delivery but preserve the event in the feed.
        if(isQuietHours(db.settings)) {
          db.pendingNotifications.push({id:id(),siteId:site.id,eventId:event.id,queuedAt:Date.now(),attempts:0,nextAttempt:Date.now()});
        } else {
          event.notifications=await notify(site,event);
          if(event.notifications.some(n=>!n.ok)) db.pendingNotifications.push({id:id(),siteId:site.id,eventId:event.id,queuedAt:Date.now(),attempts:0,nextAttempt:Date.now()+60000});
        }
      }
    }
    db.snapshots.push(snap);
    if(db.snapshots.length>5000){const removed=db.snapshots.splice(0,db.snapshots.length-5000);const removedIds=new Set(removed.map(x=>x.id));db.events=db.events.filter(e=>!removedIds.has(e.oldSnapshotId)&&!removedIds.has(e.newSnapshotId));}
    if(event&&site.adaptive){site.adaptiveMultiplier=1;site.nextCheck=Date.now()+site.interval*60000;}
    save();return {snapshot:snap,event,status:site.lastStatus,unchanged:false};
  } catch(e) {
    if(attempt<2){if(browser)await browser.close().catch(()=>{});browser=null;await new Promise(r=>setTimeout(r,500*(attempt+1)));return runCheckSite(siteId,attempt+1);}
    site.lastChecked=Date.now();site.lastStatus='error';site.lastError=String(e.message).slice(0,300);site.failureCount=(site.failureCount||0)+1;site.health=Math.max(0,(site.health??100)-10);const backoff=Math.min(24*60,Math.max(site.interval,site.interval*Math.pow(2,Math.min(site.failureCount-1,6))));site.nextCheck=Date.now()+backoff*60000;site.runs=(site.runs||0)+1;save();return {error:site.lastError,status:'error'};
  } finally {if(browser)await browser.close().catch(()=>{});}
}
async function flushPendingNotifications(){
  if(isQuietHours(db.settings)||!db.pendingNotifications.length)return;
  const now=Date.now();
  for(const item of [...db.pendingNotifications]){
    if(item.nextAttempt>now)continue;
    const site=db.sites.find(s=>s.id===item.siteId),event=db.events.find(e=>e.id===item.eventId);
    if(!site||!event){db.pendingNotifications=db.pendingNotifications.filter(x=>x.id!==item.id);continue;}
    const results=await notify(site,event);item.attempts=(item.attempts||0)+1;item.lastAttempt=now;
    if(results.length&&results.every(x=>x.ok)){db.pendingNotifications=db.pendingNotifications.filter(x=>x.id!==item.id);event.notifications=results;}
    else if(item.attempts>=5){item.deadLetter=true;item.lastError='Maximum notification retry attempts reached';item.nextAttempt=Number.MAX_SAFE_INTEGER;}
    else {item.nextAttempt=now+Math.min(60,2**item.attempts)*60000;item.lastError=results.filter(x=>!x.ok).map(x=>`${x.channel}: ${x.error||'failed'}`).join('; ')||'No notification channel configured';}
  }
  save();
}
setInterval(()=>{flushPendingNotifications().catch(err=>console.error('Pending notification flush failed:',err.message));},60000).unref();
// Persistent interval scheduler; each page is isolated and interval is clamped to the task spec.
setInterval(()=>{for(const s of db.sites){if(!s.paused&&(!s.nextCheck||s.nextCheck<=Date.now()))checkSite(s.id);}},15000).unref();
app.get('/api/health',(req,res)=>res.json({ok:true,version:'1.2.0',sites:db.sites.length,snapshots:db.snapshots.length,events:db.events.length,uptime:process.uptime(),queue:{queued:jobQueue.length,active:activeJobs,coalesced:inFlight.size,maxConcurrent:MAX_CONCURRENT_JOBS},storage:storageLabel,queueDurability:queueDurabilityLabel}));
app.get('/api/diagnostics',(req,res)=>res.json({time:new Date().toISOString(),storage:{type:storageLabel,snapshots:db.snapshots.length,events:db.events.length,sites:db.sites.length},scheduler:{queued:jobQueue.length,active:activeJobs,maxConcurrent:MAX_CONCURRENT_JOBS,pendingNotifications:db.pendingNotifications.length,jobRecords:db.jobs.length,failedJobs:db.jobs.filter(j=>j.status==='failed').length},sites:db.sites.map(s=>({id:s.id,name:s.name,status:s.lastStatus,lastChecked:s.lastChecked||null,nextCheck:s.nextCheck||null,failureCount:s.failureCount||0,adaptive:!!s.adaptive,adaptiveMultiplier:s.adaptiveMultiplier||1})),recentFailures:db.sites.filter(s=>s.lastStatus==='error'||s.lastStatus==='blocked').slice(0,20).map(s=>({id:s.id,name:s.name,status:s.lastStatus,error:s.lastError||''}))}));
app.get('/api/data',(req,res)=>res.json({sites:db.sites.map(({lastAlertHash,discordWebhook,...s})=>({...s,discordWebhook:discordWebhook?'••••••configured':''})),snapshots:db.snapshots.map(({text,...s})=>s),events:db.events,settings:{...db.settings,telegramToken:db.settings.telegramToken?'••••••configured':'',discordWebhook:db.settings.discordWebhook?'••••••configured':''}}));
app.post('/api/sites',async(req,res)=>{try{const url=await validateUrl(String(req.body.url||''));const name=String(req.body.name||new URL(url).hostname).slice(0,100);const existing=db.sites.find(s=>s.url===url);if(existing)return res.status(409).json({error:'This URL is already monitored',site:existing});const site={id:id(),url,name,interval:Math.max(15,Math.min(1440,Number(req.body.interval)||15)),paused:false,createdAt:Date.now(),lastStatus:'pending',health:100,watchSelector:String(req.body.watchSelector||'').slice(0,300),ignoreSelector:String(req.body.ignoreSelector||'').slice(0,300),sensitivity:Math.max(0,Math.min(100,Number(req.body.sensitivity??db.settings.sensitivity??20))),keywords:String(req.body.keywords||'').slice(0,1000),adaptive:!!req.body.adaptive,alertRules:normalizeAlertRules(req.body.alertRules||{}),domainDelay:3000};db.sites.push(site);save();checkSite(site.id);res.status(201).json(site);}catch(e){res.status(400).json({error:e.message});}});
app.post('/api/sites/:id/check',async(req,res)=>{const s=db.sites.find(x=>x.id===req.params.id);if(!s)return res.status(404).json({error:'Site not found'});res.json(await checkSite(s.id));});
app.patch('/api/sites/:id',(req,res)=>{const s=db.sites.find(x=>x.id===req.params.id);if(!s)return res.status(404).json({error:'Site not found'});let patch;try{patch=validateSitePatch(req.body);}catch(e){return res.status(400).json({error:e.message});}if(patch.alertRules!==undefined)patch.alertRules=normalizeAlertRules(patch.alertRules);Object.assign(s,patch);save();res.json(s);});
app.delete('/api/sites/:id',(req,res)=>{
  const siteId=req.params.id;
  const site=db.sites.find(s=>s.id===siteId);
  if(!site)return res.status(404).json({error:'Site not found'});
  // Cancel queued checks immediately so deleted sites do not keep consuming queue slots.
  const cancelledIds=new Set();
  for(const job of db.jobs){
    if(job.siteId===siteId&&job.status==='queued'){
      job.status='cancelled';job.finishedAt=Date.now();job.error='Site deleted before the check started';cancelledIds.add(job.id);
      const waiter=jobWaiters.get(job.id);if(waiter){waiter.resolve({status:'cancelled',skipped:true,jobId:job.id});jobWaiters.delete(job.id);}
    }
    if(job.siteId===siteId&&job.status==='running')job.cancelRequested=true;
  }
  for(let i=jobQueue.length-1;i>=0;i--)if(cancelledIds.has(jobQueue[i]))jobQueue.splice(i,1);
  // Remove snapshot image files only when their resolved path is inside snapshots/.
  const siteSnapshots=db.snapshots.filter(s=>s.siteId===siteId);
  for(const snap of siteSnapshots){
    if(!snap.screenshot)continue;
    const file=path.resolve(ROOT,snap.screenshot);
    if(file.startsWith(path.resolve(SHOTS)+path.sep)){try{fs.unlinkSync(file);}catch(e){if(e.code!=='ENOENT')console.warn('Could not remove snapshot image:',e.message);}}
  }
  db.sites=db.sites.filter(s=>s.id!==siteId);
  db.snapshots=db.snapshots.filter(s=>s.siteId!==siteId);
  db.events=db.events.filter(e=>e.siteId!==siteId);
  db.pendingNotifications=db.pendingNotifications.filter(n=>n.siteId!==siteId);
  save();pumpQueue();res.json({ok:true,cancelledQueuedJobs:cancelledIds.size,removedSnapshots:siteSnapshots.length});
});
app.get('/api/sites/:id/snapshots',(req,res)=>res.json(db.snapshots.filter(s=>s.siteId===req.params.id).sort((a,b)=>b.createdAt-a.createdAt).map(({text,...s})=>s)));
app.get('/api/snapshots/:id',(req,res)=>{const s=db.snapshots.find(x=>x.id===req.params.id);if(!s)return res.status(404).json({error:'Snapshot not found'});res.json(s);});
app.get('/api/snapshots/:id/screenshot',(req,res)=>{const s=db.snapshots.find(x=>x.id===req.params.id);if(!s||!s.screenshot)return res.status(404).json({error:'Screenshot not found'});const file=path.resolve(ROOT,s.screenshot);if(!file.startsWith(path.resolve(SHOTS)+path.sep)||!fs.existsSync(file))return res.status(404).json({error:'Screenshot not found'});res.sendFile(file);});
app.get('/api/analytics/numbers',(req,res)=>{
  const siteId=String(req.query.siteId||'');
  const limit=Math.max(1,Math.min(500,Number(req.query.limit)||200));
  const rows=db.snapshots.filter(s=>(!siteId||s.siteId===siteId)&&!s.demo).sort((a,b)=>a.createdAt-b.createdAt).flatMap(s=>(s.numbers||extractNumbers(s.text||'')).map(n=>({siteId:s.siteId,siteName:db.sites.find(x=>x.id===s.siteId)?.name||'Deleted website',snapshotId:s.id,time:s.createdAt,value:n.value,numericValue:Number(String(n.value).replace(/[^0-9.-]/g,'')),index:n.index}))).slice(-limit);
  res.json({items:rows,sites:db.sites.map(s=>({id:s.id,name:s.name})),note:'Numeric extraction is heuristic; values may include unrelated numbers and mixed units should not be compared directly.'});
});
app.get('/api/lab/benchmark',(req,res)=>res.json(runReliabilityBenchmark()));
app.get('/api/lab/scenarios',(req,res)=>res.json({scenarios:[{id:'price-change',name:'Price change',description:'Simulate a meaningful price increase.'},{id:'rotating-ad',name:'Rotating advertisement',description:'Simulate noisy rotating banner text that should be normalized/ignored.'},{id:'outage',name:'Website outage',description:'Record a controlled outage state without making an external request.'},{id:'burst',name:'Simultaneous monitor burst',description:'Exercise queue coalescing using repeated requests for a demo monitor.'}],safe:true,warning:'All scenarios are synthetic and marked as demo data; they do not fetch or alter external websites.'}));
app.post('/api/lab/run',(req,res)=>{
  const allowed=new Set(['price-change','rotating-ad','outage','burst']);const scenario=String(req.body.scenario||'price-change');if(!allowed.has(scenario))return res.status(400).json({error:'Unknown scenario',allowed:[...allowed]});
  let site=db.sites.find(s=>s.demo&&s.labScenario===scenario);if(!site){site={id:id(),url:'https://example.invalid/'+scenario,name:'Reliability Lab: '+scenario,interval:15,paused:true,createdAt:Date.now(),lastStatus:'ok',health:100,watchSelector:'',ignoreSelector:'',keywords:'',adaptive:false,demo:true,labScenario:scenario,runs:0};db.sites.push(site);}
  const now=Date.now();const old=db.snapshots.filter(s=>s.siteId===site.id).sort((a,b)=>b.createdAt-a.createdAt)[0];
  if(scenario==='outage'){site.lastStatus='error';site.lastError='Simulated outage (Reliability Lab)';site.lastChecked=now;site.health=Math.max(0,(site.health??100)-15);site.runs=(site.runs||0)+1;db.events.unshift({id:id(),siteId:site.id,time:now,summary:'Simulated outage',summaryLine:'Reliability Lab: simulated website outage',severity:'high',score:85,explanation:'Controlled test scenario; no external request was made.',demo:true,scenario});save();return res.json({ok:true,scenario,site,event:db.events[0],synthetic:true});}
  const texts={'price-change':'Product Alpha price $100 in stock','rotating-ad':'Product Alpha price $100 in stock rotating banner offer '+(Math.floor(now/60000)%2?'A':'B'),'burst':'Reliability Lab burst test version '+Math.floor(now/1000)};const text=texts[scenario];const hash=sha(text);if(old&&old.hash===hash){save();return res.json({ok:true,scenario,site,unchanged:true,synthetic:true});}
  const snap={id:id(),siteId:site.id,url:site.url,status:200,hash,text,numbers:extractNumbers(text),screenshot:null,createdAt:now,blocked:false,outage:false,demo:true,synthetic:true};db.snapshots.push(snap);let event=null;if(old){const d=diffText(old.text,text),sig=significance(d,old.text,text);event={id:id(),siteId:site.id,oldSnapshotId:old.id,newSnapshotId:snap.id,time:now,summary:summarizeChange(d.added,d.removed),summaryLine:scenario==='price-change'?'Reliability Lab: product price changed':scenario==='rotating-ad'?'Reliability Lab: rotating banner variation':'Reliability Lab: burst test version changed',severity:sig.score>=60?'high':sig.score>=30?'medium':'low',score:sig.score,explanation:sig.explanation,diff:d,demo:true,synthetic:true,scenario};db.events.unshift(event);}site.lastStatus='ok';site.lastError=null;site.lastChecked=now;site.runs=(site.runs||0)+1;save();res.json({ok:true,scenario,site,snapshot:snap,event,synthetic:true});
});
app.get('/api/export/config.json',(req,res)=>{res.setHeader('Content-Disposition','attachment; filename=\"changewatch-config.json\"');res.json(buildConfigExport(db));});
app.post('/api/import/config.json',async(req,res)=>{
  let imported;try{imported=validateConfigImport(req.body);}catch(e){return res.status(400).json({error:e.message});}
  const existing=new Set(db.sites.map(s=>s.url));const added=[];const skipped=[];
  for(const candidate of imported.sites){
    try{
      const safeUrl=await validateUrl(candidate.url);
      if(existing.has(safeUrl)){skipped.push({url:safeUrl,reason:'already monitored'});continue;}
      const site={id:id(),url:safeUrl,name:candidate.name,interval:candidate.interval,paused:candidate.paused,createdAt:Date.now(),lastStatus:'pending',health:100,watchSelector:candidate.watchSelector,ignoreSelector:candidate.ignoreSelector,sensitivity:candidate.sensitivity,keywords:candidate.keywords,adaptive:candidate.adaptive,alertRules:normalizeAlertRules(candidate.alertRules||{}),domainDelay:3000};
      db.sites.push(site);existing.add(safeUrl);added.push(site.id);
    }catch(e){skipped.push({url:candidate.url,reason:String(e.message).slice(0,180)});}
  }
  for(const [key,value] of Object.entries(imported.settings))db.settings[key]=value;
  save();for(const siteId of added){const site=db.sites.find(s=>s.id===siteId);if(site&&!site.paused)checkSite(siteId);}
  res.status(200).json({ok:true,added:added.length,skipped,settingsImported:Object.keys(imported.settings).length,secretsImported:false});
});
app.get('/api/events',(req,res)=>{let e=db.events;if(req.query.q)e=e.filter(x=>(x.summary+' '+(x.summaryLine||'')+' '+(x.explanation||'')).toLowerCase().includes(String(req.query.q).toLowerCase()));if(req.query.severity)e=e.filter(x=>x.severity===req.query.severity);res.json(e);});
app.get('/api/export/numbers.csv',(req,res)=>{const rows=[['site','url','snapshot_time','value','index'],...db.snapshots.flatMap(s=>(s.numbers||extractNumbers(s.text||'')).map(n=>[db.sites.find(x=>x.id===s.siteId)?.name||'',s.url,new Date(s.createdAt).toISOString(),n.value,n.index]))];const csv=rows.map(row=>row.map(v=>'"'+String(v??'').replace(/"/g,'""')+'"').join(',')).join('\\n');res.setHeader('Content-Disposition','attachment; filename="changewatch-number-history.csv"');res.type('text/csv').send(csv);});
app.get('/api/export/:format',(req,res)=>{const format=req.params.format;if(format==='json'){res.setHeader('Content-Disposition','attachment; filename="changewatch-export.json"');return res.json({sites:db.sites.map(({discordWebhook,...s})=>({...s,discordWebhook:discordWebhook?'••••••configured':''})),snapshots:db.snapshots.map(({text,...s})=>s),events:db.events});}if(format==='csv'){const esc=x=>'"'+String(x??'').replace(/"/g,'""')+'"';const rows=[['time','site','url','severity','score','summary'],...db.events.map(e=>[new Date(e.time).toISOString(),db.sites.find(s=>s.id===e.siteId)?.name,e.siteId,e.severity,e.score,e.summary])];res.setHeader('Content-Disposition','attachment; filename="changewatch-events.csv"');res.type('text/csv').send(rows.map(r=>r.map(esc).join(',')).join('\n'));return;}res.status(400).json({error:'Use json or csv'});});
app.get('/api/rss.xml',(req,res)=>{const items=db.events.slice(0,50).map(e=>`<item><title>${xml(e.summaryLine)}</title><link>${xml(db.sites.find(s=>s.id===e.siteId)?.url||'')}</link><description>${xml(e.explanation)}</description><pubDate>${new Date(e.time).toUTCString()}</pubDate><guid>${e.id}</guid></item>`).join('');res.type('application/rss+xml').send(`<?xml version="1.0"?><rss version="2.0"><channel><title>ChangeWatch Pro</title><description>Website change feed</description><link>http://localhost:${PORT}</link>${items}</channel></rss>`);});
app.get('/api/sites/:id/rss.xml',(req,res)=>{const site=db.sites.find(s=>s.id===req.params.id);if(!site)return res.status(404).type('text').send('Website not found');const items=db.events.filter(e=>e.siteId===site.id).slice(0,100).map(e=>`<item><title>${xml(e.summaryLine||e.summary)}</title><link>${xml(site.url)}</link><description>${xml(e.explanation||e.summary)}</description><pubDate>${new Date(e.time).toUTCString()}</pubDate><guid>${xml(e.id)}</guid></item>`).join('');res.type('application/rss+xml').send(`<?xml version="1.0"?><rss version="2.0"><channel><title>${xml(site.name)} — ChangeWatch Pro</title><description>Changes for ${xml(site.name)}</description><link>${xml(site.url)}</link>${items}</channel></rss>`);});
function xml(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');}
app.put('/api/settings',(req,res)=>{let patch;try{patch=validateSettingsPatch(req.body);}catch(e){return res.status(400).json({error:e.message});}Object.assign(db.settings,patch);save();res.json({ok:true,settings:{...db.settings,telegramToken:db.settings.telegramToken?'••••••configured':'',discordWebhook:db.settings.discordWebhook?'••••••configured':''}});});
app.get('/api/compare/:oldId/:newId',(req,res)=>{const a=db.snapshots.find(s=>s.id===req.params.oldId),b=db.snapshots.find(s=>s.id===req.params.newId);if(!a||!b)return res.status(404).json({error:'Snapshot not found'});if(a.siteId!==b.siteId)return res.status(400).json({error:'Snapshots must belong to the same monitored website'});const d=diffText(a.text,b.text),sig=significance(d,a.text,b.text);res.json({old:{id:a.id,siteId:a.siteId,createdAt:a.createdAt,screenshot:!!a.screenshot},new:{id:b.id,siteId:b.siteId,createdAt:b.createdAt,screenshot:!!b.screenshot},diff:d,significance:sig,explanation:explainChange(d,a.text,b.text),numbers:{old:(a.numbers||extractNumbers(a.text||'')).slice(0,100),new:(b.numbers||extractNumbers(b.text||'')).slice(0,100)}});});
app.post('/api/demo/reset',(req,res)=>{db.sites=db.sites.filter(s=>!s.demo);db.snapshots=db.snapshots.filter(s=>!s.demo);db.events=db.events.filter(s=>!s.demo);save();res.json({ok:true});});
app.post('/api/demo',(req,res)=>{let site=db.sites.find(s=>s.demo);if(!site){site={id:id(),url:'https://example.com/',name:'Demo: Example Site',interval:15,paused:true,createdAt:Date.now(),lastStatus:'ok',health:99,watchSelector:'',ignoreSelector:'',keywords:'',adaptive:false,demo:true,runs:3};db.sites.push(site);}let old=db.snapshots.find(s=>s.siteId===site.id);if(!old){old={id:id(),siteId:site.id,url:site.url,status:200,hash:sha('Welcome to Example. Pricing is $10.'),text:'Welcome to Example. Pricing is $10. Our launch date is June 12.',screenshot:null,createdAt:Date.now()-3600000,blocked:false,outage:false,demo:true};db.snapshots.push(old);}const text='Welcome to Example. Pricing is $12. Our launch date is June 14. New feature: team alerts.';const snap={id:id(),siteId:site.id,url:site.url,status:200,hash:sha(text+Date.now()),text,screenshot:null,createdAt:Date.now(),blocked:false,outage:false,demo:true};const d=diffText(old.text,text),sig=significance(d,old.text,text);const event={id:id(),siteId:site.id,oldSnapshotId:old.id,newSnapshotId:snap.id,time:Date.now(),summary:`${d.added.length} added and ${d.removed.length} removed tokens`,severity:'medium',score:sig.score,explanation:sig.explanation,diff:d,summaryLine:'Demo: price and launch date updated',demo:true};db.snapshots.push(snap);db.events.unshift(event);site.lastChecked=Date.now();site.lastStatus='ok';site.health=99;save();res.json({site,snapshot:snap,event});});
cron.schedule('0 9 * * *',async()=>{
  if(!db.settings.digest)return;
  const since=Date.now()-24*60*60*1000;const recent=db.events.filter(e=>e.time>=since&&!e.demo);
  if(!recent.length)return;
  const lines=recent.slice(0,100).map(e=>`• ${e.summaryLine||e.summary} — ${db.sites.find(s=>s.id===e.siteId)?.url||''}`);
  const message=`ChangeWatch Pro daily digest: ${recent.length} change event(s) in the last 24 hours.\n\n${lines.join('\n')}`;
  const tasks=[];
  const webhook=db.settings.discordWebhook;
  if(webhook){try{const u=new URL(webhook);if(u.protocol!=='https:'||!['discord.com','discordapp.com','canary.discord.com','ptb.discord.com'].includes(u.hostname))throw Error('Invalid Discord webhook host');const r=await fetch(webhook,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({content:message.slice(0,1900)}),signal:AbortSignal.timeout(5000)});tasks.push({channel:'discord',ok:r.ok,...(!r.ok?{error:`HTTP ${r.status}`}:{})});}catch(e){tasks.push({channel:'discord',ok:false,error:e.message});}}
  if(db.settings.telegramToken&&db.settings.telegramChatId){try{const r=await fetch(`https://api.telegram.org/bot${db.settings.telegramToken}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:db.settings.telegramChatId,text:message.slice(0,4000)}),signal:AbortSignal.timeout(5000)});const b=await r.json().catch(()=>({}));tasks.push({channel:'telegram',ok:r.ok&&b.ok===true,...(!(r.ok&&b.ok===true)?{error:b.description||`HTTP ${r.status}`}:{})});}catch(e){tasks.push({channel:'telegram',ok:false,error:e.message});}}
  if(db.settings.email&&process.env.SMTP_HOST&&process.env.SMTP_FROM){try{const t=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE||'false')==='true',auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS||''}:undefined});await t.sendMail({from:process.env.SMTP_FROM,to:db.settings.email,subject:'ChangeWatch Pro daily digest',text:message});tasks.push({channel:'email',ok:true});}catch(e){tasks.push({channel:'email',ok:false,error:e.message});}}
  db.reports.unshift({id:id(),type:'daily-digest',time:Date.now(),eventCount:recent.length,deliveries:tasks});db.reports=db.reports.slice(0,100);save();
},{timezone:process.env.TZ||'Asia/Kolkata'});
app.get('/api/reports',(req,res)=>res.json(db.reports||[]));
// Keep malformed/oversized API requests JSON-formatted and never leak internal errors.
app.use(apiErrorHandler);
app.get('*',(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
if(process.env.NODE_ENV==='production'&&(!AUTH_USER||!AUTH_PASSWORD)){console.error('Refusing production startup without CW_AUTH_USER and CW_AUTH_PASSWORD.');process.exit(1);}
const server = app.listen(PORT,'0.0.0.0',()=>console.log(`ChangeWatch Pro running at http://localhost:${PORT} (storage: ${storageMode})`));
function shutdown(){ server.close(()=>{ if(sqliteStorage) sqliteStorage.close(); process.exit(0); }); }
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
