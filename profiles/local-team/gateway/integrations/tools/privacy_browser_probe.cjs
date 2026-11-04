'use strict';

const fs = require('node:fs');
const MAX_INPUT_BYTES = 16 * 1024;
const TOTAL_TIMEOUT_MS = 60_000;
const SYNTHETIC_ORIGIN = 'https://privacy-audit.invalid/';
const DNS_TEST_ID_PATTERN = /^[a-z0-9]{6,64}$/;
const FIXED = Object.freeze({
  tor: 'https://check.torproject.org/api/ip',
  ipv4: 'https://api.ipify.org?format=json',
  ipv6: 'https://api6.ipify.org?format=json',
});

function codedError(code) { const error = new Error(code); error.code = code; return error; }
function normalizeUrl(raw) {
  try { const u = new URL(raw); if (u.protocol !== 'https:' || u.username || u.password || u.port || u.hash) return null; return `${u.origin}${u.pathname}${u.search}`; }
  catch { return null; }
}
function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw codedError('INVALID_INPUT');
  for (const key of ['module_path','executable_path','proxy_server','scope']) if (typeof input[key] !== 'string' || !input[key] || input[key].length > 4096) throw codedError('INVALID_INPUT');
  if (!fs.existsSync(input.module_path) || !fs.existsSync(input.executable_path)) throw codedError('DEPENDENCY_UNAVAILABLE');
  let proxy; try { proxy = new URL(input.proxy_server); } catch { throw codedError('INVALID_PROXY'); }
  if (!['http:','https:','socks5:'].includes(proxy.protocol) || proxy.username || proxy.password || proxy.search || proxy.hash) throw codedError('INVALID_PROXY');
  const bypass = input.proxy_bypass ?? [];
  if (!Array.isArray(bypass) || bypass.length > 16 || bypass.some((v) => typeof v !== 'string' || v.length > 255)) throw codedError('INVALID_PROXY');
  if (input.webrtc_policy && input.webrtc_policy !== 'disable_non_proxied_udp') throw codedError('INVALID_INPUT');
  let dnsHost = null;
  if (input.dns_test_id !== undefined && input.dns_test_id !== null && input.dns_test_id !== '') {
    if (typeof input.dns_test_id !== 'string' || !DNS_TEST_ID_PATTERN.test(input.dns_test_id)) throw codedError('INVALID_DNS_TEST_ID');
    dnsHost = `1.${input.dns_test_id}.bash.ws`;
  }
  return { ...input, proxy_bypass:bypass, dns_host:dnsHost };
}
function errorCode(error) {
  const c=String(error?.code||error?.name||'REQUEST_FAILED').toUpperCase();
  if(c.includes('TIMEOUT'))return c==='TOTAL_TIMEOUT'?c:'TIMEOUT'; if(c.includes('ABORT'))return 'ERR_ABORTED'; if(c.includes('JSON'))return 'INVALID_JSON'; if(c.includes('NAVIGATION'))return 'NAVIGATION_TIMEOUT';
  return ['ERR_TIMED_OUT','REQUEST_FAILED','NET_ERROR','HTTP_ERROR','TOTAL_TIMEOUT','DEPENDENCY_UNAVAILABLE','INVALID_INPUT','INVALID_PROXY','INVALID_DNS_TEST_ID'].includes(c)?c:'REQUEST_FAILED';
}
function routeClass(raw,dnsHost) {
  const n=normalizeUrl(raw); if(!n)return 'blocked';
  if([FIXED.tor,FIXED.ipv4,'https://api.ipify.org/?format=json',FIXED.ipv6,'https://api6.ipify.org/?format=json'].includes(n))return 'fixed';
  if(n===SYNTHETIC_ORIGIN||n===`${SYNTHETIC_ORIGIN}?fixture=dns`)return 'synthetic';
  if(dnsHost&&/^https:\/\/[1-3]\.[a-z0-9]{6,64}\.bash\.ws\/$/.test(n)) {
    const host=new URL(n).hostname; if(host.endsWith(`.${dnsHost.split('.').slice(1).join('.')}`))return 'dns';
  }
  return 'blocked';
}
function syntheticHtml(dnsHost) {
  const names=dnsHost?[1,2,3].map((n)=>`${n}.${dnsHost.split('.').slice(1).join('.')}`):[];
  return `<!doctype html><meta charset="utf-8"><title>Local probe</title><script>
  window.__dnsProbe=async()=>{const names=${JSON.stringify(names)};const results=await Promise.all(names.map(async host=>{try{await fetch('https://'+host+'/',{mode:'no-cors',cache:'no-store',signal:AbortSignal.timeout(8000)})}catch(_){}return host}));return {attempted:results.length}};
</script>`;
}
function parseCandidate(c) {
  if(c&&typeof c==='object'&&typeof c.address==='string')return {address:c.address,type:typeof c.type==='string'?c.type:'unknown',protocol:typeof c.protocol==='string'?c.protocol:'unknown'};
  const line=typeof c==='string'?c:c?.candidate; if(typeof line!=='string')return null;
  const p=line.trim().split(/\s+/),i=p.indexOf('typ'); if(p.length<8)return null;
  return {address:p[4],type:i>=0?p[i+1]:'unknown',protocol:p[2]||'unknown'};
}
function outputLine(x){process.stdout.write(JSON.stringify(x)+String.fromCharCode(10));}
async function readInput(){return new Promise((resolve,reject)=>{const chunks=[];let size=0;process.stdin.on('data',(c)=>{size+=c.length;if(size>MAX_INPUT_BYTES){reject(codedError('INVALID_INPUT'));process.stdin.pause();return;}chunks.push(c);});process.stdin.on('error',()=>reject(codedError('INVALID_INPUT')));process.stdin.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/,'')));}catch{reject(codedError('INVALID_INPUT'));}});});}
async function endpoint(context,url){const page=await context.newPage();try{const r=await page.goto(url,{waitUntil:'domcontentloaded',timeout:20_000});if(!r||!r.ok())throw codedError('HTTP_ERROR');return {status:'observed',data:await r.json()};}catch(e){return {status:'failed',error_code:errorCode(e)};}finally{await page.close().catch(()=>{});}}
async function syntheticPage(context,dnsHost){const page=await context.newPage();await page.route(SYNTHETIC_ORIGIN+'**',async(route)=>{const req=route.request();if(req.redirectedFrom())return route.abort('blockedbyclient');if(routeClass(req.url(),dnsHost)!=='synthetic'||req.resourceType()!=='document')return route.abort('blockedbyclient');return route.fulfill({status:200,contentType:'text/html; charset=utf-8',body:syntheticHtml(req.url().includes('fixture=dns')?dnsHost:null)});});return page;}
async function dnsProbe(context,dnsHost){if(!dnsHost)return {attempted:0,status:'unavailable',error_code:'INVALID_DNS_TEST_ID'};let page;try{page=await syntheticPage(context,dnsHost);await page.goto(`${SYNTHETIC_ORIGIN}?fixture=dns`,{waitUntil:'domcontentloaded',timeout:5000});const r=await page.evaluate(()=>window.__dnsProbe());return {attempted:r.attempted,status:'attempted'};}catch(e){return {attempted:0,status:'failed',error_code:errorCode(e)};}finally{if(page)await page.close().catch(()=>{});}}
async function webrtcProbe(context){let page;try{page=await syntheticPage(context,null);await page.goto(SYNTHETIC_ORIGIN,{waitUntil:'domcontentloaded',timeout:5000});return await page.evaluate(async()=>{
  if(typeof RTCPeerConnection!=='function')return {status:'unavailable',candidates:[],errors:[],gathering_state:'unavailable'};
  const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'}]}),candidates=[],errors=[];
  pc.onicecandidate=({candidate})=>{if(!candidate)return;const parsed=candidate.toJSON?.()||candidate;const found=(()=>{if(typeof parsed.address==='string')return {address:parsed.address,type:parsed.type||'unknown',protocol:parsed.protocol||'unknown'};const words=(parsed.candidate||'').trim().split(/\s+/),i=words.indexOf('typ');return words.length>=8?{address:words[4],type:i>=0?words[i+1]:'unknown',protocol:words[2]||'unknown'}:null;})();if(found)candidates.push(found);};
  pc.onicecandidateerror=e=>{if(Number.isInteger(e.errorCode))errors.push(e.errorCode);};pc.createDataChannel('probe');
  const done=new Promise(resolve=>{pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete')resolve('complete');};});
  try{await pc.setLocalDescription(await pc.createOffer());const status=await Promise.race([done,new Promise(resolve=>setTimeout(()=>resolve('timeout'),12_000))]);return {status,candidates,errors,gathering_state:pc.iceGatheringState};}catch(_){return {status:'unavailable',candidates,errors,gathering_state:pc.iceGatheringState};}finally{pc.close();}
});}catch(e){return {status:'unavailable',candidates:[],errors:[],gathering_state:errorCode(e)};}finally{if(page)await page.close().catch(()=>{});}}
async function installRoutes(context,dnsHost){await context.route('**/*',async(route)=>{const req=route.request();if(req.redirectedFrom())return route.abort('blockedbyclient');const kind=routeClass(req.url(),dnsHost);if(kind==='fixed'||kind==='dns')return route.continue();if(kind==='synthetic'&&req.resourceType()==='document')return route.fulfill({status:200,contentType:'text/html; charset=utf-8',body:syntheticHtml(new URL(req.url()).search==='?fixture=dns'?dnsHost:null)});return route.abort('blockedbyclient');});}
async function launchProbeBrowser(target, playwright, options) {
  if (!target.webrtc_policy) return {browser:await playwright.chromium.launch(options)};
  const path=require('node:path'),os=require('node:os');
  const tempRoot=fs.realpathSync(os.tmpdir());
  const profile=fs.mkdtempSync(path.join(tempRoot,'artex-privacy-probe-'));
  fs.mkdirSync(path.join(profile,'Default'));
  fs.writeFileSync(path.join(profile,'Default','Preferences'),JSON.stringify({webrtc:{ip_handling_policy:target.webrtc_policy}}),{mode:0o600,flag:'wx'});
  try {
    const persistent=await playwright.chromium.launchPersistentContext(profile,options);
    return {browser:persistent.browser(),persistent,profile,tempRoot};
  } catch(error) { removeProbeProfile(profile,tempRoot);throw error; }
}
function removeProbeProfile(profile,tempRoot) {
  const path=require('node:path');
  const actual=fs.realpathSync(profile);
  if(actual!==profile||path.dirname(actual)!==tempRoot||!path.basename(actual).startsWith('artex-privacy-probe-')||fs.lstatSync(profile).isSymbolicLink())throw codedError('INVALID_INPUT');
  fs.rmSync(actual,{recursive:true,force:true});
}
async function closeProbeBrowser(owned) {
  try { if(owned.persistent)await owned.persistent.close();else await owned.browser.close(); }
  finally { if(owned.profile)removeProbeProfile(owned.profile,owned.tempRoot); }
}
async function run(input){
  const started=Date.now(),target=validateInput(input),playwright=require(target.module_path);
  if(!playwright.chromium||typeof playwright.chromium.launch!=='function')throw codedError('DEPENDENCY_UNAVAILABLE');
  const launchRemaining=Math.max(1,Math.min(15_000,TOTAL_TIMEOUT_MS-(Date.now()-started)));
  const owned=await launchProbeBrowser(target,playwright,{headless:true,executablePath:target.executable_path,proxy:{server:target.proxy_server,bypass:target.proxy_bypass.length?target.proxy_bypass.join(','):undefined},timeout:launchRemaining});
  const browser=owned.browser;
  const contexts=[];
  try{
    const jsonContext=await browser.newContext({javaScriptEnabled:false,serviceWorkers:'block'});contexts.push(jsonContext);jsonContext.setDefaultNavigationTimeout(20_000);await installRoutes(jsonContext,target.dns_host);
    const syntheticContext=await browser.newContext({serviceWorkers:'block'});contexts.push(syntheticContext);syntheticContext.setDefaultNavigationTimeout(20_000);await installRoutes(syntheticContext,target.dns_host);
    let timer;const remaining=Math.max(1,TOTAL_TIMEOUT_MS-(Date.now()-started));
    try{const vals=await Promise.race([Promise.all([endpoint(jsonContext,FIXED.ipv4),endpoint(jsonContext,FIXED.ipv6),endpoint(jsonContext,FIXED.tor),dnsProbe(syntheticContext,target.dns_host),webrtcProbe(syntheticContext)]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(codedError('TOTAL_TIMEOUT')),remaining);})]);const [ipv4,ipv6,tor,dns,webrtc]=vals;return {scope:target.scope,browser_version:browser.version(),ipv4,ipv6,tor,dns,webrtc};}
    finally{clearTimeout(timer);}
  }finally{for(const c of contexts)await c.close().catch(()=>{});await closeProbeBrowser(owned);}
}
async function testFixture(input){
  const target=validateInput(input);const playwright=require(target.module_path),browser=await playwright.chromium.launch({headless:true,executablePath:target.executable_path,proxy:{server:target.proxy_server,bypass:target.proxy_bypass.length?target.proxy_bypass.join(','):undefined},timeout:15_000});let context;
  try{context=await browser.newContext({serviceWorkers:'block'});await installRoutes(context,target.dns_host);const page=await context.newPage();const observed={synthetic:false,blocked:false,rtcp_available:false,candidate_parse:null,fixture_only:true};
    page.on('requestfailed',req=>{if(req.url()==='https://example.com/'){observed.blocked=true;}});
    await page.goto(SYNTHETIC_ORIGIN,{waitUntil:'domcontentloaded',timeout:5000});observed.synthetic=await page.title()==='Local probe';observed.rtcp_available=await page.evaluate(()=>typeof RTCPeerConnection==='function');
    await page.evaluate(()=>fetch('https://example.com/').catch(()=>{}));await page.waitForTimeout(150);observed.blocked=observed.blocked||await page.evaluate(()=>performance.getEntriesByName('https://example.com/').length===0);
    observed.candidate_parse=parseCandidate('candidate:1 1 udp 2122260223 192.0.2.7 54321 typ host');await page.close();return observed;
  }finally{if(context)await context.close().catch(()=>{});await browser.close().catch(()=>{});}
}
(async()=>{let input;try{input=await readInput();if(process.env.PRIVACY_PROBE_TEST_HELPER==='1'){const mode=process.env.PRIVACY_PROBE_TEST_MODE||'validate';if(mode==='fixture')outputLine({test_only:true,fixture:await testFixture(input)});else{const t=validateInput(input);outputLine({test_only:true,dns_host:t.dns_host,route_classes:{ipv4:routeClass(FIXED.ipv4,t.dns_host),normalized_ipv4:routeClass('https://api.ipify.org/?format=json',t.dns_host),tor:routeClass(FIXED.tor,t.dns_host),dns:t.dns_host?routeClass(`https://1.${t.dns_host.split('.').slice(1).join('.')}/`,t.dns_host):'blocked',other:routeClass('https://example.com/',t.dns_host)},candidate_parse:parseCandidate('candidate:1 1 udp 2122260223 192.0.2.7 54321 typ host')});}return;}outputLine(await run(input));}catch(e){const code=errorCode(e);if(process.env.PRIVACY_PROBE_TEST_HELPER==='1')outputLine({test_only:true,error_code:code});else outputLine({scope:typeof input?.scope==='string'?input.scope:'',browser_version:'',ipv4:{status:'failed',error_code:code},ipv6:{status:'failed',error_code:code},tor:{status:'failed',error_code:code},dns:{attempted:0,status:'failed',error_code:code},webrtc:{status:'unavailable',candidates:[],errors:[],gathering_state:code}});process.exitCode=1;}})();