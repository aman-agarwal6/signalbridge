/** Local/server-side only. No browser or serverless persistence assumptions. */
import { createHmac,createHash,randomUUID } from "node:crypto";
import { mkdir,open,readFile,readdir,rename,unlink } from "node:fs/promises";
import { join } from "node:path";
export const sign=(secret,app,key,time,body)=>createHmac("sha256",secret).update(`signalbridge.v1\n${app}\n${key}\n${time}\n`).update(body).digest("hex");
export const pseudonym=(secret,app,id)=>createHmac("sha256",secret).update(app+"\n"+id).digest("hex");
const fields=["schema_version","event_id","app","environment","occurred_at","actor","resource","episode","operation","outcome","reason","context"].sort();
const MAX_RECEIPT_BYTES = 1024;

async function receipt(response, eventId) {
 const reader = response.body?.getReader();
 if (!reader) throw Error("Missing collector receipt.");
 const chunks = [];
 let size = 0;
 try {
  while (true) {
   const { done, value } = await reader.read();
   if (done) break;
   size += value.byteLength;
   if (size > MAX_RECEIPT_BYTES) throw Error("Collector receipt exceeds its limit.");
   chunks.push(value);
  }
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size)));
  if (!value || !["accepted", "duplicate"].includes(value.status) || value.event_id !== eventId) {
   throw Error("Invalid collector receipt.");
  }
 } finally {
  // Release an oversized, invalid or completed response so connections can be reused.
  try { await reader.cancel(); } catch {}
  reader.releaseLock();
 }
}
async function persistedRecord(file,filename,app){
 const fd=await open(file,"r");let raw;
 try{if((await fd.stat()).size>65536)throw Error("Invalid outbox record.");raw=await fd.readFile("utf8");}finally{await fd.close();}
 const record=JSON.parse(raw);
 if(!record||Object.keys(record).sort().join()!=="attempts,body,hash,nextAt,state"||
   typeof record.body!=="string"||Buffer.byteLength(record.body)>16384||
   typeof record.hash!=="string"||!/^[a-f0-9]{64}$/.test(record.hash)||
   createHash("sha256").update(record.body).digest("hex")!==record.hash||
   !Number.isSafeInteger(record.attempts)||record.attempts<0||record.attempts>8||
   !Number.isSafeInteger(record.nextAt)||record.nextAt<0||!["pending","dead"].includes(record.state))throw Error("Invalid outbox record.");
 const event=JSON.parse(record.body);assertMetadata(event,app);
 if(filename!==event.event_id+".json")throw Error("Invalid outbox identity.");
 return record;
}
function assertMetadata(e,app){
 if(!e||Object.keys(e).sort().join()!==fields.join()||e.schema_version!==1||e.app!==app||!["lab","test"].includes(e.environment))throw Error("Invalid metadata contract.");
 for(const k of ["event_id","episode"])if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(e[k]))throw Error("Invalid identifier.");
 for(const k of ["actor","resource"])if(!/^[a-f0-9]{64}$/.test(e[k]))throw Error("Pseudonymous identifiers required.");
 if(!["private_record.read","membership.change","session.verify"].includes(e.operation)||!["allowed","denied","not_visible","error"].includes(e.outcome)||
 !["member","owner","membership_required","membership_removed","resource_unavailable","session_invalid","mfa_required","dependency_unavailable","policy_regression"].includes(e.reason))throw Error("Unknown observation.");
 const date=x=>typeof x==="string"&&x.length<=40&&/(Z|[+-]\d\d:\d\d)$/.test(x)&&Number.isFinite(Date.parse(x));
 if(!date(e.occurred_at))throw Error("Invalid timestamp.");
 if(e.context!==null){const c=e.context;
  if(!c||Object.keys(c).sort().join()!==["managed_device","reauthenticated","valid_from","valid_to","known_at"].sort().join()||
   typeof c.managed_device!=="boolean"||typeof c.reauthenticated!=="boolean"||![c.valid_from,c.valid_to,c.known_at].every(date)||Date.parse(c.valid_from)>=Date.parse(c.valid_to))throw Error("Invalid context.");}
}
export class Outbox {
 constructor({directory,app,keyId,secret,endpoint,transport=fetch,clock=()=>Date.now()}){
  const url=new URL(endpoint);
  if(url.protocol!=="http:"||!["127.0.0.1","localhost","[::1]"].includes(url.hostname)||url.username||url.password||url.search||url.hash||
     url.pathname!=="/api/v1/events/"+app+"/")throw Error("Only the exact local collector endpoint is allowed.");
  if(secret.length<32)throw Error("A local key of at least 32 characters is required.");
  Object.assign(this,{directory,app,keyId,secret,endpoint,transport,clock});
 }
 async enqueue(event){
  assertMetadata(event,this.app);
  const body=JSON.stringify(event);
  if(Buffer.byteLength(body)>16384)throw Error("Event too large.");
  await mkdir(this.directory,{recursive:true});
  const file=join(this.directory,event.event_id+".json");
  const record={body,hash:createHash("sha256").update(body).digest("hex"),attempts:0,nextAt:0,state:"pending"};
  try{const fd=await open(file,"wx",0o600);try{await fd.writeFile(JSON.stringify(record));await fd.sync();}finally{await fd.close();}}
  catch(e){if(e.code!=="EEXIST")throw e;const existing=JSON.parse(await readFile(file,"utf8"));if(existing.hash!==record.hash)throw Error("Conflicting event ID.");}
 }
 async flush(limit=100){
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw Error("Delivery limit must be an integer from 1 to 1000.");
  await mkdir(this.directory,{recursive:true});
  const lockPath=join(this.directory,"courier.lock");
  let lock;
  try{lock=await open(lockPath,"wx",0o600);}catch(e){if(e.code==="EEXIST")return {sent:0,busy:true};throw e;}
  const result={sent:0,deferred:0,dead:0};
  try{
   let attempted=0;
   for(const filename of (await readdir(this.directory)).filter(n=>/^[a-f0-9-]{36}\.json$/.test(n)).sort()){
    if(attempted>=limit)break;
     const file=join(this.directory,filename);let record;
     try{record=await persistedRecord(file,filename,this.app);}catch(error){
      if(error.code==="ENOENT")continue;
      if(error.code&&!["EISDIR"].includes(error.code))throw error;
      // Preserve invalid bytes for operator recovery, outside the delivery queue.
      await rename(file,file+".corrupt-"+randomUUID());result.dead++;attempted++;continue;
     }
    if(record.state==="dead"){result.dead++;continue;}
    if(record.nextAt>this.clock()){result.deferred++;continue;}
    attempted++;
    const time=new Date(this.clock()).toISOString();
    let status=0;
    try{const response=await this.transport(this.endpoint,{method:"POST",redirect:"error",signal:AbortSignal.timeout(3000),
      headers:{"Content-Type":"application/json","X-SB-Key":this.keyId,"X-SB-Time":time,
       "X-SB-Signature":sign(this.secret,this.app,this.keyId,time,record.body)},body:record.body});
      status=response.status;
      if(status===200||status===202){await receipt(response, JSON.parse(record.body).event_id);
       await unlink(file);result.sent++;continue;}
      try { await response.body?.cancel(); } catch {}
    }catch{}
    record.attempts++;
    record.state=(record.attempts>=8||[400,401,403,404,409,413,415].includes(status))?"dead":"pending";
    record.nextAt=this.clock()+Math.min(300000,1000*2**record.attempts);
    const temporary=file+".tmp";await writeAtomic(temporary,file,JSON.stringify(record));
    result[record.state==="dead"?"dead":"deferred"]++;
   }
  }finally{await lock.close();await unlink(lockPath);}
  return result;
 }
}
async function writeAtomic(temp,target,text){const fd=await open(temp,"w",0o600);try{await fd.writeFile(text);await fd.sync();}finally{await fd.close();}await rename(temp,target);}
