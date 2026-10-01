import test from "node:test";
import "./sender-persistence.test.mjs";
import assert from "node:assert/strict";
import { mkdtemp,readFile,rm,readdir,writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join,resolve,dirname,basename } from "node:path";
import { randomUUID } from "node:crypto";
import { Outbox,sign } from "./sender.mjs";
const secret="x".repeat(64);
const event=()=>({schema_version:1,event_id:randomUUID(),app:"bettail",environment:"test",occurred_at:new Date().toISOString(),actor:"a".repeat(64),resource:"b".repeat(64),episode:randomUUID(),operation:"private_record.read",outcome:"denied",reason:"membership_required",context:null});
async function cleanup(path){const absolute=resolve(path);if(dirname(absolute)!==resolve(tmpdir())||!basename(absolute).startsWith("signalbridge-test-"))throw Error("Unsafe cleanup path.");await rm(absolute,{recursive:true,force:true});}
const setup=async(options={})=>new Outbox({directory:await mkdtemp(join(tmpdir(),"signalbridge-test-")),app:"bettail",keyId:"lab-key",secret,endpoint:"http://127.0.0.1:8741/api/v1/events/bettail/",...options});
test("outage survives process recreation and duplicate delivery acknowledgement",async()=>{
 let time=Date.now();const out=await setup({clock:()=>time,transport:async()=>{throw Error("offline");}});const e=event();
 try{await out.enqueue(e);assert.equal((await out.flush()).deferred,1);
  time+=10000;const recreated=new Outbox({...out,transport:async(_url,r)=>{assert.equal(r.headers["X-SB-Signature"],sign(secret,"bettail","lab-key",r.headers["X-SB-Time"],r.body));return new Response(JSON.stringify({status:"duplicate",event_id:e.event_id}),{status:200});}});
  assert.equal((await recreated.flush()).sent,1);assert.deepEqual(await readdir(out.directory),[]);
 }finally{await cleanup(out.directory);}
});
test("same ID with altered content fails without replacing original",async()=>{
 const out=await setup(),e=event();try{await out.enqueue(e);await out.enqueue(e);
 await assert.rejects(out.enqueue({...e,outcome:"allowed"}),/Conflicting/);assert.equal((await readdir(out.directory)).length,1);
 }finally{await cleanup(out.directory);}
});
test("permanent rejection is retained in dead letter and never silently dropped",async()=>{
 const out=await setup({transport:async()=>new Response("no",{status:401})}),e=event();
 try{await out.enqueue(e);assert.equal((await out.flush()).dead,1);
 assert.equal(JSON.parse(await readFile(join(out.directory,e.event_id+".json"),"utf8")).state,"dead");
 }finally{await cleanup(out.directory);}
});
test("a dishonest success receipt retains the event",async()=>{
 const out=await setup({transport:async()=>new Response(JSON.stringify({status:"accepted",event_id:randomUUID()}),{status:202})});
 try{await out.enqueue(event());assert.equal((await out.flush()).deferred,1);}finally{await cleanup(out.directory);}
});
test("sensitive extras are rejected before touching disk",async()=>{
 const out=await setup();try{await assert.rejects(out.enqueue({...event(),email:"private@example.test"}),/metadata contract/);assert.deepEqual(await readdir(out.directory),[]);}finally{await cleanup(out.directory);}
});
test("explicit timezone offsets are accepted",async()=>{
 const out=await setup();try{await out.enqueue({...event(),occurred_at:"2026-09-23T20:30:00-05:00"});assert.equal((await readdir(out.directory)).length,1);}finally{await cleanup(out.directory);}
});
test("remote hosts, credential URLs, paths, and HTTPS downgrade ambiguities are rejected",()=>{
 for(const endpoint of ["https://collector.example/api/v1/events/bettail/","http://127.0.0.1/api/v1/events/netted/","http://user:pass@localhost/api/v1/events/bettail/","http://localhost/api/v1/events/bettail/?x=1"]){
 assert.throws(()=>new Outbox({directory:"unused",app:"bettail",keyId:"k",secret,endpoint}),/local collector/);
 }
});

test("oversized success receipt is cancelled and the event is retained",async()=>{
 let cancelled=false;
 const out=await setup({transport:async()=>new Response(new ReadableStream({
  pull(controller){controller.enqueue(new Uint8Array(2048));},
  cancel(){cancelled=true;}
 }),{status:202})});
 try{await out.enqueue(event());assert.equal((await out.flush()).deferred,1);assert.equal(cancelled,true);
 assert.equal((await readdir(out.directory)).length,1);
 }finally{await cleanup(out.directory);}
});

test("failure responses are cancelled without buffering their bodies",async()=>{
 let cancelled=false;
 const out=await setup({transport:async()=>new Response(new ReadableStream({
  cancel(){cancelled=true;}
 }),{status:503})});
 try{await out.enqueue(event());assert.equal((await out.flush()).deferred,1);assert.equal(cancelled,true);}
 finally{await cleanup(out.directory);}
});

test("chunked valid receipt is bounded and acknowledged",async()=>{
 const e=event(),body=Buffer.from(JSON.stringify({status:"accepted",event_id:e.event_id}));
 const out=await setup({transport:async()=>new Response(new ReadableStream({start(controller){
  controller.enqueue(body.subarray(0,13));controller.enqueue(body.subarray(13));controller.close();
 }}),{status:202})});
 try{await out.enqueue(e);assert.equal((await out.flush()).sent,1);assert.deepEqual(await readdir(out.directory),[]);}
 finally{await cleanup(out.directory);}
});

test("invalid UTF-8 receipt cannot acknowledge or remove an event",async()=>{
 const out=await setup({transport:async()=>new Response(new Uint8Array([0xff]),{status:202})});
 try{await out.enqueue(event());assert.equal((await out.flush()).deferred,1);assert.equal((await readdir(out.directory)).length,1);}
 finally{await cleanup(out.directory);}
});

test("bounded delivery stops before reading the next record",async()=>{
 const e={...event(),event_id:"00000000-0000-4000-8000-000000000001"};
 const out=await setup({transport:async()=>new Response(JSON.stringify({status:"accepted",event_id:e.event_id}),{status:202})});
 try{await out.enqueue(e);await writeFile(join(out.directory,"ffffffff-ffff-4fff-8fff-ffffffffffff.json"),"incomplete");
 assert.equal((await out.flush(1)).sent,1);assert.equal((await readdir(out.directory)).length,1);
 }finally{await cleanup(out.directory);}
});

test("invalid delivery limits fail before transport or outbox writes",async()=>{
 const out=await setup({transport:async()=>{throw Error("Should not send");}});
 try{for(const limit of [0,-1,1.2,Infinity,1001,"1",null])await assert.rejects(out.flush(limit),/Delivery limit/);
 assert.deepEqual(await readdir(out.directory),[]);
 }finally{await cleanup(out.directory);}
});
