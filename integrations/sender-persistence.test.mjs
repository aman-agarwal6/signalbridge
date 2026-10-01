import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,readdir,rm,rename} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,resolve,dirname,basename} from "node:path";
import {randomUUID,createHash} from "node:crypto";
import {Outbox} from "./sender.mjs";

const observation=()=>({schema_version:1,event_id:randomUUID(),app:"bettail",environment:"test",occurred_at:new Date().toISOString(),actor:"a".repeat(64),resource:"b".repeat(64),episode:randomUUID(),operation:"private_record.read",outcome:"denied",reason:"membership_required",context:null});
const hash=body=>createHash("sha256").update(body).digest("hex");
async function fixture(run){
 const directory=await mkdtemp(join(tmpdir(),"signalbridge-test-persistence-"));
 const sent=[];
 const outbox=new Outbox({directory,app:"bettail",keyId:"synthetic-test",secret:"x".repeat(64),endpoint:"http://127.0.0.1:8741/api/v1/events/bettail/",transport:async(_url,request)=>{
  const event=JSON.parse(request.body);sent.push(event);
  return Response.json({status:"accepted",event_id:event.event_id},{status:202});
 }});
 try{await run(outbox,sent);}finally{
  const target=resolve(directory);
  assert.equal(dirname(target),resolve(tmpdir()));assert.ok(basename(target).startsWith("signalbridge-test-persistence-"));
  await rm(target,{recursive:true,force:true});
 }
}
for(const [label,mutate] of [
 ["checksum mismatch",record=>{record.body=JSON.stringify({...JSON.parse(record.body),outcome:"allowed"});}],
 ["invalid event metadata with a matching checksum",record=>{record.body=JSON.stringify({...JSON.parse(record.body),extra:"not-allowed"});record.hash=hash(record.body);}],
 ["wrong app with a matching checksum",record=>{record.body=JSON.stringify({...JSON.parse(record.body),app:"netted"});record.hash=hash(record.body);}],
 ["oversized event body",record=>{record.body=" ".repeat(16385);record.hash=hash(record.body);}],
 ["invalid retry envelope",record=>{record.attempts=-1;}],
 ["malformed JSON",()=>null],
]){
 test("persisted "+label+" is retained without being signed and does not block valid events",()=>fixture(async(outbox,sent)=>{
  const bad={...observation(),event_id:"00000000-0000-4000-8000-000000000001"},good={...observation(),event_id:"ffffffff-ffff-4fff-8fff-ffffffffffff"};
  await outbox.enqueue(bad);await outbox.enqueue(good);
  const path=join(outbox.directory,bad.event_id+".json"),record=JSON.parse(await readFile(path,"utf8"));
  const invalid=mutate(record)===null?"incomplete":JSON.stringify(record);
  await writeFile(path,invalid);
  assert.deepEqual(await outbox.flush(),{sent:1,deferred:0,dead:1});
  assert.deepEqual(sent.map(event=>event.event_id),[good.event_id]);
  const files=await readdir(outbox.directory);assert.equal(files.length,1);assert.ok(files[0].startsWith(bad.event_id+".json.corrupt-"));
  assert.equal(await readFile(join(outbox.directory,files[0]),"utf8"),invalid);
  assert.deepEqual(await outbox.flush(),{sent:0,deferred:0,dead:0});
 }));
}
test("a persisted event must match its filename",()=>fixture(async(outbox,sent)=>{
 const event=observation();await outbox.enqueue(event);
 await rename(join(outbox.directory,event.event_id+".json"),join(outbox.directory,randomUUID()+".json"));
 assert.equal((await outbox.flush()).dead,1);assert.equal(sent.length,0);
}));
test("oversized persisted envelopes are retained without delivery",()=>fixture(async(outbox,sent)=>{
 const event=observation();await outbox.enqueue(event);await writeFile(join(outbox.directory,event.event_id+".json")," ".repeat(65537));
 assert.equal((await outbox.flush()).dead,1);assert.equal(sent.length,0);
}));
