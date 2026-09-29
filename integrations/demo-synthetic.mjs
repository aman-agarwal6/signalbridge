/** Portable core demo: deliberately synthetic, never source-app integration evidence. */
import { readFileSync } from "node:fs";
import { resolve,dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Outbox } from "./sender.mjs";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const keys=JSON.parse(readFileSync(resolve(root,"var/synthetic-keys.json"),"utf8"));
const inputs=JSON.parse(readFileSync(resolve(root,"fixtures/events.json"),"utf8"));
const episodes=new Map(),now=Date.now();
for(const app of ["bettail","netted"]){
 const sender=new Outbox({directory:resolve(root,"var/synthetic-outbox",app),app,keyId:app+"-synthetic-v1",secret:keys[app],endpoint:"http://127.0.0.1:8741/api/v1/events/"+app+"/"});
 for(const input of inputs.filter(e=>e.app===app)){
  const e=structuredClone(input),shift=now-Date.parse(e.occurred_at);
  const key=app+e.episode;if(!episodes.has(key))episodes.set(key,randomUUID());
  e.event_id=randomUUID();e.episode=episodes.get(key);e.occurred_at=new Date(now).toISOString();
  if(e.context)for(const field of ["valid_from","valid_to","known_at"])e.context[field]=new Date(Date.parse(e.context[field])+shift).toISOString();
  await sender.enqueue(e);
 }
 const result=await sender.flush();console.log(app+" synthetic fixture delivery: "+JSON.stringify(result));
 if(result.dead||result.deferred)process.exitCode=1;
}
console.log("This command is a synthetic core demo, not proof of app instrumentation.");
