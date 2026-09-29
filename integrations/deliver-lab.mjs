import { readFileSync } from "node:fs";
import { resolve,dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Outbox } from "./sender.mjs";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const keys=JSON.parse(readFileSync(resolve(root,"var/lab-keys.json"),"utf8"));
const events=JSON.parse(readFileSync(resolve(root,"artifacts/local/observed-events.json"),"utf8"));
let total=0;
for(const app of ["bettail","netted"]){
 const outbox=new Outbox({directory:resolve(root,"var/outbox",app),app,keyId:app+"-lab-v1",secret:keys[app],endpoint:"http://127.0.0.1:8741/api/v1/events/"+app+"/"});
 for(const event of events.filter(e=>e.app===app))await outbox.enqueue(event);
 const result=await outbox.flush();console.log(app+": "+JSON.stringify(result));total+=result.sent;
 if(result.dead||result.deferred)process.exitCode=1;
}
console.log("Delivered "+total+" metadata records observed during actual local database operations.");

