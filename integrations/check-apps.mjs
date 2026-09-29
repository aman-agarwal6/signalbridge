import { PGlite } from "@electric-sql/pglite";
import { readFileSync,readdirSync,mkdirSync,writeFileSync,existsSync } from "node:fs";
import { resolve,dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID,createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const selected=process.argv[2] || "all";
if (!["all","bettail","netted"].includes(selected)) throw Error("Choose all, bettail or netted.");
const sha=value=>createHash("sha256").update(value).digest("hex");
const observedEvents=[];
const report={schema_version:1,executed_at:new Date().toISOString(),environment:"ephemeral-pglite",apps:[],
 limitations:["Auth claims are local test doubles; real JWT validation is not exercised.","Storage catalog policies do not prove file-serving or signed-URL behavior.","No hosted services contacted; no production release gate is configured.","Working-tree migration hashes identify uncommitted source as well as HEAD."]};
const auth=`create role anon; create role authenticated; create schema auth;
create table auth.users(id uuid primary key,email_confirmed_at timestamptz default now());
create table auth.sessions(id uuid primary key,user_id uuid references auth.users(id),created_at timestamptz default now(),not_after timestamptz);
create table auth.mfa_factors(id uuid primary key default gen_random_uuid(),user_id uuid references auth.users(id),status text,factor_type text);
create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
create function auth.jwt() returns jsonb language sql stable as $$select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb$$;
grant usage on schema auth to authenticated; grant execute on function auth.uid(),auth.jwt() to authenticated;`;
const catalogs=`create schema realtime;create table realtime.messages(extension text);alter table realtime.messages enable row level security;
create function realtime.topic() returns text language sql stable as $$select current_setting('realtime.topic',true)$$;
create function realtime.send(jsonb,text,text,boolean) returns void language sql as $$select$$;
create schema storage;create table storage.buckets(id text primary key,name text,public boolean,file_size_limit bigint,allowed_mime_types text[]);
create table storage.objects(id uuid primary key default gen_random_uuid(),bucket_id text,name text);alter table storage.objects enable row level security;
grant usage on schema storage to authenticated,anon;grant select,insert,delete on storage.objects to authenticated;`;
async function run(app) {
 const source=resolve(process.env[app.toUpperCase()+"_REPO"] || resolve(root,"..",app));
 const migrationDir=resolve(source,"supabase","migrations");
 const result={app,revision:"unavailable",migration_hashes:[],checks:[],status:"blocked",duration_ms:0};
 report.apps.push(result);
 if(!existsSync(migrationDir)){ result.error="Source migration directory unavailable.";return; }
 const started=performance.now();
 result.revision=execFileSync("git",["-C",source,"rev-parse","HEAD"],{encoding:"utf8"}).trim();
 result.working_tree_dirty=Boolean(execFileSync("git",["-C",source,"status","--porcelain"],{encoding:"utf8"}).trim());
 const db=new PGlite();
 const salt=randomUUID(), episodes=new Map(), forbiddenActors=new Set();
 let faultActive=false;
 const observe=(user,sql,params,response,error)=>{
  if(!/select (id,title from public.bet_posts|public\.bt_snapshot|public\.netted_snapshot)/.test(sql))return;
  const resource=/bet_posts/.test(sql)?String(params[0]):/bt_snapshot/.test(sql)?JSON.parse(params[0]).post_id||'snapshot':'snapshot';
  let visible=false;
  if(!error){const r=response.rows[0];visible=Boolean(r && (r.result ? (r.result.posts||r.result.records||[]).length : true));}
  if(!episodes.has(user))episodes.set(user,randomUUID());
  const denied=error && /unavailable|NETTED_SESSION|NETTED_MFA|permission denied/i.test(error.message);
  observedEvents.push({schema_version:1,event_id:randomUUID(),app,environment:'lab',occurred_at:new Date().toISOString(),
   actor:sha(salt+app+user),resource:sha(salt+app+resource),episode:episodes.get(user),operation:'private_record.read',
   outcome:error?(denied?'denied':'error'):(visible?'allowed':'not_visible'),
   reason:error?(denied?(app==='bettail'?'membership_required':'session_invalid'):'dependency_unavailable'):
    visible?(faultActive&&forbiddenActors.has(user)?'policy_regression':app==='bettail'?'member':'owner'):'resource_unavailable',context:null});
 };
 const check=async(id,fn)=>{ const begin=performance.now();try{await fn();result.checks.push({id,status:"passed",duration_ms:Math.round(performance.now()-begin)});}
  catch(e){result.checks.push({id,status:"failed",error:e instanceof assert.AssertionError?"Assertion mismatch":e.message.slice(0,200)});throw e;} };
 const as=async(user,sql,params=[],overrides={})=>{
  await db.exec("set role authenticated");
  try {
   await db.query("select set_config('request.jwt.claim.sub',$1,false),set_config('request.jwt.claims',$2,false)",[user,JSON.stringify({sub:user,session_id:user,aal:"aal2",app_metadata:{provider:"google"},...overrides})]);
   try{const response=await db.query(sql,params);observe(user,sql,params,response,null);return response;}
   catch(error){observe(user,sql,params,null,error);throw error;}
  } finally { await db.exec("reset role"); }
 };
 const identity=async()=>{const u=randomUUID();await db.query("insert into auth.users(id) values($1)",[u]);
  await db.query("insert into auth.sessions(id,user_id) values($1,$1)",[u]);
  await db.query("insert into auth.mfa_factors(user_id,status,factor_type) values($1,'verified','totp')",[u]);return u;};
 try{
  await db.exec(auth);if(app==="bettail")await db.exec(catalogs);
  for(const file of readdirSync(migrationDir).filter(f=>f.endsWith(".sql")).sort()){
   const text=readFileSync(resolve(migrationDir,file),"utf8");
   result.migration_hashes.push({file,sha256:sha(text)});
   await db.exec(text);
  }
  await check("ordinary-role-is-not-superuser",async()=>{
   const row=(await db.query("select rolsuper,rolbypassrls from pg_roles where rolname='authenticated'")).rows[0];
   assert.equal(row.rolsuper,false);assert.equal(row.rolbypassrls,false);
  });
  if(app==="bettail"){
   const owner=await identity(),member=await identity(),outsider=await identity();
   forbiddenActors.add(outsider);
   const action=async(u,action,data)=>(await as(u,"select bt_mutate($1,$2::jsonb,$3::uuid) result",[action,JSON.stringify(data),randomUUID()])).rows[0].result;
   for(const u of [owner,member,outsider])await action(u,"profile",{display_name:"Synthetic member",username:"lab_"+u.replaceAll("-","").slice(0,20),timezone:"UTC",unit_cents:2000,preferences:{}});
   const group=String((await action(owner,"create_group",{name:"SignalBridge lab"})).group_id);
   const invite=await action(owner,"create_invite",{group_id:group,max_uses:2,days:1});
   await action(member,"join_group",{code:invite.code});
   const pick=await action(owner,"post",{group_id:group,title:"Synthetic private pick",selection:"Test",market:"spread",line:"+3.5",sport:"NFL",league:"NFL",event_name:"Synthetic A vs B",event_start_time:"2030-09-10T00:20:00Z",bet_type:"spread",sportsbook:"draftkings",sportsbook_url:"",accepted_odds:-110,stake_cents:2000,legs:[]});
   const post=String(pick.post_id);
   const read=u=>as(u,"select id,title from public.bet_posts where id=$1",[post]);
   const snapshot=u=>as(u,"select public.bt_snapshot($1::jsonb) result",[JSON.stringify({group_id:group,post_id:post})]);
   const boundary=async()=>{
    assert.deepEqual((await read(member)).rows,[{id:post,title:"Synthetic private pick"}]);
    assert.deepEqual((await read(outsider)).rows,[]);
   };
   await check("member-can-read-exact-private-pick",async()=>assert.deepEqual((await read(member)).rows,[{id:post,title:"Synthetic private pick"}]));
   await check("outsider-id-substitution-is-not-visible",async()=>assert.deepEqual((await read(outsider)).rows,[]));
   await check("member-real-snapshot-rpc",async()=>assert.ok((await snapshot(member)).rows[0].result.posts.some(p=>p.id===post)));
   await check("outsider-real-snapshot-rpc-denied",async()=>assert.rejects(snapshot(outsider),/unavailable/i));
   await check("unknown-identifiers-stay-not-visible",async()=>{
    for(let i=0;i<3;i++)assert.deepEqual((await as(outsider,"select id,title from public.bet_posts where id=$1",[randomUUID()])).rows,[]);
   });
   await check("mutation-is-caught-by-unchanged-boundary",async()=>{
    await db.exec("begin");
    try{faultActive=true;await db.exec("alter policy post_read on public.bet_posts using(true)");
     await assert.rejects(boundary(),e=>e instanceof assert.AssertionError);
    }finally{faultActive=false;await db.exec("rollback");}
   });
   await check("restored-policy-preserves-allow-and-filter",boundary);
   await db.query("update public.group_members set active=false,removed=true where group_id=$1 and user_id=$2",[group,member]);
   await check("removed-member-new-read-is-not-visible",async()=>assert.deepEqual((await read(member)).rows,[]));
   await check("removed-member-snapshot-rpc-denied",async()=>assert.rejects(snapshot(member),/unavailable/i));
   await check("owner-remains-authorized-after-removal",async()=>assert.equal((await read(owner)).rows.length,1));
   await check("anonymous-direct-read-rejected",async()=>{
    await db.exec("set role anon");
    try{await assert.rejects(db.query("select id from public.bet_posts where id=$1",[post]),/permission denied/);}
    finally{await db.exec("reset role");}
   });
   result.observations={resource:"public.bet_posts",direct_path:"SELECT with RLS",server_path:"bt_snapshot",filter_semantics:"not_visible",revocation:"new reads after active=false and removed=true"};
  }else{
   const owner=await identity(),other=await identity(),record=randomUUID();
   forbiddenActors.add(other);
   const snapshot=u=>as(u,"select public.netted_snapshot() result");
   await as(owner,"select public.netted_apply($1,'account',$2::jsonb,0) result",[record,JSON.stringify({name:"Synthetic lab account",accountType:"checking",amount:10000})]);
   const boundary=async()=>{
    assert.ok((await snapshot(owner)).rows[0].result.records.some(r=>r.id===record));
    assert.ok(!(await snapshot(other)).rows[0].result.records.some(r=>r.id===record));
   };
   await check("owner-can-read-created-record-via-rpc",async()=>assert.ok((await snapshot(owner)).rows[0].result.records.some(r=>r.id===record)));
   await check("other-user-snapshot-excludes-private-record",async()=>assert.ok(!(await snapshot(other)).rows[0].result.records.some(r=>r.id===record)));
   await check("direct-table-access-denied",async()=>assert.rejects(as(owner,"select id from public.netted_records"),/permission denied/));
   await check("mfa-required-by-real-database-function",async()=>assert.rejects(as(owner,"select public.netted_snapshot()",[],{aal:"aal1"}),/NETTED_MFA/));
   await check("forged-session-rejected",async()=>assert.rejects(as(owner,"select public.netted_snapshot()",[],{session_id:other}),/NETTED_SESSION/));
   await check("mutation-is-caught-by-unchanged-boundary",async()=>{
    await db.exec("begin");
    try{faultActive=true;await db.exec(`create or replace function public.netted_snapshot() returns jsonb language sql security definer set search_path='' as $$select jsonb_build_object('records',coalesce(jsonb_agg(jsonb_build_object('id',id,'kind',kind)),'[]'::jsonb),'version',count(*)) from public.netted_records$$`);
     await assert.rejects(boundary(),e=>e instanceof assert.AssertionError);
    }finally{faultActive=false;await db.exec("rollback");}
   });
   await check("restored-rpc-preserves-owner-isolation",boundary);
   await as(owner,"select public.netted_end_session()");
   await check("revoked-session-rejected",async()=>assert.rejects(snapshot(owner),/NETTED_SESSION/));
   await check("other-user-session-survives-revocation",async()=>assert.equal((await snapshot(other)).rows[0].result.records.length,0));
   result.observations={resource:"public.netted_records",direct_path:"table permission denied",server_path:"netted_snapshot / check_session",revocation:"netted_end_session invalidates new RPC access"};
  }
  result.status="passed";
 }catch(e){result.status="failed";result.error=e.message.slice(0,250);}
 finally{await db.close();result.duration_ms=Math.round(performance.now()-started);}
}
for(const app of selected==="all"?["bettail","netted"]:[selected])await run(app);
const out=resolve(root,"artifacts","local");mkdirSync(out,{recursive:true});
writeFileSync(resolve(out,"app-checks.json"),JSON.stringify(report,null,2)+"\n");
writeFileSync(resolve(out,"observed-events.json"),JSON.stringify(observedEvents,null,2)+"\n");
for(const app of report.apps)console.log(app.app+": "+app.status+"; "+app.checks.filter(c=>c.status==="passed").length+"/"+app.checks.length+" checks; "+app.duration_ms+" ms"+(app.error?" — "+app.error:""));
if(report.apps.some(a=>a.status!=="passed")||report.apps.some(a=>a.checks.length===0))process.exitCode=1;
