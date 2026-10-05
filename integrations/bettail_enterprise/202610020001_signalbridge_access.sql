-- ONLY for the verified disposable BetTail source copy. No real app migration.
-- Prepared, not applied. The source-native acceptance run must verify this SQL.
begin;
do $$ begin
 if to_regprocedure('extensions.hmac(bytea,bytea,text)') is null then
  raise exception 'The copied lab requires its existing pgcrypto extension';
 end if;
end $$;
create schema sb_bettail;
revoke all on schema sb_bettail from public, anon, authenticated;
alter default privileges in schema sb_bettail revoke execute on functions from public;
create table sb_bettail.configuration (
 singleton boolean primary key default true check(singleton),
 observer_key bytea not null check(octet_length(observer_key)=32),
 pseudonym_key bytea not null check(octet_length(pseudonym_key)=32),
 check(observer_key<>pseudonym_key)
);
create table sb_bettail.watched (
 slot smallint primary key check(slot between 1 and 4),
 kind text not null check(kind in ('post','image')),
 ref uuid not null, group_id uuid not null references public.groups(id),
 post_id uuid not null references public.bet_posts(id),
 episode uuid not null unique default gen_random_uuid(),
 unique(kind,ref)
);
create table sb_bettail.outbox (
 event_id uuid primary key,
 payload jsonb not null check(octet_length(payload::text)<=4096),
 read_proof bytea,
 created_at timestamptz not null default clock_timestamp(),
 available_at timestamptz not null default clock_timestamp(),
 lease uuid, lease_until timestamptz,
 attempts integer not null default 0 check(attempts between 0 and 100),
 state text not null default 'pending' check(state in ('pending','acknowledged','dead')),
 error_code text not null default '', acknowledged_at timestamptz
);
create index sb_bettail_pending on sb_bettail.outbox(available_at,created_at,event_id)
 where state='pending';
revoke all on all tables in schema sb_bettail from public,anon,authenticated;

-- Operator-only provisioning after synthetic fixtures exist. Up to two exact
-- post/image pairs allow a separate publication control; IDs are never merged
-- by source_post_id, creator, image owner, or group name.
create function sb_bettail.watch_pair(pair_number integer,p_post uuid,p_comment uuid)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare g uuid;
begin
 perform pg_advisory_xact_lock(hashtextextended('signalbridge-bettail-access',0));
 if pair_number not in (1,2) or exists(select 1 from sb_bettail.outbox) then
  raise exception 'Cannot change this bounded observation profile';
 end if;
 select p.group_id into g from public.bet_posts p
 join public.comments c on c.bet_post_id=p.id
 join public.chat_uploads i on i.id=c.image_id and i.post_id=p.id
 where p.id=p_post and c.id=p_comment and p.deleted_at is null
 and p.removed_at is null and c.deleted_at is null and i.discarded_at is null;
 if g is null then raise exception 'A live post and attached post image are required'; end if;
 insert into sb_bettail.watched(slot,kind,ref,group_id,post_id) values
 (pair_number*2-1,'post',p_post,g,p_post),(pair_number*2,'image',p_comment,g,p_post);
end $$;

create function sb_bettail.pseudonym(category text,identifier uuid) returns text
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
 select encode(extensions.hmac(convert_to('bettail:'||category||':'||identifier::text,'UTF8'),
 c.pseudonym_key,'sha256'),'hex') from sb_bettail.configuration c where c.singleton
$$;

-- Evaluate the *existing* source authorization functions as the affected
-- subject. Only the private mutation wrapper may call this helper. The original
-- operator context is restored on both success and exception; no impersonation
-- endpoint is exposed to an application user or collector. No role is changed.
create function sb_bettail.effective(w sb_bettail.watched,subject uuid) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare previous_sub text=current_setting('request.jwt.claim.sub',true);
 previous_actor uuid=auth.uid();
 result boolean=false; snapshot jsonb;
begin
 if not exists(select 1 from public.profiles p where p.id=subject and p.deleted_at is null)
 then return false; end if;
 begin
  perform set_config('request.jwt.claim.sub',subject::text,true);
  if auth.uid() is distinct from subject then
   raise exception 'Subject context did not take effect';
  end if;
  if w.kind='image' then
   result=public.bt_chat_image_path(w.ref) is not null;
  else
   begin
    snapshot=public.bt_snapshot(jsonb_build_object('group_id',w.group_id,'post_id',w.post_id));
    result=exists(select 1 from jsonb_array_elements(coalesce(snapshot->'posts','[]'::jsonb)) p
      where p->>'id'=w.post_id::text);
   exception when sqlstate 'P0001' then
    if sqlerrm not in ('Bet unavailable.','Group unavailable.') then raise; end if;
    result=false;
   end;
  end if;
 exception when others then
  perform set_config('request.jwt.claim.sub',coalesce(previous_sub,''),true);
  if auth.uid() is distinct from previous_actor then raise exception 'Operator context changed'; end if;
  raise;
 end;
 perform set_config('request.jwt.claim.sub',coalesce(previous_sub,''),true);
 if auth.uid() is distinct from previous_actor then raise exception 'Operator context changed'; end if;
 return result;
end $$;

create function sb_bettail.emit(w sb_bettail.watched,operator_id uuid,subject uuid,
 new_state text) returns void language plpgsql security definer
set search_path=pg_catalog,pg_temp as $$
declare identifier uuid=gen_random_uuid(); body jsonb;
begin
 if operator_id is null or subject is null or new_state not in ('removed','granted')
 or not exists(select 1 from sb_bettail.configuration)
 then raise exception 'Invalid copied-lab transition'; end if;
 if (select count(*) from sb_bettail.outbox)>=10000 then
  raise exception 'Copied-lab outbox capacity reached';
 end if;
 body=jsonb_build_object('schema_version',2,'event_id',identifier,'app','bettail',
 'environment','lab','occurred_at',to_char(clock_timestamp() at time zone 'UTC',
 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'actor',sb_bettail.pseudonym('account',operator_id),
 'resource',sb_bettail.pseudonym(w.kind,w.ref),'episode',w.episode,
 'operation','membership.change','outcome','allowed',
 'reason',case when new_state='removed' then 'membership_removed' else 'member' end,
 'context',null,'membership',jsonb_build_object('subject',sb_bettail.pseudonym('account',subject),
 'state',new_state));
 insert into sb_bettail.outbox(event_id,payload) values(identifier,body);
end $$;

-- Preserve the actual mutation implementation, including owner/self restrictions,
-- request-id receipts and current grants. The old implementation becomes private.
-- The frozen final wrapper includes BOTH deletion dispatches inserted by 046.
-- Check its body/signature before moving it, and reject stale implicit block
-- qualifiers anywhere in the existing reviewed mutation chain. Source policies,
-- nested workflows, entry_source handling and request-ID logic remain intact.
do $$ declare original pg_proc; f record;
begin
 select * into original from pg_proc where oid='public.bt_mutate(text,jsonb,uuid)'::regprocedure;
 if original.pronargs<>3 or original.pronargdefaults<>0
 or original.proargnames is distinct from array['action','data','request_id']::text[]
 or original.prorettype<>'jsonb'::regtype or not original.prosecdef
 or original.prolang<>(select oid from pg_language where lanname='plpgsql')
 or original.proconfig is distinct from array['search_path=pg_catalog, public, pg_temp']::text[]
 or encode(extensions.digest(convert_to(replace(original.prosrc,chr(13),''),'UTF8'),'sha256'),'hex')<>
 '80c3cf3ed4e3c0489213049e3ccec946fed22b47b2542624c8cb25d6eac1091c'
 then raise exception 'Unexpected frozen BetTail mutation definition'; end if;
 if not has_function_privilege('authenticated',original.oid,'EXECUTE')
 or has_function_privilege('anon',original.oid,'EXECUTE') then
  raise exception 'Unexpected frozen BetTail mutation grants';
 end if;
 for f in select p.proname,p.prosrc from pg_proc p join pg_namespace n on n.oid=p.pronamespace
 where n.nspname='public' and p.proname in
 ('bt_mutate_core','bt_mutate_review','bt_mutate_before_connected') loop
  if strpos(f.prosrc,'bt_mutate.')<>0 then
   raise exception 'A source mutation block qualifier was not repaired';
  end if;
 end loop;
 if to_regprocedure('public.bt_mutate_core(text,jsonb,uuid)') is null
 or to_regprocedure('public.bt_mutate_review(text,jsonb,uuid)') is null
 or to_regprocedure('public.bt_mutate_before_connected(text,jsonb,uuid)') is null then
  raise exception 'Incomplete frozen BetTail mutation chain';
 end if;
end $$;
alter function public.bt_mutate(text,jsonb,uuid) set schema sb_bettail;
alter function sb_bettail.bt_mutate(text,jsonb,uuid) rename to original_mutate;
do $$ begin
 -- Retain the exact guarded definition and safely update its implicit block
 -- label if a function-qualified parameter is present. Do not replace policies.
 execute replace(pg_get_functiondef('sb_bettail.original_mutate(text,jsonb,uuid)'::regprocedure),
  'bt_mutate.','original_mutate.');
end $$;
revoke all on function sb_bettail.original_mutate(text,jsonb,uuid) from public,anon,authenticated;
create function public.bt_mutate(action text,data jsonb,request_id uuid) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare operator_id uuid=auth.uid(); subject uuid; g uuid; w sb_bettail.watched;
 before_access jsonb='{}'::jsonb; after_access boolean; result jsonb;
begin
 if operator_id is null then raise exception 'Sign in to continue.'; end if;
 if action not in ('remove_member','restore_member','member_role','transfer_owner','leave_group')
 then return sb_bettail.original_mutate(action,data,request_id); end if;
 g=(data->>'group_id')::uuid;
 subject=case when action='leave_group' then operator_id else (data->>'member_id')::uuid end;
 -- Serialize selected changes, profile provisioning and finite outbox accounting.
 -- A source RPC failure rolls back both its business change and emitted records.
 perform pg_advisory_xact_lock(hashtextextended('signalbridge-bettail-access',0));
 for w in select * from sb_bettail.watched where group_id=g order by slot loop
  before_access=before_access||jsonb_build_object(w.slot::text,sb_bettail.effective(w,subject));
 end loop;
 result=sb_bettail.original_mutate(action,data,request_id);
 if auth.uid() is distinct from operator_id then raise exception 'Operator context changed'; end if;
 for w in select * from sb_bettail.watched where group_id=g order by slot loop
  after_access=sb_bettail.effective(w,subject);
  if after_access is distinct from (before_access->>w.slot::text)::boolean then
   perform sb_bettail.emit(w,operator_id,subject,case when after_access then 'granted' else 'removed' end);
  end if;
 end loop;
 if auth.uid() is distinct from operator_id then raise exception 'Operator context changed'; end if;
 return result;
end $$;
revoke all on function public.bt_mutate(text,jsonb,uuid) from public,anon;
grant execute on function public.bt_mutate(text,jsonb,uuid) to authenticated;

-- Authenticated users cannot invent read observations. The proof covers their
-- auth.uid(), exact resource, result, event ID and fresh timestamp, with a key
-- available only to this lab's server process and private database table.
create function public.sb_bettail_observe(event_id uuid,resource_kind text,resource_ref uuid,
 observed_at text,observed_outcome text,proof text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare actor_id uuid=auth.uid(); w sb_bettail.watched; expected bytea; message text;
 reason text; body jsonb; prior sb_bettail.outbox; observation_time timestamptz;
begin
 if actor_id is null or resource_kind not in ('post','image')
 or observed_outcome not in ('allowed','denied','not_visible','error')
 or observed_at is null or observed_at !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
 or proof is null or proof !~ '^[0-9a-f]{64}$' or event_id is null or resource_ref is null
 then raise exception 'Observation rejected' using errcode='42501'; end if;
 observation_time=observed_at::timestamptz;
 if abs(extract(epoch from clock_timestamp()-observation_time))>30 then
  raise exception 'Observation rejected' using errcode='42501';
 end if;
 select * into w from sb_bettail.watched where kind=resource_kind and ref=resource_ref;
 if not found then raise exception 'Observation rejected' using errcode='42501'; end if;
 reason=case observed_outcome when 'allowed' then 'member' when 'denied' then 'membership_required'
 when 'not_visible' then 'resource_unavailable' else 'dependency_unavailable' end;
 message=concat_ws(E'\n','signalbridge.bettail.read.v1',event_id::text,actor_id::text,
 resource_kind,resource_ref::text,observed_at,observed_outcome,reason);
 select extensions.hmac(convert_to(message,'UTF8'),c.observer_key,'sha256') into expected
 from sb_bettail.configuration c where c.singleton;
 -- Compare fixed-length digests of proof values, not a secret-prefix string.
 if expected is null or extensions.digest(decode(proof,'hex'),'sha256')<>
 extensions.digest(expected,'sha256') then
  raise exception 'Observation rejected' using errcode='42501';
 end if;
 perform pg_advisory_xact_lock(hashtextextended('signalbridge-bettail-access',0));
 select * into prior from sb_bettail.outbox o where o.event_id=sb_bettail_observe.event_id;
 if found then
  if prior.read_proof is distinct from expected then
   raise exception 'Observation conflict' using errcode='23505';
  end if;
  return jsonb_build_object('event_id',event_id,'status','duplicate');
 end if;
 if (select count(*) from sb_bettail.outbox)>=10000 then
  raise exception 'Copied-lab outbox capacity reached';
 end if;
 body=jsonb_build_object('schema_version',1,'event_id',event_id,'app','bettail',
 'environment','lab','occurred_at',observed_at,'actor',sb_bettail.pseudonym('account',actor_id),
 'resource',sb_bettail.pseudonym(w.kind,w.ref),'episode',w.episode,
 'operation','private_record.read','outcome',observed_outcome,'reason',reason,'context',null);
 insert into sb_bettail.outbox(event_id,payload,read_proof) values(event_id,body,expected);
 return jsonb_build_object('event_id',event_id,'status','recorded');
end $$;
revoke all on function public.sb_bettail_observe(uuid,text,uuid,text,text,text) from public,anon;
grant execute on function public.sb_bettail_observe(uuid,text,uuid,text,text,text) to authenticated;

-- A dedicated NOLOGIN group may be granted to one future lab delivery login.
-- It cannot read keys, change a source account or fabricate/modify outbox bodies.
create role sb_bettail_delivery nologin;
grant usage on schema sb_bettail to sb_bettail_delivery;
create function sb_bettail.claim(p_lease uuid) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare item sb_bettail.outbox;
begin
 if p_lease is null then raise exception 'Lease required'; end if;
 -- A process can disappear on its 100th committed claim without calling finish.
 -- Retire at most 100 exhausted, expired rows per call, never an active lease.
 with exhausted as (
  select o.event_id from sb_bettail.outbox o where o.state='pending' and o.attempts>=100
  and (o.lease_until is null or o.lease_until<=clock_timestamp())
  order by o.available_at,o.created_at,o.event_id for update skip locked limit 100
 ) update sb_bettail.outbox o set state='dead',error_code='retry_exhausted',lease=null,lease_until=null
 from exhausted x where o.event_id=x.event_id;
 select * into item from sb_bettail.outbox o where o.state='pending' and o.attempts<100
 and o.available_at<=clock_timestamp() and (o.lease_until is null or o.lease_until<=clock_timestamp())
 order by o.available_at,o.created_at,o.event_id for update skip locked limit 1;
 if not found then return null; end if;
 update sb_bettail.outbox set lease=p_lease,lease_until=clock_timestamp()+interval '30 seconds',
 attempts=attempts+1,error_code='' where event_id=item.event_id;
 return item.payload;
end $$;
create function sb_bettail.finish(p_id uuid,p_lease uuid,p_state text,p_error text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare completed sb_bettail.outbox;
begin
 if p_state not in ('acknowledged','pending','dead') or p_error not in
 ('','invalid_outbox_record','invalid_acknowledgement','event_conflict','delivery_rejected',
 'redirect_rejected','collector_unavailable','transport_failed') then raise exception 'Invalid delivery result'; end if;
 update sb_bettail.outbox set state=case when p_state='pending' and attempts>=100 then 'dead' else p_state end,
 error_code=case when p_state='pending' and attempts>=100 then 'retry_exhausted' else p_error end,
 acknowledged_at=case when p_state='acknowledged' then clock_timestamp() else null end,
 available_at=clock_timestamp()+interval '30 seconds',lease=null,lease_until=null
 where event_id=p_id and lease=p_lease and lease_until>clock_timestamp() and state='pending'
 returning * into completed;
 if not found then return null; end if;
 return jsonb_build_object('event_id',completed.event_id,'state',completed.state,'error',completed.error_code);
end $$;
revoke all on all functions in schema sb_bettail from public,anon,authenticated;
revoke all on function sb_bettail.effective(sb_bettail.watched,uuid) from sb_bettail_delivery;
grant execute on function sb_bettail.claim(uuid),sb_bettail.finish(uuid,uuid,text,text) to sb_bettail_delivery;
commit;
