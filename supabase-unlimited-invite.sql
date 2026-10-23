-- Bookshelf Reader: reusable ("unlimited") invite codes.
-- Run in Supabase: SQL Editor -> New query -> paste -> Run. Safe to run again.
-- The result at the bottom shows your reusable code: anyone with it can create an account,
-- as many times as you like, until you delete it (Clubs tab -> Invites -> ✕, or the last line below).

alter table public.invites add column if not exists unlimited boolean not null default false;
alter table public.invites add column if not exists uses integer not null default 0;

-- Sign-up accepts an unused one-time code, or any reusable code.
create or replace function public.check_invite() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform 1 from invites
    where code = upper(trim(coalesce(new.raw_user_meta_data ->> 'invite', '')))
      and (unlimited or used_by is null)
    for update;
  if not found then raise exception 'INVALID_INVITE: a valid invite code is required'; end if;
  return new;
end $$;

-- One-time codes get marked used; reusable codes just count uses. Reusable codes never grant admin.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare inv public.invites;
begin
  select * into inv from invites where code = upper(trim(coalesce(new.raw_user_meta_data ->> 'invite', '')));
  insert into public.profiles (id, name, is_admin)
  values (new.id, coalesce(nullif(trim(new.raw_user_meta_data ->> 'name'), ''), 'Reader'),
          coalesce(inv.make_admin and not inv.unlimited, false));
  update invites set uses = uses + 1,
                     used_by = case when unlimited then null else new.id end,
                     used_at = now()
    where code = inv.code;
  return new;
end $$;

-- Admins may create reusable codes from the site too (still never admin-granting).
drop policy if exists "admins create invites" on public.invites;
create policy "admins create invites" on public.invites for insert to authenticated
  with check (public.is_admin() and created_by = auth.uid() and used_by is null and make_admin = false and uses = 0);

-- Create one reusable code now (only if you don't already have one).
insert into public.invites (code, note, unlimited, created_by)
select 'CLUB-' || upper(substr(md5(random()::text || clock_timestamp()::text), 1, 6)), 'Reusable invite', true, null
where not exists (select 1 from public.invites where unlimited);

select code as reusable_invite_code, uses as accounts_made_with_it from public.invites where unlimited;

-- To switch a reusable code off later, run:  delete from public.invites where unlimited;
