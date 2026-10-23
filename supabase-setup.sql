-- Bookshelf Reader: book club backend.
-- Run once in Supabase: SQL Editor -> New query -> paste all of this -> Run.
-- Safe to re-run: it drops and recreates only its own policies/functions.

-- ---------- Tables ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  name text not null check (char_length(name) between 2 and 30),
  created_at timestamptz not null default now()
);

alter table public.profiles add column if not exists is_admin boolean not null default false;

-- Accounts are invite-only: sign-up must carry an unused code from this table.
create table if not exists public.invites (
  code text primary key default upper(substr(md5(random()::text || clock_timestamp()::text), 1, 8)),
  note text not null default '' check (char_length(note) <= 80),
  make_admin boolean not null default false,
  created_by uuid references public.profiles on delete set null default auth.uid(),
  used_by uuid references public.profiles on delete set null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);
-- Reusable codes work for any number of sign-ups (and never grant admin).
alter table public.invites add column if not exists unlimited boolean not null default false;
alter table public.invites add column if not exists uses integer not null default 0;

create table if not exists public.clubs (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 60),
  code text not null unique default upper(substr(md5(random()::text || clock_timestamp()::text), 1, 6)),
  owner uuid not null references public.profiles(id) on delete cascade,
  book_path text,
  book_title text,
  book_author text,
  created_at timestamptz not null default now()
);

create table if not exists public.club_members (
  club_id uuid not null references public.clubs on delete cascade,
  user_id uuid not null references public.profiles on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (club_id, user_id)
);

create table if not exists public.club_plan (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs on delete cascade,
  label text not null check (char_length(label) between 1 and 120),
  href text,
  target_pct real not null check (target_pct between 0 and 1),
  due date not null,
  created_at timestamptz not null default now()
);

create table if not exists public.club_progress (
  club_id uuid not null references public.clubs on delete cascade,
  user_id uuid not null references public.profiles on delete cascade default auth.uid(),
  cfi text,
  pct real not null default 0 check (pct between 0 and 1),
  chapter text,
  seconds integer not null default 0 check (seconds >= 0),
  updated_at timestamptz not null default now(),
  primary key (club_id, user_id)
);

create table if not exists public.club_notes (
  id uuid primary key default gen_random_uuid(),
  club_id uuid not null references public.clubs on delete cascade,
  user_id uuid not null references public.profiles on delete cascade default auth.uid(),
  kind text not null check (kind in ('quote', 'note', 'sticker')),
  cfi text not null,
  text text not null default '' check (char_length(text) <= 5000),
  note text not null default '' check (char_length(note) <= 5000),
  emoji text,
  word text,
  color text,
  chapter text,
  pct real,
  created_at timestamptz not null default now()
);
create index if not exists club_notes_club on public.club_notes (club_id);

-- ---------- Sign-up: needs a valid invite; the profile is created from the sign-up name ----------
-- Enforced here (not just in the page), so calling the Supabase API directly can't skip it.
create or replace function public.check_invite() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform 1 from invites
    where code = upper(trim(coalesce(new.raw_user_meta_data ->> 'invite', ''))) and (unlimited or used_by is null)
    for update; -- lock so two people can't use the same one-time code at once
  if not found then raise exception 'INVALID_INVITE: a valid invite code is required'; end if;
  return new;
end $$;
drop trigger if exists check_invite on auth.users;
create trigger check_invite before insert on auth.users
  for each row execute function public.check_invite();

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare invite_code text := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite', '')));
begin
  insert into public.profiles (id, name, is_admin)
  values (new.id, coalesce(nullif(trim(new.raw_user_meta_data ->> 'name'), ''), 'Reader'),
          coalesce((select make_admin and not unlimited from invites where code = invite_code), false));
  update invites set uses = uses + 1, used_by = case when unlimited then null else new.id end, used_at = now()
    where code = invite_code;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from profiles where id = auth.uid()), false)
$$;
grant execute on function public.is_admin() to authenticated;

-- ---------- Helpers (security definer avoids policy recursion) ----------
create or replace function public.is_member(c uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from club_members where club_id = c and user_id = auth.uid())
$$;

create or replace function public.is_owner(c uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from clubs where id = c and owner = auth.uid())
$$;

-- Create a club and join it as owner.
create or replace function public.create_club(club_name text) returns public.clubs
language plpgsql security definer set search_path = public as $$
declare c public.clubs;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  insert into clubs (name, owner) values (trim(club_name), auth.uid()) returning * into c;
  insert into club_members (club_id, user_id) values (c.id, auth.uid());
  return c;
end $$;

-- Join a club by its 6-character code.
create or replace function public.join_club(join_code text) returns public.clubs
language plpgsql security definer set search_path = public as $$
declare c public.clubs;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  select * into c from clubs where code = upper(trim(join_code));
  if c.id is null then raise exception 'No club with that code'; end if;
  insert into club_members (club_id, user_id) values (c.id, auth.uid()) on conflict do nothing;
  return c;
end $$;

revoke all on function public.create_club(text), public.join_club(text) from public, anon;
grant execute on function public.create_club(text), public.join_club(text) to authenticated;
grant execute on function public.is_member(uuid), public.is_owner(uuid) to authenticated;

-- ---------- Row level security ----------
alter table public.profiles      enable row level security;
alter table public.clubs         enable row level security;
alter table public.club_members  enable row level security;
alter table public.club_plan     enable row level security;
alter table public.club_progress enable row level security;
alter table public.club_notes    enable row level security;
alter table public.invites       enable row level security;

drop policy if exists "profiles readable" on public.profiles;
create policy "profiles readable" on public.profiles for select to authenticated using (true);
-- No profile update policy: otherwise anyone could flip their own is_admin flag.
drop policy if exists "profile self update" on public.profiles;

drop policy if exists "admins read invites" on public.invites;
create policy "admins read invites" on public.invites for select to authenticated using (public.is_admin());
drop policy if exists "admins create invites" on public.invites;
create policy "admins create invites" on public.invites for insert to authenticated
  with check (public.is_admin() and created_by = auth.uid() and used_by is null and make_admin = false and uses = 0);
drop policy if exists "admins delete unused invites" on public.invites;
create policy "admins delete unused invites" on public.invites for delete to authenticated using (public.is_admin() and used_by is null);

drop policy if exists "clubs for members" on public.clubs;
create policy "clubs for members" on public.clubs for select to authenticated using (public.is_member(id));
drop policy if exists "owner edits club" on public.clubs;
create policy "owner edits club" on public.clubs for update to authenticated using (owner = auth.uid()) with check (owner = auth.uid());
drop policy if exists "owner deletes club" on public.clubs;
create policy "owner deletes club" on public.clubs for delete to authenticated using (owner = auth.uid());

drop policy if exists "members see members" on public.club_members;
create policy "members see members" on public.club_members for select to authenticated using (public.is_member(club_id));
drop policy if exists "leave or remove" on public.club_members;
create policy "leave or remove" on public.club_members for delete to authenticated using (user_id = auth.uid() or public.is_owner(club_id));

drop policy if exists "members see plan" on public.club_plan;
create policy "members see plan" on public.club_plan for select to authenticated using (public.is_member(club_id));
drop policy if exists "owner writes plan" on public.club_plan;
create policy "owner writes plan" on public.club_plan for all to authenticated using (public.is_owner(club_id)) with check (public.is_owner(club_id));

drop policy if exists "members see progress" on public.club_progress;
create policy "members see progress" on public.club_progress for select to authenticated using (public.is_member(club_id));
drop policy if exists "own progress insert" on public.club_progress;
create policy "own progress insert" on public.club_progress for insert to authenticated with check (user_id = auth.uid() and public.is_member(club_id));
drop policy if exists "own progress update" on public.club_progress;
create policy "own progress update" on public.club_progress for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid() and public.is_member(club_id));

drop policy if exists "members see notes" on public.club_notes;
create policy "members see notes" on public.club_notes for select to authenticated using (public.is_member(club_id));
drop policy if exists "own notes insert" on public.club_notes;
create policy "own notes insert" on public.club_notes for insert to authenticated with check (user_id = auth.uid() and public.is_member(club_id));
drop policy if exists "own notes update" on public.club_notes;
create policy "own notes update" on public.club_notes for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "own notes delete" on public.club_notes;
create policy "own notes delete" on public.club_notes for delete to authenticated using (user_id = auth.uid());

-- ---------- Private storage for club books: <club_id>/book.epub ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('club-books', 'club-books', false, 52428800, array['application/epub+zip', 'application/octet-stream'])
on conflict (id) do nothing;

create or replace function public.club_of_path(path text) returns uuid
language sql immutable as $$
  select case when split_part(path, '/', 1) ~ '^[0-9a-f-]{36}$' then split_part(path, '/', 1)::uuid end
$$;

drop policy if exists "members download club book" on storage.objects;
create policy "members download club book" on storage.objects for select to authenticated
  using (bucket_id = 'club-books' and public.is_member(public.club_of_path(name)));
drop policy if exists "owner uploads club book" on storage.objects;
create policy "owner uploads club book" on storage.objects for insert to authenticated
  with check (bucket_id = 'club-books' and public.is_owner(public.club_of_path(name)));
drop policy if exists "owner replaces club book" on storage.objects;
create policy "owner replaces club book" on storage.objects for update to authenticated
  using (bucket_id = 'club-books' and public.is_owner(public.club_of_path(name)));
drop policy if exists "owner deletes club book" on storage.objects;
create policy "owner deletes club book" on storage.objects for delete to authenticated
  using (bucket_id = 'club-books' and public.is_owner(public.club_of_path(name)));

-- ---------- Your first (admin) invite ----------
-- Made only while no admin exists yet. The query result at the bottom shows the code:
-- use it on the Clubs tab -> "Create an account".
insert into public.invites (code, note, make_admin, created_by)
select 'ADMIN-' || upper(substr(md5(random()::text || clock_timestamp()::text), 1, 6)), 'First admin account', true, null
where not exists (select 1 from public.profiles where is_admin)
  and not exists (select 1 from public.invites where make_admin and used_by is null);

select code as your_admin_invite_code from public.invites where make_admin and used_by is null;
