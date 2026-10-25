-- Bookshelf Reader: share links for books.
-- Run in Supabase: SQL Editor -> New query -> paste -> Run. Safe to run again.
-- Files: shared-books/<user id>/<random id>.epub. Signed-in readers upload into their own folder;
-- the bucket is public, so anyone with the exact link can download, but nobody can list the files.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('shared-books', 'shared-books', true, 52428800, array['application/epub+zip', 'application/octet-stream'])
on conflict (id) do update set public = true;

drop policy if exists "upload own shared books" on storage.objects;
create policy "upload own shared books" on storage.objects for insert to authenticated
  with check (bucket_id = 'shared-books' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "see own shared books" on storage.objects;
create policy "see own shared books" on storage.objects for select to authenticated
  using (bucket_id = 'shared-books' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "remove own shared books" on storage.objects;
create policy "remove own shared books" on storage.objects for delete to authenticated
  using (bucket_id = 'shared-books' and (storage.foldername(name))[1] = auth.uid()::text);

select 'Sharing is set up' as status;
