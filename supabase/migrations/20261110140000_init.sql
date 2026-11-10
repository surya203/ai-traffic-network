-- AI Network Sentinel — initial schema
-- Paste this file into the Supabase SQL editor and run it once.
-- Creates the investigation tables, owner-only row level security,
-- and two private storage buckets.
--
-- Object paths must start with the owner's user id:
--   {user_id}/filename
-- The backend writes report PDFs with the service role. Authenticated
-- users can read their own report objects and cannot insert them.
--
-- network-uploads is capped at 50 MB so the limit stays within the
-- Supabase Free plan global file size. investigation-reports is 10 MB.

-- ---------------------------------------------------------------------------
-- updated_at
-- ---------------------------------------------------------------------------

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

revoke all on function public.set_updated_at() from public, anon;
grant execute on function public.set_updated_at() to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- uploads
-- ---------------------------------------------------------------------------

create table public.uploads (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  filename text not null check (char_length(filename) > 0),
  storage_path text not null check (
    char_length(storage_path) > 0
    and storage_path !~ '\.\.'
  ),
  bucket text not null default 'network-uploads' check (bucket = 'network-uploads'),
  content_type text,
  file_kind text not null check (file_kind in ('pcap', 'pcapng', 'json', 'pdf')),
  size_bytes bigint not null check (size_bytes >= 0),
  sha256 text not null check (sha256 ~* '^[a-f0-9]{64}$'),
  status text not null default 'pending' check (status in ('pending', 'uploaded', 'failed')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint uploads_id_user_key unique (id, user_id)
);

comment on table public.uploads is
  'Uploaded PCAP, JSON, and PDF files. Bytes live in the private network-uploads bucket.';

create index uploads_user_id_idx on public.uploads (user_id);
create index uploads_status_idx on public.uploads (status);

create trigger uploads_set_updated_at
before update on public.uploads
for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- analysis_jobs
-- One job per upload. (id, user_id) is the parent key for child rows.
-- ---------------------------------------------------------------------------

create table public.analysis_jobs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  upload_id uuid not null,
  status text not null default 'queued' check (
    status in ('queued', 'processing', 'completed', 'failed')
  ),
  progress integer not null default 0 check (progress >= 0 and progress <= 100),
  error_message text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint analysis_jobs_upload_id_key unique (upload_id),
  constraint analysis_jobs_id_user_key unique (id, user_id),
  constraint analysis_jobs_upload_owner_fkey
    foreign key (upload_id, user_id)
    references public.uploads (id, user_id)
    on delete cascade
);

comment on table public.analysis_jobs is
  'One processing job per upload. Child rows must use the same user_id.';

create index analysis_jobs_user_id_idx on public.analysis_jobs (user_id);
create index analysis_jobs_status_idx on public.analysis_jobs (status);

create trigger analysis_jobs_set_updated_at
before update on public.analysis_jobs
for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- network_events
-- Aggregated flows and document evidence. Not one row per raw packet.
-- ---------------------------------------------------------------------------

create table public.network_events (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  source_ip inet,
  destination_ip inet,
  source_port integer check (source_port is null or source_port between 0 and 65535),
  destination_port integer check (destination_port is null or destination_port between 0 and 65535),
  protocol text,
  packet_count bigint not null default 0 check (packet_count >= 0),
  byte_count bigint not null default 0 check (byte_count >= 0),
  first_seen timestamptz,
  last_seen timestamptz,
  tcp_flags text[],
  dns_query text,
  evidence_type text not null check (
    evidence_type in ('aggregated', 'packet_sample', 'document')
  ),
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint network_events_job_owner_fkey
    foreign key (job_id, user_id)
    references public.analysis_jobs (id, user_id)
    on delete cascade
);

comment on table public.network_events is
  'Aggregated traffic and extracted document evidence for one analysis job.';

create index network_events_job_id_idx on public.network_events (job_id);
create index network_events_user_id_idx on public.network_events (user_id);

-- ---------------------------------------------------------------------------
-- threat_analyses
-- ---------------------------------------------------------------------------

create table public.threat_analyses (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  model text not null check (char_length(model) > 0),
  prompt_version text not null check (char_length(prompt_version) > 0),
  findings jsonb not null,
  created_at timestamptz not null default now(),
  constraint threat_analyses_job_id_key unique (job_id),
  constraint threat_analyses_id_user_key unique (id, user_id),
  constraint threat_analyses_job_owner_fkey
    foreign key (job_id, user_id)
    references public.analysis_jobs (id, user_id)
    on delete cascade
);

comment on table public.threat_analyses is
  'One validated LLM finding set per analysis job.';

create index threat_analyses_user_id_idx on public.threat_analyses (user_id);

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------

create table public.alerts (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  analysis_id uuid,
  title text not null check (char_length(title) > 0),
  severity text not null check (severity in ('critical', 'high', 'medium', 'low')),
  category text not null check (char_length(category) > 0),
  source_ip inet,
  destination_ip inet,
  explanation text,
  evidence jsonb not null default '[]'::jsonb,
  recommendations jsonb not null default '[]'::jsonb,
  status text not null default 'open' check (
    status in ('open', 'investigating', 'resolved', 'dismissed')
  ),
  detected_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint alerts_job_owner_fkey
    foreign key (job_id, user_id)
    references public.analysis_jobs (id, user_id)
    on delete cascade,
  constraint alerts_analysis_owner_fkey
    foreign key (analysis_id, user_id)
    references public.threat_analyses (id, user_id)
    on delete set null (analysis_id)
);

comment on table public.alerts is
  'Security alerts for an investigation. Status changes require the owner.';

create index alerts_user_id_idx on public.alerts (user_id);
create index alerts_job_id_idx on public.alerts (job_id);
create index alerts_status_idx on public.alerts (status);
create index alerts_severity_idx on public.alerts (severity);

create trigger alerts_set_updated_at
before update on public.alerts
for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- reports
-- ---------------------------------------------------------------------------

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  storage_path text check (
    storage_path is null
    or (char_length(storage_path) > 0 and storage_path !~ '\.\.')
  ),
  bucket text not null default 'investigation-reports' check (bucket = 'investigation-reports'),
  status text not null default 'pending' check (status in ('pending', 'ready', 'failed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint reports_job_id_key unique (job_id),
  constraint reports_job_owner_fkey
    foreign key (job_id, user_id)
    references public.analysis_jobs (id, user_id)
    on delete cascade
);

comment on table public.reports is
  'Generated investigation PDF metadata. The file lives in investigation-reports.';

create index reports_user_id_idx on public.reports (user_id);

create trigger reports_set_updated_at
before update on public.reports
for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- ip_geolocations
-- Shared cache. Authenticated users may read. Only the service role may write.
-- Private, loopback, multicast, and documentation ranges are rejected.
-- ---------------------------------------------------------------------------

create table public.ip_geolocations (
  id uuid primary key default gen_random_uuid(),
  ip inet not null,
  country text,
  country_code text check (country_code is null or country_code ~ '^[A-Z]{2}$'),
  city text,
  latitude double precision check (latitude is null or latitude between -90 and 90),
  longitude double precision check (longitude is null or longitude between -180 and 180),
  source text not null default 'maxmind' check (char_length(source) > 0),
  looked_up_at timestamptz not null default now(),
  constraint ip_geolocations_ip_key unique (ip),
  constraint ip_geolocations_global_unicast check (
    (
      family(ip) = 4
      and not (
        ip <<= '0.0.0.0/8'
        or ip <<= '10.0.0.0/8'
        or ip <<= '100.64.0.0/10'
        or ip <<= '127.0.0.0/8'
        or ip <<= '169.254.0.0/16'
        or ip <<= '172.16.0.0/12'
        or ip <<= '192.0.0.0/24'
        or ip <<= '192.0.2.0/24'
        or ip <<= '192.168.0.0/16'
        or ip <<= '198.18.0.0/15'
        or ip <<= '198.51.100.0/24'
        or ip <<= '203.0.113.0/24'
        or ip <<= '224.0.0.0/4'
        or ip <<= '240.0.0.0/4'
      )
    )
    or (
      family(ip) = 6
      and not (
        ip <<= '::/128'
        or ip <<= '::1/128'
        or ip <<= '::ffff:0:0/96'
        or ip <<= 'fc00::/7'
        or ip <<= 'fe80::/10'
        or ip <<= 'ff00::/8'
        or ip <<= '2001:db8::/32'
      )
    )
  )
);

comment on table public.ip_geolocations is
  'Approximate public-IP geolocation cache. Not an attacker location.';

-- ---------------------------------------------------------------------------
-- Privileges and row level security
-- ---------------------------------------------------------------------------

revoke all on table
  public.uploads,
  public.analysis_jobs,
  public.network_events,
  public.threat_analyses,
  public.alerts,
  public.reports,
  public.ip_geolocations
from anon, authenticated;

grant select, insert, update, delete on table
  public.uploads,
  public.analysis_jobs,
  public.network_events,
  public.threat_analyses,
  public.alerts,
  public.reports
to authenticated;

grant select on table public.ip_geolocations to authenticated;

grant all on table
  public.uploads,
  public.analysis_jobs,
  public.network_events,
  public.threat_analyses,
  public.alerts,
  public.reports,
  public.ip_geolocations
to service_role;

alter table public.uploads enable row level security;
alter table public.analysis_jobs enable row level security;
alter table public.network_events enable row level security;
alter table public.threat_analyses enable row level security;
alter table public.alerts enable row level security;
alter table public.reports enable row level security;
alter table public.ip_geolocations enable row level security;

-- uploads
create policy "uploads_select"
on public.uploads for select to authenticated
using ((select auth.uid()) = user_id);

create policy "uploads_insert"
on public.uploads for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "uploads_update"
on public.uploads for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "uploads_delete"
on public.uploads for delete to authenticated
using ((select auth.uid()) = user_id);

-- analysis_jobs
create policy "analysis_jobs_select"
on public.analysis_jobs for select to authenticated
using ((select auth.uid()) = user_id);

create policy "analysis_jobs_insert"
on public.analysis_jobs for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "analysis_jobs_update"
on public.analysis_jobs for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "analysis_jobs_delete"
on public.analysis_jobs for delete to authenticated
using ((select auth.uid()) = user_id);

-- network_events
create policy "network_events_select"
on public.network_events for select to authenticated
using ((select auth.uid()) = user_id);

create policy "network_events_insert"
on public.network_events for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "network_events_update"
on public.network_events for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "network_events_delete"
on public.network_events for delete to authenticated
using ((select auth.uid()) = user_id);

-- threat_analyses
create policy "threat_analyses_select"
on public.threat_analyses for select to authenticated
using ((select auth.uid()) = user_id);

create policy "threat_analyses_insert"
on public.threat_analyses for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "threat_analyses_update"
on public.threat_analyses for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "threat_analyses_delete"
on public.threat_analyses for delete to authenticated
using ((select auth.uid()) = user_id);

-- alerts
create policy "alerts_select"
on public.alerts for select to authenticated
using ((select auth.uid()) = user_id);

create policy "alerts_insert"
on public.alerts for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "alerts_update"
on public.alerts for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "alerts_delete"
on public.alerts for delete to authenticated
using ((select auth.uid()) = user_id);

-- reports
create policy "reports_select"
on public.reports for select to authenticated
using ((select auth.uid()) = user_id);

create policy "reports_insert"
on public.reports for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "reports_update"
on public.reports for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "reports_delete"
on public.reports for delete to authenticated
using ((select auth.uid()) = user_id);

-- ip_geolocations: read-only for signed-in users. No write policies.
create policy "ip_geolocations_select"
on public.ip_geolocations for select to authenticated
using (true);

-- ---------------------------------------------------------------------------
-- Private storage buckets
-- Bucket rows are configuration. File bytes are uploaded through the Storage API.
-- ---------------------------------------------------------------------------

insert into storage.buckets (id, name, public, file_size_limit)
values
  ('network-uploads', 'network-uploads', false, 52428800),
  ('investigation-reports', 'investigation-reports', false, 10485760)
on conflict (id) do nothing;

create policy "network_uploads_select"
on storage.objects for select to authenticated
using (
  bucket_id = 'network-uploads'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

create policy "network_uploads_insert"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'network-uploads'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

create policy "network_uploads_update"
on storage.objects for update to authenticated
using (
  bucket_id = 'network-uploads'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
)
with check (
  bucket_id = 'network-uploads'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

create policy "network_uploads_delete"
on storage.objects for delete to authenticated
using (
  bucket_id = 'network-uploads'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);

create policy "investigation_reports_select"
on storage.objects for select to authenticated
using (
  bucket_id = 'investigation-reports'
  and (storage.foldername(name))[1] = (select auth.uid()::text)
);
