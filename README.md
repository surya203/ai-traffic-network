# AI Network Sentinel

## Supabase setup

1. Create a project in the [Supabase dashboard](https://supabase.com/dashboard).
2. Open the SQL Editor, paste [`supabase/migrations/20261110140000_init.sql`](supabase/migrations/20261110140000_init.sql), and run it once.
3. Open the app and create an account. This project asks you to confirm that email before the first sign-in.
4. In Project Settings, copy the project URL, the publishable key, and the secret key. Copy the JWKS URL. Older projects may still show an anon key, a service role key, and a JWT secret.
5. Copy `.env.example` to `.env` and fill in those values. Keep `.env` out of git. The secret key stays on the backend.
6. Copy `frontend/.env.example` to `frontend/.env`. Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` to the same project URL and publishable key. Do not put the secret key in the frontend file.

The script creates `uploads`, `analysis_jobs`, `network_events`, `threat_analyses`, `alerts`, `reports`, and `ip_geolocations`.

Row level security is enabled. A signed-in user can read and change rows whose `user_id` is their own. A child row has to reference an analysis job owned by that same user. `ip_geolocations` is readable by any signed-in user. Writes to that cache use the service role.

Private buckets:

| Bucket | Limit | Who can write |
| --- | --- | --- |
| `network-uploads` | 50 MB | The signed-in user, only under `{user_id}/...` |
| `investigation-reports` | 10 MB | The backend, using the service role. The owner can read `{user_id}/...` |

Uploads can also be replaced or deleted by that owner. Downloads use signed URLs. Neither bucket is public.

The 50 MB cap matches the Supabase Free plan global file size limit. If the bucket insert fails because the project limit is lower, raise the global Storage limit to at least 50 MB and run the script again. A failed run in the SQL editor rolls back, so the script can be pasted a second time.

After it runs, confirm the tables and buckets:

```sql
select tablename, rowsecurity
from pg_tables
where schemaname = 'public'
  and tablename in (
    'uploads',
    'analysis_jobs',
    'network_events',
    'threat_analyses',
    'alerts',
    'reports',
    'ip_geolocations'
  )
order by tablename;

select id, public, file_size_limit
from storage.buckets
where id in ('network-uploads', 'investigation-reports');
```

`rowsecurity` should be true for every table. Both buckets should show `public = false`.

## Run locally

Backend, from the repository root:

```powershell
py -3 -m venv backend\.venv
backend\.venv\Scripts\python -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` and sign in with the Supabase administrator. If login says the email is not confirmed, confirm that user in the Supabase Authentication dashboard.

`GET /health` does not need a session. Dashboard, uploads, jobs, alerts, reports, and the map read your tables with the signed-in user's token, so row level security still applies. Uploaded files go to the `network-uploads` bucket. A new analysis job stays `queued` until a worker is added. Packet counts stay at zero until that worker stores `network_events`.

New Supabase projects sign access tokens with ES256. The API verifies those with the project JWKS endpoint. Older projects that still sign with HS256 also need `SUPABASE_JWT_SECRET`.
