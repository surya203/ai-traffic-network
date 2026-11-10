import { useGet } from "../lib/useGet"
import { useAuth } from "../auth/AuthProvider"
import { PageIntro, Panel } from "../components/ui"

export function SettingsPage() {
  const { session } = useAuth()
  const { data, error, loading } = useGet("/api/v1/auth/me")

  return (
    <div>
      <PageIntro title="Settings" text="The API checks your Supabase session. The service role key stays on the server." />
      <Panel title="Signed-in administrator">
        {loading ? <p className="text-sm text-[#93a4c3]">Checking session…</p> : null}
        {error ? <p className="text-sm text-rose-200">{error}</p> : null}
        {data ? (
          <dl className="space-y-2 text-sm">
            <div>
              <dt className="text-[#93a4c3]">Email</dt>
              <dd>{data.email || session?.user?.email || "—"}</dd>
            </div>
            <div>
              <dt className="text-[#93a4c3]">User id</dt>
              <dd className="font-mono">{data.id}</dd>
            </div>
          </dl>
        ) : null}
      </Panel>
    </div>
  )
}
