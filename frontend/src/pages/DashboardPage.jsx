import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { useEffect, useState } from "react"
import { api } from "../lib/api"
import { useGet } from "../lib/useGet"
import { formatWhen, PageIntro, Panel, Severity } from "../components/ui"

const chartTooltip = {
  contentStyle: { background: "#101a2b", border: "1px solid #24344d", borderRadius: 8 },
  labelStyle: { color: "#e8eefc" },
}

function Stat({ label, value }) {
  return (
    <div className="rounded-xl border border-[#24344d] bg-[#101a2b] px-4 py-3">
      <p className="text-xs uppercase tracking-wide text-[#93a4c3]">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{Number(value || 0).toLocaleString()}</p>
    </div>
  )
}

export function DashboardPage() {
  const [poll, setPoll] = useState(0)
  const { data, error, loading } = useGet("/api/v1/dashboard", poll)

  useEffect(() => {
    const status = data?.job_status
    if (!status) return undefined
    const active = (status.queued || 0) + (status.processing || 0) > 0
    setPoll(active ? 3000 : 0)
    if ((status.queued || 0) > 0) {
      api.post("/api/v1/analysis/run-queued").catch(() => {})
    }
    return undefined
  }, [data])

  return (
    <div>
      <PageIntro
        title="Security dashboard"
        text="Counts come from your Supabase tables. Empty values mean no matching rows yet, not sample traffic."
      />
      {loading ? <p className="text-sm text-[#93a4c3]">Loading investigation data…</p> : null}
      {error ? <p className="rounded-lg bg-rose-500/10 px-3 py-2 text-sm text-rose-200">{error}</p> : null}
      {data ? <DashboardBody data={data} /> : null}
    </div>
  )
}

function DashboardBody({ data }) {
  return (
    <div className="space-y-4">
      {data.partial ? (
        <p className="rounded-lg bg-amber-500/10 px-3 py-2 text-sm text-amber-100">
          This summary hit the row cap, so the totals below are incomplete.
        </p>
      ) : null}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Uploaded files" value={data.uploads_total} />
        <Stat label="Analyzed captures" value={data.analyses_completed} />
        <Stat label="Packets" value={data.packets_total} />
        <Stat label="Connections" value={data.connections_total} />
        <Stat label="Threats" value={data.threats_total} />
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {Object.entries(data.severity).map(([level, count]) => (
          <div key={level} className="flex items-center justify-between rounded-xl border border-[#24344d] bg-[#101a2b] px-4 py-3">
            <Severity value={level} />
            <span className="text-lg font-semibold">{count}</span>
          </div>
        ))}
      </div>
      <Panel title="Analysis status">
        <div className="grid gap-2 sm:grid-cols-4">
          {Object.entries(data.job_status).map(([status, count]) => (
            <p key={status} className="text-sm text-[#d5def0]">
              <span className="text-[#93a4c3]">{status}</span> {count}
            </p>
          ))}
        </div>
      </Panel>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Traffic timeline">
          {data.timeline.length === 0 ? (
            <p className="text-sm text-[#93a4c3]">No aggregated packet times yet.</p>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.timeline}>
                  <CartesianGrid stroke="#24344d" />
                  <XAxis dataKey="date" stroke="#93a4c3" />
                  <YAxis stroke="#93a4c3" allowDecimals={false} />
                  <Tooltip {...chartTooltip} />
                  <Area dataKey="packets" stroke="#2ee6c7" fill="#2ee6c733" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
        <Panel title="Protocol distribution">
          {data.protocols.length === 0 ? (
            <p className="text-sm text-[#93a4c3]">No protocols stored yet.</p>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.protocols}>
                  <CartesianGrid stroke="#24344d" />
                  <XAxis dataKey="protocol" stroke="#93a4c3" />
                  <YAxis stroke="#93a4c3" allowDecimals={false} />
                  <Tooltip {...chartTooltip} />
                  <Bar dataKey="count" fill="#7dd3fc" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <IpList title="Top source IPs" rows={data.top_source_ips} />
        <IpList title="Top destination IPs" rows={data.top_destination_ips} />
        <Panel title="Recent investigations">
          {data.recent_investigations.length === 0 ? (
            <p className="text-sm text-[#93a4c3]">No analysis jobs yet.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {data.recent_investigations.map((job) => (
                <li key={job.id} className="flex items-center justify-between gap-3">
                  <span>{job.filename}</span>
                  <span className="text-[#93a4c3]">{job.status}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Latest alerts">
          {data.latest_alerts.length === 0 ? (
            <p className="text-sm text-[#93a4c3]">No alerts yet.</p>
          ) : (
            <ul className="space-y-3 text-sm">
              {data.latest_alerts.map((alert) => (
                <li key={alert.id}>
                  <div className="flex items-center justify-between gap-3">
                    <span>{alert.title}</span>
                    <Severity value={alert.severity} />
                  </div>
                  <p className="text-[#93a4c3]">{formatWhen(alert.detected_at)}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}

function IpList({ title, rows }) {
  return (
    <Panel title={title}>
      {rows.length === 0 ? (
        <p className="text-sm text-[#93a4c3]">No addresses stored yet.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {rows.map((row) => (
            <li key={row.ip} className="flex justify-between gap-3">
              <span className="font-mono">{row.ip}</span>
              <span className="text-[#93a4c3]">{row.count}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
