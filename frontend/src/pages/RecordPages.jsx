import { useEffect } from "react"
import { api } from "../lib/api"
import { useGet } from "../lib/useGet"
import { Empty, formatWhen, PageIntro, Panel, Severity } from "../components/ui"

export function InvestigationsPage() {
  const jobs = useGet("/api/v1/analysis")
  const uploads = useGet("/api/v1/uploads")
  const names = Object.fromEntries((uploads.data?.uploads || []).map((row) => [row.id, row.filename]))
  const list = jobs.data?.jobs || []
  const active = list.some((job) => job.status === "queued" || job.status === "processing")

  useEffect(() => {
    if (!list.some((job) => job.status === "queued")) return undefined
    api.post("/api/v1/analysis/run-queued").catch(() => {})
    return undefined
  }, [jobs.data])

  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(() => jobs.reload(), 2000)
    return () => clearInterval(timer)
  }, [active, jobs.reload])

  return (
    <div>
      <PageIntro
        title="Investigations"
        text="Queued files start analyzing on this page. Status refreshes while a job is running."
      />
      <Panel title="Jobs">
        {jobs.loading ? <p className="text-sm text-[#93a4c3]">Loading jobs…</p> : null}
        {jobs.error ? <p className="text-sm text-rose-200">{jobs.error}</p> : null}
        {jobs.data && jobs.data.jobs.length === 0 ? <Empty>No investigations yet.</Empty> : null}
        {jobs.data && jobs.data.jobs.length > 0 ? (
          <ul className="space-y-3 text-sm">
            {jobs.data.jobs.map((job) => (
              <li key={job.id} className="flex flex-wrap items-center justify-between gap-2 border-b border-[#24344d] pb-3">
                <div>
                  <p>{names[job.upload_id] || "Upload"}</p>
                  <p className="text-[#93a4c3]">{formatWhen(job.created_at)}</p>
                  {job.error_message ? <p className="text-rose-200">{job.error_message}</p> : null}
                </div>
                <p>
                  {job.status} · {job.progress || 0}%
                </p>
              </li>
            ))}
          </ul>
        ) : null}
      </Panel>
    </div>
  )
}

export function AlertsPage() {
  const { data, error, loading } = useGet("/api/v1/alerts")
  return (
    <div>
      <PageIntro title="Security alerts" text="Alerts are created from stored findings. Status changes and blocking actions are not automatic." />
      <Panel title="Alerts">
        {loading ? <p className="text-sm text-[#93a4c3]">Loading alerts…</p> : null}
        {error ? <p className="text-sm text-rose-200">{error}</p> : null}
        {data && data.alerts.length === 0 ? <Empty>No alerts yet.</Empty> : null}
        {data && data.alerts.length > 0 ? (
          <ul className="space-y-4 text-sm">
            {data.alerts.map((alert) => (
              <li key={alert.id} className="border-b border-[#24344d] pb-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{alert.title}</span>
                  <Severity value={alert.severity} />
                  <span className="text-[#93a4c3]">{alert.status}</span>
                </div>
                <p className="mt-1 text-[#93a4c3]">
                  {alert.category} · {alert.source_ip || "no source"} → {alert.destination_ip || "no destination"} · {formatWhen(alert.detected_at)}
                </p>
                {alert.explanation ? <p className="mt-1">{alert.explanation}</p> : null}
              </li>
            ))}
          </ul>
        ) : null}
      </Panel>
    </div>
  )
}

export function ThreatsPage() {
  const { data, error, loading } = useGet("/api/v1/threats")
  return (
    <div>
      <PageIntro title="Threat intelligence" text="Rule findings are stored for each analysis. When OpenAI is configured, its reviewer note is stored beside them. A note is not confirmation of an attack." />
      <Panel title="Stored analyses">
        {loading ? <p className="text-sm text-[#93a4c3]">Loading analyses…</p> : null}
        {error ? <p className="text-sm text-rose-200">{error}</p> : null}
        {data && data.threats.length === 0 ? <Empty>No threat analyses stored yet.</Empty> : null}
        {data?.threats?.map((row) => {
          const findings = Array.isArray(row.findings?.findings) ? row.findings.findings : []
          return (
            <article key={row.id} className="mb-4 border-b border-[#24344d] pb-4 text-sm">
              <p className="text-[#93a4c3]">
                {row.model} · {row.prompt_version} · {formatWhen(row.created_at)}
              </p>
              {row.findings?.analyst_note ? <p className="mt-2">{row.findings.analyst_note}</p> : null}
              {findings.length === 0 ? <p className="mt-2">No finding objects in the stored JSON.</p> : null}
              <ul className="mt-2 space-y-2">
                {findings.map((finding, index) => (
                  <li key={`${row.id}-${index}`}>
                    <span className="mr-2">{finding.title || finding.category || "Finding"}</span>
                    <Severity value={finding.severity} />
                    {finding.explanation ? <p className="mt-1 text-[#d5def0]">{finding.explanation}</p> : null}
                  </li>
                ))}
              </ul>
            </article>
          )
        })}
      </Panel>
    </div>
  )
}

export function ReportsPage() {
  const { data, error, loading } = useGet("/api/v1/reports")
  return (
    <div>
      <PageIntro title="Reports" text="Generated PDF reports will be listed here after they are stored in the private reports bucket." />
      <Panel title="Report files">
        {loading ? <p className="text-sm text-[#93a4c3]">Loading reports…</p> : null}
        {error ? <p className="text-sm text-rose-200">{error}</p> : null}
        {data && data.reports.length === 0 ? <Empty>No reports stored yet.</Empty> : null}
        {data?.reports?.map((report) => (
          <p key={report.id} className="border-b border-[#24344d] py-2 text-sm">
            {report.status} · {formatWhen(report.created_at)}
            {report.storage_path ? <span className="block text-[#93a4c3]">{report.storage_path}</span> : null}
          </p>
        ))}
      </Panel>
    </div>
  )
}
