export function formatBytes(bytes) {
  if (bytes == null) return "—"
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatWhen(value) {
  if (!value) return "—"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString()
}

const SEVERITY = {
  critical: "bg-rose-500/15 text-rose-300",
  high: "bg-orange-500/15 text-orange-300",
  medium: "bg-amber-500/15 text-amber-200",
  low: "bg-sky-500/15 text-sky-300",
}

export function Severity({ value }) {
  const tone = SEVERITY[value] || "bg-slate-500/15 text-slate-300"
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${tone}`}>{value || "—"}</span>
}

export function Panel({ title, children, action }) {
  return (
    <section className="rounded-xl border border-[#24344d] bg-[#101a2b] p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-medium text-[#d5def0]">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

export function Empty({ children }) {
  return <p className="text-sm text-[#93a4c3]">{children}</p>
}

export function PageIntro({ title, text }) {
  return (
    <header className="mb-6">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {text ? <p className="mt-1 max-w-3xl text-sm text-[#93a4c3]">{text}</p> : null}
    </header>
  )
}
