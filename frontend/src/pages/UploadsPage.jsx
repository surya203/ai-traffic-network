import { useState } from "react"
import { supabase } from "../lib/supabase"
import { api, errorMessage } from "../lib/api"
import { useAuth } from "../auth/AuthProvider"
import { useGet } from "../lib/useGet"
import { Empty, formatBytes, formatWhen, PageIntro, Panel } from "../components/ui"

const MAX_BYTES = 50 * 1024 * 1024
const KINDS = { pcap: "pcap", pcapng: "pcapng", json: "json", pdf: "pdf" }

function kindFor(name) {
  const extension = name.toLowerCase().split(".").pop()
  return KINDS[extension] || null
}

async function sha256Hex(file) {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer())
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("")
}

export function UploadsPage() {
  const { session } = useAuth()
  const { data, error, loading, reload } = useGet("/api/v1/uploads")
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)
  const [stage, setStage] = useState("")

  async function takeFile(file) {
    setMessage("")
    const fileKind = kindFor(file.name)
    if (!fileKind) {
      setMessage("Use a .pcap, .pcapng, .json, or .pdf file.")
      return
    }
    if (file.size <= 0 || file.size > MAX_BYTES) {
      setMessage("File must be between 1 byte and 50 MB.")
      return
    }
    const userId = session?.user?.id
    if (!userId || !supabase) {
      setMessage("Sign in before uploading.")
      return
    }

    const safeName = file.name.replace(/[^\w.\-]+/g, "_").slice(0, 120)
    const storagePath = `${userId}/${crypto.randomUUID()}-${safeName}`
    setBusy(true)
    try {
      setStage("Hashing")
      const sha256 = await sha256Hex(file)
      setStage("Uploading to private storage")
      const uploaded = await supabase.storage.from("network-uploads").upload(storagePath, file, {
        upsert: false,
        contentType: file.type || "application/octet-stream",
      })
      if (uploaded.error) throw uploaded.error
      setStage("Saving the investigation record")
      try {
        await api.post("/api/v1/uploads/complete", {
          filename: file.name,
          storage_path: storagePath,
          file_kind: fileKind,
          size_bytes: file.size,
          sha256,
          content_type: file.type || null,
        })
      } catch (err) {
        await supabase.storage.from("network-uploads").remove([storagePath])
        throw err
      }
      setMessage("File stored. Analysis is starting.")
      reload()
      api.post("/api/v1/analysis/run-queued").catch(() => {})
    } catch (err) {
      setMessage(err?.response ? errorMessage(err, "Upload failed") : err.message || "Upload failed")
    } finally {
      setBusy(false)
      setStage("")
    }
  }

  async function removeUpload(row) {
    if (!window.confirm(`Delete ${row.filename}?`)) return
    setMessage("")
    try {
      await api.delete(`/api/v1/uploads/${row.id}`)
      if (row.storage_path && supabase) {
        await supabase.storage.from("network-uploads").remove([row.storage_path])
      }
      reload()
    } catch (err) {
      setMessage(errorMessage(err, "Could not delete that upload"))
    }
  }

  return (
    <div>
      <PageIntro
        title="Upload network data"
        text="Files go directly to the private network-uploads bucket under your user id. They are not sent through the API server."
      />
      <label
        className="mb-4 block rounded-xl border border-dashed border-[#2ee6c7] bg-[#101a2b] px-4 py-10 text-center"
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault()
          const file = event.dataTransfer.files?.[0]
          if (file) takeFile(file)
        }}
      >
        <p className="text-sm">{busy ? stage : "Drop a PCAP, PCAPNG, JSON, or PDF file here"}</p>
        <input
          type="file"
          accept=".pcap,.pcapng,.json,.pdf"
          className="mt-3 text-sm"
          disabled={busy}
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) takeFile(file)
            event.target.value = ""
          }}
        />
      </label>
      {message ? <p className="mb-4 text-sm text-[#d5def0]">{message}</p> : null}
      <Panel title="Upload history">
        {loading ? <p className="text-sm text-[#93a4c3]">Loading uploads…</p> : null}
        {error ? <p className="text-sm text-rose-200">{error}</p> : null}
        {data && data.uploads.length === 0 ? <Empty>No files stored yet.</Empty> : null}
        {data && data.uploads.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-[#93a4c3]">
                <tr>
                  <th className="py-2 pr-3 font-medium">File</th>
                  <th className="py-2 pr-3 font-medium">Kind</th>
                  <th className="py-2 pr-3 font-medium">Size</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">Added</th>
                  <th className="py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {data.uploads.map((row) => (
                  <tr key={row.id} className="border-t border-[#24344d]">
                    <td className="py-2 pr-3">{row.filename}</td>
                    <td className="py-2 pr-3">{row.file_kind}</td>
                    <td className="py-2 pr-3">{formatBytes(row.size_bytes)}</td>
                    <td className="py-2 pr-3">{row.status}</td>
                    <td className="py-2 pr-3">{formatWhen(row.created_at)}</td>
                    <td className="py-2 text-right">
                      <button type="button" className="text-[#2ee6c7]" onClick={() => removeUpload(row)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Panel>
    </div>
  )
}
