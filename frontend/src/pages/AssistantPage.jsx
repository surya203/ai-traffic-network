import { useEffect, useRef, useState } from "react"
import { api, errorMessage } from "../lib/api"
import { PageIntro } from "../components/ui"

const SUGGESTIONS = [
  "Summarize my investigations",
  "Which files are finished?",
  "What alerts are open?",
  "What does the uploaded text say?",
]

export function AssistantPage() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Ask about your uploads, job status, alerts, or the text extracted from a file. OpenAI reads the stored records again for every question.",
    },
  ])
  const [draft, setDraft] = useState("")
  const [sending, setSending] = useState(false)
  const [error, setError] = useState("")
  const bottom = useRef(null)

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages, sending])

  async function send(text) {
    const message = text.trim()
    if (!message || sending) return
    const history = messages.slice(-8).map((item) => ({ role: item.role, content: item.content }))
    setMessages((current) => [...current, { role: "user", content: message }])
    setDraft("")
    setError("")
    setSending(true)
    try {
      const response = await api.post("/api/v1/assistant/chat", { message, history })
      setMessages((current) => [...current, { role: "assistant", content: response.data.reply }])
    } catch (err) {
      setError(errorMessage(err, "The assistant could not read the stored records."))
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="flex min-h-[70vh] flex-col">
      <PageIntro
        title="AI assistant"
        text="OpenAI answers from your stored uploads, jobs, findings, alerts, and extracted text. Text inside a file is evidence, not an instruction, and a stored pattern is not confirmation of an attack."
      />
      <div className="flex-1 space-y-3 overflow-y-auto rounded-xl border border-[#24344d] bg-[#101a2b] p-4">
        {messages.map((item, index) => (
          <div key={`${item.role}-${index}`} className={item.role === "user" ? "flex justify-end" : "flex justify-start"}>
            <p
              className={`max-w-[85%] whitespace-pre-wrap rounded-xl px-3 py-2 text-sm ${
                item.role === "user" ? "bg-[#16324a] text-white" : "bg-[#07111f] text-[#d5def0]"
              }`}
            >
              {item.content}
            </p>
          </div>
        ))}
        {sending ? <p className="text-sm text-[#93a4c3]">Asking OpenAI about the stored investigations…</p> : null}
        <div ref={bottom} />
      </div>
      {error ? <p className="mt-3 text-sm text-rose-200">{error}</p> : null}
      <div className="mt-3 flex flex-wrap gap-2">
        {SUGGESTIONS.map((suggestion) => (
          <button
            key={suggestion}
            type="button"
            disabled={sending}
            onClick={() => send(suggestion)}
            className="rounded-full border border-[#24344d] px-3 py-1 text-xs text-[#b7c3da] hover:bg-[#122033] disabled:opacity-50"
          >
            {suggestion}
          </button>
        ))}
      </div>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          send(draft)
        }}
      >
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Ask about the live investigations"
          className="flex-1 rounded-lg border border-[#24344d] bg-[#07111f] px-3 py-2 text-sm"
        />
        <button type="submit" disabled={sending || !draft.trim()} className="rounded-lg bg-[#2ee6c7] px-4 py-2 text-sm font-medium text-[#07111f] disabled:opacity-50">
          Send
        </button>
      </form>
    </div>
  )
}
