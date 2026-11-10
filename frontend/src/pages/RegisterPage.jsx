import { useState } from "react"
import { Link, Navigate } from "react-router-dom"
import { useAuth } from "../auth/AuthProvider"

export function RegisterPage() {
  const { configured, session, signUp } = useAuth()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [busy, setBusy] = useState(false)

  if (session) return <Navigate to="/" replace />

  async function onSubmit(event) {
    event.preventDefault()
    setError("")
    setNotice("")
    if (password.length < 6) {
      setError("Use a password of at least 6 characters.")
      return
    }
    if (password !== confirm) {
      setError("The passwords do not match.")
      return
    }
    setBusy(true)
    try {
      const result = await signUp(email.trim(), password)
      if (result.needsConfirmation) {
        setNotice("Account created. Confirm the message Supabase sent to your email, then sign in.")
        setPassword("")
        setConfirm("")
      }
    } catch (err) {
      setError(err.message || "Registration failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={onSubmit} className="w-full max-w-md rounded-2xl border border-[#24344d] bg-[#101a2b] p-6">
        <p className="text-xs uppercase tracking-[0.18em] text-[#2ee6c7]">AI Network Sentinel</p>
        <h1 className="mt-2 text-2xl font-semibold">Create an account</h1>
        <p className="mt-2 text-sm text-[#93a4c3]">
          Registration creates a Supabase user. Your uploads and investigations stay private to that account.
        </p>
        {!configured ? (
          <p className="mt-4 rounded-lg bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
            Add VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY to frontend/.env, then restart the dev server.
          </p>
        ) : null}
        <label className="mt-5 block text-sm">
          Email
          <input
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="mt-1 w-full rounded-lg border border-[#24344d] bg-[#07111f] px-3 py-2"
          />
        </label>
        <label className="mt-3 block text-sm">
          Password
          <input
            type="password"
            required
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-1 w-full rounded-lg border border-[#24344d] bg-[#07111f] px-3 py-2"
          />
        </label>
        <label className="mt-3 block text-sm">
          Confirm password
          <input
            type="password"
            required
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            className="mt-1 w-full rounded-lg border border-[#24344d] bg-[#07111f] px-3 py-2"
          />
        </label>
        {error ? <p className="mt-3 text-sm text-rose-300">{error}</p> : null}
        {notice ? <p className="mt-3 text-sm text-[#d5def0]">{notice}</p> : null}
        <button
          type="submit"
          disabled={!configured || busy}
          className="mt-5 w-full rounded-lg bg-[#2ee6c7] px-3 py-2 text-sm font-semibold text-[#06221c] disabled:cursor-not-allowed disabled:bg-[#1c4f48] disabled:text-[#8eb9b1]"
        >
          {busy ? "Creating account…" : "Create account"}
        </button>
        <p className="mt-4 text-sm text-[#93a4c3]">
          Already registered?{" "}
          <Link to="/login" className="text-[#2ee6c7]">
            Sign in
          </Link>
        </p>
      </form>
    </div>
  )
}
