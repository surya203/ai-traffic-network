import { useCallback, useEffect, useState } from "react"
import { api, errorMessage } from "../lib/api"

export function useGet(path, pollMs = 0) {
  const [data, setData] = useState(null)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const reload = useCallback(() => setTick((value) => value + 1), [])

  useEffect(() => {
    let cancelled = false
    if (tick === 0) setLoading(true)
    api
      .get(path)
      .then((response) => {
        if (!cancelled) setData(response.data)
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err, "Could not load data"))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [path, tick])

  useEffect(() => {
    if (!pollMs) return undefined
    const timer = setInterval(() => reload(), pollMs)
    return () => clearInterval(timer)
  }, [pollMs, reload])

  return { data, error, loading, reload }
}
