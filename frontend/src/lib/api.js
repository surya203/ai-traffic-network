import axios from "axios"
import { supabase } from "./supabase"

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
})

api.interceptors.request.use(async (config) => {
  if (!supabase) return config
  const { data } = await supabase.auth.getSession()
  const token = data.session?.access_token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export function errorMessage(error, fallback) {
  const detail = error?.response?.data?.detail
  if (typeof detail === "string") return detail
  return fallback
}
