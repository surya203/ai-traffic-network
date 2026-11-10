import { NavLink, Outlet } from "react-router-dom"
import {
  Bell,
  FileText,
  LayoutDashboard,
  Map,
  MessageSquare,
  Search,
  Settings,
  ShieldAlert,
  Upload,
} from "lucide-react"
import { useAuth } from "../auth/AuthProvider"

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/uploads", label: "Upload Network Data", icon: Upload },
  { to: "/investigations", label: "Investigations", icon: Search },
  { to: "/threats", label: "Threat Intelligence", icon: ShieldAlert },
  { to: "/map", label: "Threat Map", icon: Map },
  { to: "/alerts", label: "Security Alerts", icon: Bell },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/assistant", label: "AI Assistant", icon: MessageSquare },
  { to: "/settings", label: "Settings", icon: Settings },
]

export function AppShell() {
  const { session, signOut } = useAuth()
  const email = session?.user?.email || "Signed in"

  return (
    <div className="min-h-screen md:grid md:grid-cols-[250px_1fr]">
      <aside className="border-b border-[#24344d] bg-[#0b1526] md:border-b-0 md:border-r">
        <div className="px-4 py-5">
          <p className="text-xs uppercase tracking-[0.18em] text-[#2ee6c7]">Sentinel</p>
          <p className="mt-1 text-sm text-[#93a4c3]">Network investigations</p>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-2 pb-3 md:flex-col md:overflow-visible">
          {NAV.map((item) => {
            const Icon = item.icon
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                    isActive ? "bg-[#16324a] text-white" : "text-[#b7c3da] hover:bg-[#122033]"
                  }`
                }
              >
                <Icon size={16} />
                {item.label}
              </NavLink>
            )
          })}
        </nav>
        <div className="hidden border-t border-[#24344d] px-4 py-4 md:block">
          <p className="truncate text-xs text-[#93a4c3]">{email}</p>
          <button type="button" onClick={signOut} className="mt-2 text-sm text-[#2ee6c7]">
            Log out
          </button>
        </div>
      </aside>
      <div>
        <div className="flex items-center justify-between border-b border-[#24344d] px-4 py-3 md:hidden">
          <p className="truncate text-xs text-[#93a4c3]">{email}</p>
          <button type="button" onClick={signOut} className="text-sm text-[#2ee6c7]">
            Log out
          </button>
        </div>
        <main className="px-4 py-6 md:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
