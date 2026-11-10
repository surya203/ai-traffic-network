import { CircleMarker, MapContainer, Popup, TileLayer } from "react-leaflet"
import "leaflet/dist/leaflet.css"
import { useGet } from "../lib/useGet"
import { Empty, PageIntro, Panel } from "../components/ui"

const COLORS = {
  critical: "#fb7185",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
}

function colorFor(ip, alerts) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 }
  let best = null
  for (const alert of alerts) {
    if (alert.source_ip === ip || alert.destination_ip === ip) {
      if (!best || rank[alert.severity] > rank[best]) best = alert.severity
    }
  }
  return best ? COLORS[best] : "#2ee6c7"
}

export function MapPage() {
  const geo = useGet("/api/v1/geolocation")
  const alerts = useGet("/api/v1/alerts")
  const locations = geo.data?.locations || []
  const plotted = locations.filter((row) => row.latitude != null && row.longitude != null)

  return (
    <div>
      <PageIntro
        title="Threat map"
        text="Markers use coordinates stored in ip_geolocations. Placement is approximate and does not identify a person or a physical attacker."
      />
      {geo.loading ? <p className="mb-3 text-sm text-[#93a4c3]">Loading locations…</p> : null}
      {geo.error ? <p className="mb-3 text-sm text-rose-200">{geo.error}</p> : null}
      <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom>
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {plotted.map((row) => (
          <CircleMarker
            key={row.ip}
            center={[row.latitude, row.longitude]}
            radius={8}
            pathOptions={{ color: colorFor(row.ip, alerts.data?.alerts || []) }}
          >
            <Popup>
              <div>
                <strong>{row.ip}</strong>
                <p>{[row.city, row.country].filter(Boolean).join(", ") || "No place name stored"}</p>
                <p>Source: {row.source}</p>
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
      <div className="mt-4">
        <Panel title="Stored locations">
          {locations.length === 0 ? <Empty>No public IP locations are stored yet.</Empty> : null}
          <ul className="space-y-2 text-sm">
            {locations.map((row) => (
              <li key={row.ip}>
                <span className="font-mono">{row.ip}</span>
                <span className="text-[#93a4c3]">
                  {" "}
                  {[row.city, row.country].filter(Boolean).join(", ") || "coordinates unavailable"}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  )
}
