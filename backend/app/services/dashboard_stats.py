from collections import Counter

SEVERITIES = ("critical", "high", "medium", "low")
JOB_STATUSES = ("queued", "processing", "completed", "failed")


def build_dashboard(*, uploads: list[dict], jobs: list[dict], events: list[dict], alerts: list[dict]) -> dict:
    filenames = {row.get("id"): row.get("filename") or "Unknown file" for row in uploads}
    severity = {name: 0 for name in SEVERITIES}
    for alert in alerts:
        level = alert.get("severity")
        if level in severity:
            severity[level] += 1

    job_status = {name: 0 for name in JOB_STATUSES}
    for job in jobs:
        status = job.get("status")
        if status in job_status:
            job_status[status] += 1

    packets = 0
    connections = 0
    protocols: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    timeline: Counter[str] = Counter()

    for event in events:
        packet_count = int(event.get("packet_count") or 0)
        packets += packet_count
        if event.get("evidence_type") == "aggregated":
            connections += 1
        protocols[event.get("protocol") or "unknown"] += 1
        if event.get("source_ip"):
            sources[str(event["source_ip"])] += 1
        if event.get("destination_ip"):
            destinations[str(event["destination_ip"])] += 1
        seen = event.get("first_seen")
        if seen:
            timeline[str(seen)[:10]] += packet_count

    recent = sorted(jobs, key=lambda row: row.get("created_at") or "", reverse=True)[:6]
    latest = sorted(alerts, key=lambda row: row.get("detected_at") or "", reverse=True)[:6]

    return {
        "uploads_total": len(uploads),
        "analyses_completed": job_status["completed"],
        "packets_total": packets,
        "connections_total": connections,
        "threats_total": len(alerts),
        "severity": severity,
        "job_status": job_status,
        "recent_investigations": [
            {
                "id": job.get("id"),
                "status": job.get("status"),
                "progress": job.get("progress") or 0,
                "created_at": job.get("created_at"),
                "filename": filenames.get(job.get("upload_id"), "Unknown file"),
            }
            for job in recent
        ],
        "latest_alerts": [
            {
                "id": alert.get("id"),
                "title": alert.get("title"),
                "severity": alert.get("severity"),
                "category": alert.get("category"),
                "status": alert.get("status"),
                "source_ip": alert.get("source_ip"),
                "destination_ip": alert.get("destination_ip"),
                "detected_at": alert.get("detected_at"),
            }
            for alert in latest
        ],
        "timeline": [{"date": day, "packets": timeline[day]} for day in sorted(timeline)],
        "protocols": [{"protocol": name, "count": count} for name, count in protocols.most_common()],
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in sources.most_common(5)],
        "top_destination_ips": [{"ip": ip, "count": count} for ip, count in destinations.most_common(5)],
    }
