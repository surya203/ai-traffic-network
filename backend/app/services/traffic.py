import json
import os
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO


def parse_json_bytes(payload: bytes) -> list[dict]:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The JSON file could not be read") from exc

    records = parsed
    if isinstance(parsed, dict):
        records = parsed.get("events") or parsed.get("connections") or parsed.get("flows")
    if not isinstance(records, list):
        return [_document("json", "The JSON file has no connection list.", {"top_level": type(parsed).__name__})]

    flows = []
    for item in records:
        if not isinstance(item, dict):
            continue
        source = _first(item, "source_ip", "src_ip", "src", "source")
        destination = _first(item, "destination_ip", "dest_ip", "dst_ip", "dst", "destination")
        if not source and not destination:
            continue
        flows.append(
            {
                "source_ip": _text(source),
                "destination_ip": _text(destination),
                "source_port": _port(item.get("source_port", item.get("src_port"))),
                "destination_port": _port(item.get("destination_port", item.get("dest_port", item.get("dst_port")))),
                "protocol": _text(item.get("protocol")),
                "packet_count": _count(item.get("packet_count", item.get("packets", 1))),
                "byte_count": _count(item.get("byte_count", item.get("bytes", 0))),
                "first_seen": _text(item.get("first_seen") or item.get("timestamp")),
                "last_seen": _text(item.get("last_seen") or item.get("timestamp")),
                "tcp_flags": [],
                "dns_query": _text(item.get("dns_query") or item.get("query")),
                "evidence_type": "aggregated",
                "details": {},
            }
        )
    if flows:
        return flows
    return [_document("json", "No connection fields were found in the JSON.", {"records": len(records)})]


def parse_pdf_bytes(payload: bytes) -> list[dict]:
    from pypdf import PdfReader

    reader = PdfReader(BytesIO(payload))
    parts = []
    for page in reader.pages[:20]:
        parts.append(page.extract_text() or "")
    text = "\n".join(parts).strip()
    return [
        _document(
            "pdf",
            "Text was extracted from the PDF. It is supporting text, not packet evidence.",
            {"excerpt": text[:4000], "page_count": len(reader.pages)},
        )
    ]


def parse_pcap_bytes(payload: bytes) -> list[dict]:
    suffix = ".pcap"
    handle, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(handle, payload)
        os.close(handle)
        handle = None
        return _read_pcap(path)
    finally:
        if handle is not None:
            os.close(handle)
        if os.path.exists(path):
            os.remove(path)


def _read_pcap(path: str) -> list[dict]:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    groups = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": None, "last": None, "flags": set(), "dns": None})
    seen = 0
    with PcapReader(path) as reader:
        for packet in reader:
            seen += 1
            if seen > 100_000:
                break
            network = packet.getlayer(IP) or packet.getlayer(IPv6)
            if network is None:
                continue
            source = str(network.src)
            destination = str(network.dst)
            source_port = None
            destination_port = None
            protocol = "IP"
            flags = ""
            dns_name = None
            if packet.haslayer(TCP):
                protocol = "TCP"
                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)
                flags = str(packet[TCP].flags)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                raw_name = packet[DNS].qd.qname
                dns_name = raw_name.decode(errors="ignore").rstrip(".") if isinstance(raw_name, bytes) else str(raw_name).rstrip(".")
            when = datetime.fromtimestamp(float(packet.time), timezone.utc)
            key = (source, destination, source_port, destination_port, protocol)
            group = groups[key]
            group["packets"] += 1
            group["bytes"] += len(packet)
            group["first"] = when if group["first"] is None or when < group["first"] else group["first"]
            group["last"] = when if group["last"] is None or when > group["last"] else group["last"]
            if flags:
                group["flags"].add(flags)
            if dns_name:
                group["dns"] = dns_name

    flows = []
    for (source, destination, source_port, destination_port, protocol), group in groups.items():
        flows.append(
            {
                "source_ip": source,
                "destination_ip": destination,
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol,
                "packet_count": group["packets"],
                "byte_count": group["bytes"],
                "first_seen": group["first"].isoformat() if group["first"] else None,
                "last_seen": group["last"].isoformat() if group["last"] else None,
                "tcp_flags": sorted(group["flags"]),
                "dns_query": group["dns"],
                "evidence_type": "aggregated",
                "details": {},
            }
        )
    flows.sort(key=lambda item: item["packet_count"], reverse=True)
    if seen > 100_000:
        for flow in flows:
            flow["details"] = {"capture_truncated": True}
    return flows[:2000]


def analyze_flows(flows: list[dict]) -> dict:
    aggregated = [flow for flow in flows if flow.get("evidence_type") == "aggregated"]
    findings = []
    if not aggregated:
        findings.append(
            _finding(
                category="document_only",
                title="No packet flows in this file",
                severity="low",
                confidence=0.9,
                explanation="The file produced supporting text or no readable connections. That is not packet evidence and does not show an attack.",
                evidence=["No aggregated IP flows were extracted"],
                recommendations=["Upload a PCAP or a JSON connection list if you need traffic analysis"],
            )
        )
        return {"findings": findings}

    by_source = defaultdict(lambda: {"ports": set(), "destinations": set(), "packets": 0, "flows": 0})
    pair_packets = defaultdict(int)
    dns_names = set()
    for flow in aggregated:
        source = flow.get("source_ip") or "unknown"
        destination = flow.get("destination_ip") or "unknown"
        bucket = by_source[source]
        if flow.get("destination_port") is not None:
            bucket["ports"].add(flow["destination_port"])
        bucket["destinations"].add(destination)
        bucket["packets"] += int(flow.get("packet_count") or 0)
        bucket["flows"] += 1
        pair_packets[(source, destination)] += int(flow.get("packet_count") or 0)
        if flow.get("dns_query"):
            dns_names.add(flow["dns_query"])

    for source, bucket in by_source.items():
        port_count = len(bucket["ports"])
        if port_count >= 15:
            findings.append(
                _finding(
                    category="possible_port_scanning",
                    title="Potential port scanning activity",
                    severity="high" if port_count >= 30 else "medium",
                    confidence=0.55 if port_count < 30 else 0.75,
                    explanation=(
                        f"{source} contacted {port_count} destination ports across {bucket['flows']} aggregated flows. "
                        "That pattern can appear during a port scan. This file alone does not prove an attack."
                    ),
                    evidence=[
                        f"{port_count} unique destination ports",
                        f"{bucket['flows']} aggregated flows",
                        f"{bucket['packets']} packets from this source",
                    ],
                    recommendations=["Compare the source with change windows and firewall logs", "Check whether the activity was an authorized scan"],
                    source_ip=source,
                )
            )
        if bucket["flows"] >= 25 and len(bucket["destinations"]) >= 10:
            findings.append(
                _finding(
                    category="repeated_connection_attempts",
                    title="Many outbound connections from one source",
                    severity="medium",
                    confidence=0.5,
                    explanation=(
                        f"{source} appears in {bucket['flows']} aggregated flows to {len(bucket['destinations'])} destinations. "
                        "Repeated connections can be normal services or probing. Human review is required."
                    ),
                    evidence=[f"{bucket['flows']} flows", f"{len(bucket['destinations'])} destinations"],
                    recommendations=["Review which destinations are expected for this host"],
                    source_ip=source,
                )
            )

    for (source, destination), packets in pair_packets.items():
        if packets >= 5000:
            findings.append(
                _finding(
                    category="possible_high_volume",
                    title="High packet volume on one path",
                    severity="medium",
                    confidence=0.45,
                    explanation=(
                        f"{source} sent {packets} packets to {destination} in this file. "
                        "High volume can be a transfer, a backup, or a flood. It is not attributed to an attack here."
                    ),
                    evidence=[f"{packets} packets on one source and destination pair"],
                    recommendations=["Check the application and the time window before treating this as hostile"],
                    source_ip=source,
                    destination_ip=destination,
                )
            )

    if len(dns_names) >= 25:
        findings.append(
            _finding(
                category="possible_dns_anomaly",
                title="Many distinct DNS names",
                severity="low",
                confidence=0.4,
                explanation=(
                    f"The capture includes {len(dns_names)} distinct DNS names. "
                    "That can be normal browsing or automated lookups. It is not proof of tunneling or an attack."
                ),
                evidence=[f"{len(dns_names)} DNS names"],
                recommendations=["Review the busiest names against expected resolvers"],
            )
        )

    if not findings:
        findings.append(
            _finding(
                category="no_threshold_crossed",
                title="No threshold was crossed",
                severity="low",
                confidence=0.6,
                explanation=(
                    f"{len(aggregated)} aggregated flows were stored. "
                    "None of the volume, port, or DNS thresholds were crossed. That is not a declaration that the traffic is safe."
                ),
                evidence=[f"{len(aggregated)} aggregated flows"],
                recommendations=["Review the connection table if this capture was expected to contain an incident"],
            )
        )
    return {"findings": findings}


def _finding(category, title, severity, confidence, explanation, evidence, recommendations, source_ip=None, destination_ip=None):
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "explanation": explanation,
        "evidence": evidence,
        "recommendations": recommendations,
        "requires_human_review": True,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }


def _document(kind: str, note: str, details: dict) -> dict:
    return {
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "packet_count": 0,
        "byte_count": 0,
        "first_seen": None,
        "last_seen": None,
        "tcp_flags": [],
        "dns_query": None,
        "evidence_type": "document",
        "details": {"kind": kind, "note": note, **details},
    }


def _first(item: dict, *keys):
    for key in keys:
        if item.get(key) not in (None, ""):
            return item.get(key)
    return None


def _text(value):
    if value is None:
        return None
    return str(value)


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def _count(value) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(number, 0)
