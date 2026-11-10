from app.services.traffic import analyze_flows, parse_json_bytes


def _flow(port, packets=1):
    return {
        "source_ip": "203.0.113.10",
        "destination_ip": "198.51.100.20",
        "source_port": 40000,
        "destination_port": port,
        "protocol": "TCP",
        "packet_count": packets,
        "byte_count": packets * 60,
        "evidence_type": "aggregated",
        "dns_query": None,
    }


def test_json_connections_become_flows():
    payload = b'{"connections":[{"source_ip":"203.0.113.8","destination_ip":"198.51.100.9","destination_port":443,"protocol":"TCP","packet_count":4}]}'
    flows = parse_json_bytes(payload)
    assert flows[0]["evidence_type"] == "aggregated"
    assert flows[0]["destination_port"] == 443
    assert flows[0]["packet_count"] == 4


def test_json_without_addresses_is_a_document():
    flows = parse_json_bytes(b'{"note":"hello"}')
    assert flows[0]["evidence_type"] == "document"
    assert flows[0]["source_ip"] is None


def test_many_ports_are_described_as_possible_scanning():
    result = analyze_flows([_flow(port) for port in range(1, 21)])
    categories = [item["category"] for item in result["findings"]]
    assert "possible_port_scanning" in categories
    finding = next(item for item in result["findings"] if item["category"] == "possible_port_scanning")
    assert "does not prove an attack" in finding["explanation"]
    assert finding["requires_human_review"] is True


def test_quiet_flow_does_not_invent_an_attack():
    result = analyze_flows([_flow(443, packets=3)])
    assert result["findings"][0]["category"] == "no_threshold_crossed"
