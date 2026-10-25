"""
Analyseur et dissecteur de paquets réseau Scapy pour Wireshark Web.
Extrait les métadonnées, les couches protocolaires et le dump hexadécimal/ASCII.
"""

from datetime import datetime
import binascii

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
    )
except ImportError:
    pass


def safe_hex(val, digits=4) -> str:
    """Formate un entier en hexadécimal de manière sécurisée même si None."""
    if val is None:
        return "0x" + "0" * digits
    try:
        return f"0x{int(val):0{digits}x}"
    except Exception:
        return str(val)


def safe_int(val, default=0) -> int:
    """Convertit en entier avec valeur par défaut si None ou échec."""
    if val is None:
        return default
    try:
        return int(val)
    except Exception:
        return default


def get_protocol_badge(protocol_name: str) -> str:
    """Retourne la classe CSS de badge pour le protocole."""
    proto = protocol_name.upper()
    mapping = {
        "DNS": "proto-dns",
        "HTTP": "proto-http",
        "HTTPS": "proto-tls",
        "TLS": "proto-tls",
        "TCP": "proto-tcp",
        "UDP": "proto-udp",
        "ICMP": "proto-icmp",
        "ARP": "proto-arp",
        "DHCP": "proto-udp",
        "NTP": "proto-udp",
        "IPV4": "proto-ip",
        "IPV6": "proto-ip",
    }
    return mapping.get(proto, "proto-default")


def get_tcp_flags_str(flags) -> str:
    """Convertit les flags TCP en chaîne lisible Wireshark style."""
    if flags is None:
        return ""
    flag_str = str(flags)
    mapping = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    active_flags = [mapping[c] for c in flag_str if c in mapping]
    return ", ".join(active_flags) if active_flags else flag_str


def extract_tls_sni(payload: bytes) -> str | None:
    """Tente d'extraire le Server Name Indication (SNI) d'un paquet TLS Client Hello."""
    try:
        if len(payload) < 43:
            return None
        sess_id_len = payload[43]
        pos = 44 + sess_id_len
        if pos + 2 > len(payload):
            return None
        cipher_suites_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return None
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(payload):
            return None
        extensions_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2

        limit = min(pos + extensions_len, len(payload))
        while pos + 4 <= limit:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            pos += 4
            if ext_type == 0:  # SNI extension
                if pos + 5 <= limit:
                    name_len = int.from_bytes(payload[pos + 3 : pos + 5], "big")
                    name = payload[pos + 5 : pos + 5 + name_len].decode("ascii", errors="ignore")
                    return name
            pos += ext_len
    except Exception:
        pass
    return None


def detect_application_protocol(pkt) -> tuple[str, str]:
    """
    Détecte le protocole applicatif et génère un résumé informatif style Wireshark.
    Retourne (nom_protocole, info_string).
    """
    # 1. ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op_name = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else f"Op={arp.op}")
        if arp.op == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            info = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            info = f"ARP {op_name} src={arp.psrc} dst={arp.pdst}"
        return "ARP", info

    # 2. DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        qr = "response" if getattr(dns, "qr", 0) == 1 else "query"
        dns_id = getattr(dns, "id", 0) or 0
        info_parts = [f"Standard {qr} 0x{dns_id:04x}"]

        qdcount = getattr(dns, "qdcount", None)
        if qdcount is None:
            qdcount = 1 if getattr(dns, "qd", None) else 0

        if qdcount > 0 and getattr(dns, "qd", None):
            qname = getattr(dns.qd, "qname", b"")
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype_num = getattr(dns.qd, "qtype", 1)
            type_names = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}
            qtype_str = type_names.get(qtype_num, f"Type {qtype_num}")
            info_parts.append(f"{qtype_str} {qname}")

        ancount = getattr(dns, "ancount", None)
        if ancount is None:
            ancount = 1 if getattr(dns, "an", None) else 0

        if getattr(dns, "qr", 0) == 1 and ancount > 0 and getattr(dns, "an", None):
            ans_parts = []
            curr_an = dns.an
            count = 0
            while curr_an and count < 2:
                rdata = getattr(curr_an, "rdata", None)
                if rdata:
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="ignore")
                    ans_parts.append(str(rdata))
                curr_an = getattr(curr_an, "payload", None)
                count += 1
            if ans_parts:
                info_parts.append("-> " + ", ".join(ans_parts))

        return "DNS", " ".join(info_parts)

    # 3. HTTP / Raw Inspection over TCP
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
        http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
        if any(payload.startswith(m) for m in http_methods):
            try:
                first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                return "HTTP", first_line
            except Exception:
                pass
        elif payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2"):
            try:
                first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                return "HTTP", first_line
            except Exception:
                pass

        # Détection TLS Client Hello / Server Hello
        if len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03:
            if len(payload) > 5 and payload[5] == 0x01:
                sni = extract_tls_sni(payload)
                if sni:
                    return "TLS", f"Client Hello (SNI: {sni})"
                return "TLS", "Client Hello"
            elif len(payload) > 5 and payload[5] == 0x02:
                return "TLS", "Server Hello"
            return "TLS", "Application Data / Handshake"

    # 4. ICMP
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        types_map = {
            0: "Echo (ping) reply",
            3: "Destination unreachable",
            8: "Echo (ping) request",
            11: "Time-to-live exceeded",
        }
        name = types_map.get(icmp.type, f"ICMP Type={icmp.type} Code={icmp.code}")
        seq = getattr(icmp, "seq", None)
        icmp_id = getattr(icmp, "id", None)
        extra = []
        if icmp_id is not None:
            extra.append(f"id={safe_hex(icmp_id)}")
        if seq is not None:
            extra.append(f"seq={seq}")
        info = f"{name} " + " ".join(extra) if extra else name
        return "ICMP", info.strip()

    # 5. TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags_str = get_tcp_flags_str(tcp.flags)
        sport = tcp.sport
        dport = tcp.dport
        payload_len = len(bytes(pkt[Raw])) if pkt.haslayer(Raw) else 0
        seq = getattr(tcp, "seq", 0) or 0
        ack = getattr(tcp, "ack", 0) or 0
        win = getattr(tcp, "window", 0) or 0
        info = f"{sport} → {dport} [{flags_str}] Seq={seq} Ack={ack} Win={win} Len={payload_len}"
        if sport == 443 or dport == 443:
            return "TLS", info
        return "TCP", info

    # 6. UDP
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        sport = udp.sport
        dport = udp.dport
        ulen = getattr(udp, "len", 0) or 0
        if sport == 53 or dport == 53:
            return "DNS", f"{sport} → {dport} Len={ulen}"
        if sport in (67, 68) or dport in (67, 68):
            return "DHCP", f"{sport} → {dport} Len={ulen}"
        if sport == 123 or dport == 123:
            return "NTP", f"Network Time Protocol Len={ulen}"
        if sport == 5555 or dport == 5555:
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else ""
            if dst_ip.startswith("224.") or dst_ip.startswith("239."):
                return "UDP", f"InduTwin Multicast {sport} → {dport} Len={ulen}"
            return "UDP", f"InduTwin {sport} → {dport} Len={ulen}"
        return "UDP", f"{sport} → {dport} Len={ulen}"

    # 7. IP seul
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return "IPv4", f"IPv4 proto={ip.proto} len={getattr(ip, 'len', 0)}"
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        return "IPv6", f"IPv6 nh={ip6.nh} len={getattr(ip6, 'plen', 0)}"

    # 8. Ethernet seul
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        return "Ethernet", f"Type={safe_hex(eth.type)}"

    return "RAW", f"Length: {len(pkt)} bytes"


def generate_hexdump_lines(raw_bytes: bytes) -> list[dict]:
    """Génère les lignes de dump hexadécimal et ASCII style Wireshark."""
    lines = []
    length = len(raw_bytes)
    for i in range(0, length, 16):
        chunk = raw_bytes[i : i + 16]
        offset = f"{i:04x}"
        bytes_hex = [f"{b:02x}" for b in chunk]
        ascii_chars = []
        for b in chunk:
            if 32 <= b <= 126:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append("·")
        lines.append({
            "offset": offset,
            "bytes_hex": bytes_hex,
            "bytes_ascii": "".join(ascii_chars),
        })
    return lines


def parse_packet_summary(pkt, pkt_id: int, rel_time: float, source: str = "LIVE") -> dict:
    """Génère un résumé léger d'un paquet pour le tableau principal."""
    src = "Unknown"
    dst = "Unknown"
    src_port = None
    dst_port = None

    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
    elif pkt.haslayer(Ether):
        src = pkt[Ether].src
        dst = pkt[Ether].dst

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    proto_name, info = detect_application_protocol(pkt)

    return {
        "id": pkt_id,
        "time": f"{rel_time:.6f}",
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto_name,
        "badge_class": get_protocol_badge(proto_name),
        "length": len(pkt),
        "info": info,
        "source": source,
    }


def parse_packet_details(pkt, pkt_id: int, rel_time: float, source: str = "LIVE") -> dict:
    """Dissection complète et détaillée de toutes les couches du paquet."""
    summary = parse_packet_summary(pkt, pkt_id, rel_time, source=source)
    raw_bytes = bytes(pkt)
    layers = []

    # 1. Cadre / Frame
    frame_fields = [
        {"name": "Frame Number", "value": str(pkt_id)},
        {"name": "Frame Length", "value": f"{len(raw_bytes)} octets ({len(raw_bytes)*8} bits)"},
        {"name": "Relative Time", "value": f"{rel_time:.6f} secondes"},
        {"name": "Timestamp", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")},
    ]
    layers.append({
        "id": "layer_frame",
        "name": f"Frame {pkt_id}: {len(raw_bytes)} octets capturés",
        "badge": "FRAME",
        "fields": frame_fields,
    })

    # 2. Ethernet II
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        eth_type_hex = safe_hex(eth.type)
        eth_type_desc = {0x0800: "IPv4", 0x86dd: "IPv6", 0x0806: "ARP"}.get(eth.type, "Autre")
        eth_fields = [
            {"name": "Destination MAC", "value": str(eth.dst)},
            {"name": "Source MAC", "value": str(eth.src)},
            {"name": "Type", "value": f"{eth_type_hex} ({eth_type_desc})"},
        ]
        layers.append({
            "id": "layer_ethernet",
            "name": f"Ethernet II, Src: {eth.src}, Dst: {eth.dst}",
            "badge": "ETH",
            "fields": eth_fields,
        })

    # 3. Réseau (IPv4 / IPv6 / ARP)
    if pkt.haslayer(IP):
        ip = pkt[IP]
        ip_fields = [
            {"name": "Version", "value": str(ip.version)},
            {"name": "Header Length (IHL)", "value": f"{safe_int(ip.ihl) * 4} octets ({ip.ihl})"},
            {"name": "Type of Service (TOS)", "value": safe_hex(ip.tos, 2)},
            {"name": "Total Length", "value": f"{safe_int(ip.len)} octets"},
            {"name": "Identification", "value": f"{safe_hex(ip.id)} ({safe_int(ip.id)})"},
            {"name": "Flags", "value": f"{str(ip.flags)} ({safe_hex(int(ip.flags) if ip.flags is not None else 0, 2)})"},
            {"name": "Fragment Offset", "value": str(ip.frag)},
            {"name": "Time to Live (TTL)", "value": str(ip.ttl)},
            {"name": "Protocol", "value": f"{ip.proto} ({summary['protocol']})"},
            {"name": "Header Checksum", "value": safe_hex(ip.chksum)},
            {"name": "Source IP", "value": str(ip.src)},
            {"name": "Destination IP", "value": str(ip.dst)},
        ]
        layers.append({
            "id": "layer_ip",
            "name": f"Internet Protocol Version 4, Src: {ip.src}, Dst: {ip.dst}",
            "badge": "IPv4",
            "fields": ip_fields,
        })
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        ip6_fields = [
            {"name": "Version", "value": str(ip6.version)},
            {"name": "Traffic Class", "value": safe_hex(ip6.tc, 2)},
            {"name": "Flow Label", "value": safe_hex(ip6.fl, 5)},
            {"name": "Payload Length", "value": f"{safe_int(ip6.plen)} octets"},
            {"name": "Next Header", "value": str(ip6.nh)},
            {"name": "Hop Limit", "value": str(ip6.hlim)},
            {"name": "Source IPv6", "value": str(ip6.src)},
            {"name": "Destination IPv6", "value": str(ip6.dst)},
        ]
        layers.append({
            "id": "layer_ipv6",
            "name": f"Internet Protocol Version 6, Src: {ip6.src}, Dst: {ip6.dst}",
            "badge": "IPv6",
            "fields": ip6_fields,
        })
    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        op_desc = "1 (Requête who-has)" if arp.op == 1 else ("2 (Réponse is-at)" if arp.op == 2 else str(arp.op))
        arp_fields = [
            {"name": "Hardware Type", "value": f"{arp.hwtype} (Ethernet)"},
            {"name": "Protocol Type", "value": f"{safe_hex(arp.ptype)} (IPv4)"},
            {"name": "Hardware Size", "value": f"{arp.hwlen} octets"},
            {"name": "Protocol Size", "value": f"{arp.plen} octets"},
            {"name": "Opcode", "value": op_desc},
            {"name": "Sender MAC Address", "value": str(arp.hwsrc)},
            {"name": "Sender IP Address", "value": str(arp.psrc)},
            {"name": "Target MAC Address", "value": str(arp.hwdst)},
            {"name": "Target IP Address", "value": str(arp.pdst)},
        ]
        layers.append({
            "id": "layer_arp",
            "name": f"Address Resolution Protocol ({op_desc})",
            "badge": "ARP",
            "fields": arp_fields,
        })

    # 4. Transport (TCP / UDP / ICMP)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags_str = get_tcp_flags_str(tcp.flags)
        tcp_fields = [
            {"name": "Source Port", "value": str(tcp.sport)},
            {"name": "Destination Port", "value": str(tcp.dport)},
            {"name": "Sequence Number", "value": str(tcp.seq)},
            {"name": "Acknowledgment Number", "value": str(tcp.ack)},
            {"name": "Header Length", "value": f"{safe_int(tcp.dataofs) * 4} octets ({tcp.dataofs})"},
            {"name": "Flags", "value": f"[{flags_str}] ({safe_hex(int(tcp.flags) if tcp.flags is not None else 0, 3)})"},
            {"name": "Window Size", "value": str(tcp.window)},
            {"name": "Checksum", "value": safe_hex(tcp.chksum)},
            {"name": "Urgent Pointer", "value": str(tcp.urgptr)},
        ]
        layers.append({
            "id": "layer_tcp",
            "name": f"Transmission Control Protocol, Src Port: {tcp.sport}, Dst Port: {tcp.dport}, [{flags_str}]",
            "badge": "TCP",
            "fields": tcp_fields,
        })
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        udp_fields = [
            {"name": "Source Port", "value": str(udp.sport)},
            {"name": "Destination Port", "value": str(udp.dport)},
            {"name": "Length", "value": f"{safe_int(udp.len)} octets"},
            {"name": "Checksum", "value": safe_hex(udp.chksum)},
        ]
        layers.append({
            "id": "layer_udp",
            "name": f"User Datagram Protocol, Src Port: {udp.sport}, Dst Port: {udp.dport}",
            "badge": "UDP",
            "fields": udp_fields,
        })
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_fields = [
            {"name": "Type", "value": f"{icmp.type} ({summary['info'].split()[0]})"},
            {"name": "Code", "value": str(icmp.code)},
            {"name": "Checksum", "value": safe_hex(icmp.chksum)},
            {"name": "Identifier", "value": safe_hex(getattr(icmp, 'id', 0))},
            {"name": "Sequence Number", "value": str(getattr(icmp, 'seq', 0))},
        ]
        layers.append({
            "id": "layer_icmp",
            "name": f"Internet Control Message Protocol, Type {icmp.type}, Code {icmp.code}",
            "badge": "ICMP",
            "fields": icmp_fields,
        })

    # 5. Applicatif (DNS / HTTP / TLS / Payload)
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        dns_id = getattr(dns, "id", 0) or 0
        dns_qr = getattr(dns, "qr", 0) or 0
        qdcount = getattr(dns, "qdcount", None) or (1 if getattr(dns, "qd", None) else 0)
        ancount = getattr(dns, "ancount", None) or (1 if getattr(dns, "an", None) else 0)
        nscount = getattr(dns, "nscount", 0) or 0
        arcount = getattr(dns, "arcount", 0) or 0

        dns_fields = [
            {"name": "Transaction ID", "value": safe_hex(dns_id)},
            {"name": "Flags", "value": f"{'Response' if dns_qr == 1 else 'Query'} (QR={dns_qr})"},
            {"name": "Questions count", "value": str(qdcount)},
            {"name": "Answer RRs count", "value": str(ancount)},
            {"name": "Authority RRs count", "value": str(nscount)},
            {"name": "Additional RRs count", "value": str(arcount)},
        ]
        if qdcount > 0 and getattr(dns, "qd", None):
            qname = getattr(dns.qd, "qname", b"")
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore").rstrip(".")
            dns_fields.append({"name": "Queried Domain", "value": str(qname)})
        layers.append({
            "id": "layer_dns",
            "name": f"Domain Name System ({'response' if dns_qr == 1 else 'query'})",
            "badge": "DNS",
            "fields": dns_fields,
        })

    # Couche Payload Données / Raw
    if pkt.haslayer(Raw):
        payload_bytes = bytes(pkt[Raw])
        sample_text = payload_bytes[:256].decode("latin-1", errors="replace")
        raw_fields = [
            {"name": "Payload Length", "value": f"{len(payload_bytes)} octets"},
            {"name": "Preview (ASCII)", "value": sample_text},
        ]
        layers.append({
            "id": "layer_raw",
            "name": f"Données Applicatives (Payload: {len(payload_bytes)} octets)",
            "badge": "DATA",
            "fields": raw_fields,
        })

    hexdump_lines = generate_hexdump_lines(raw_bytes)

    return {
        **summary,
        "layers": layers,
        "hexdump": hexdump_lines,
        "raw_hex": binascii.hexlify(raw_bytes).decode("ascii"),
    }
