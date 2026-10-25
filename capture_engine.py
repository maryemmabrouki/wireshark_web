"""
Moteur de capture réseau Scapy et générateur de trafic de démonstration.
Gère la capture en direct réelle avec AsyncSniffer, le mode démo virtuel, l'import/export PCAP.
"""

import os
import time
import random
import threading
from typing import Optional
from datetime import datetime

from scapy.all import (
    conf, Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw,
    AsyncSniffer, wrpcap, rdpcap
)

from packet_parser import parse_packet_summary, parse_packet_details


class CaptureEngine:
    def __init__(self, max_packets: int = 5000):
        self.max_packets = max_packets
        self.lock = threading.Lock()

        # État et mode de capture
        # capture_mode : "LIVE" (capture réelle), "PCAP" (fichier), "DEMO" (simulation), "NONE"
        self.capture_mode = "NONE"
        self.is_capturing = False
        self.is_demo_mode = False
        self.selected_interface = None
        self.selected_interface_name = "Aucune"
        self.start_time = None
        self.packet_counter = 0

        # Stockage : liste de dicts contenant { 'summary', 'details', 'scapy_pkt' }
        self.packets_data = []

        # Sniffer asynchrone Scapy et threads
        self._sniffer: Optional[AsyncSniffer] = None
        self._demo_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Dernier message d'état ou d'erreur
        self.last_status_message = "Prêt"
        self.last_error = None

    def get_interfaces(self) -> list[dict]:
        """
        Retourne la liste des interfaces réseau disponibles sur le système,
        triées avec priorité aux interfaces actives (Loopback, Wi-Fi, Ethernet).
        """
        interfaces = [
            {
                "id": "DEMO_MODE",
                "name": "🧪 Simulateur / Mode Démo (Trafic Virtuel)",
                "description": "Génération de paquets variés (DNS, HTTP, ICMP, ARP, TCP, TLS)",
                "ip": "192.168.1.50",
                "is_demo": True,
                "is_active": True,
            }
        ]

        active_ifaces = []
        other_ifaces = []

        try:
            for iface_key, iface_obj in conf.ifaces.items():
                name = getattr(iface_obj, "name", str(iface_key))
                desc = getattr(iface_obj, "description", "")
                ip_addr = getattr(iface_obj, "ip", "") or ""
                mac_addr = getattr(iface_obj, "mac", "") or ""

                display_name = name
                if desc and desc != name:
                    display_name = f"{name} ({desc})"

                is_loopback = "loopback" in name.lower() or "loopback" in str(iface_key).lower() or ip_addr == "127.0.0.1"
                has_ip = bool(ip_addr and not ip_addr.startswith("169.254"))

                item = {
                    "id": str(iface_key),
                    "name": display_name,
                    "raw_name": name,
                    "description": desc or "Interface réseau locale",
                    "ip": ip_addr if ip_addr else "Non configurée",
                    "mac": mac_addr,
                    "is_demo": False,
                    "is_loopback": is_loopback,
                    "is_active": has_ip or is_loopback,
                }

                if is_loopback or has_ip:
                    active_ifaces.append(item)
                else:
                    other_ifaces.append(item)

        except Exception as e:
            interfaces.append({
                "id": "DEFAULT",
                "name": f"Interface Scapy par défaut ({conf.iface})",
                "description": str(e),
                "ip": "127.0.0.1",
                "is_demo": False,
                "is_active": True,
            })

        # Trier en mettant en avant les interfaces configurées
        interfaces.extend(active_ifaces)
        interfaces.extend(other_ifaces)

        return interfaces

    def start_capture(self, interface: str = None) -> tuple[bool, str]:
        """Démarre la capture de paquets (en direct ou en mode démo)."""
        with self.lock:
            if self.is_capturing:
                return False, "Une capture est déjà en cours d'exécution. Veuillez l'arrêter avant d'en démarrer une nouvelle."

            self._stop_event.clear()
            self.last_error = None

        if interface == "DEMO_MODE":
            return self._start_demo_capture()
        else:
            return self._start_live_capture(interface)

    def _resolve_interface(self, interface_id: Optional[str]):
        """Résout un identifiant ou nom d'interface en objet Scapy NetworkInterface."""
        if not interface_id or interface_id == "DEFAULT":
            return conf.iface, getattr(conf.iface, "name", "Interface par défaut")

        # Recherche exacte par clé dans conf.ifaces
        if interface_id in conf.ifaces:
            obj = conf.ifaces[interface_id]
            return obj, getattr(obj, "name", str(interface_id))

        # Recherche par nom lisible
        for key, obj in conf.ifaces.items():
            name = getattr(obj, "name", "")
            if name == interface_id or str(key) == interface_id:
                return obj, name

        # Recherche approximative
        for key, obj in conf.ifaces.items():
            name = getattr(obj, "name", "")
            if interface_id.lower() in name.lower() or interface_id.lower() in str(key).lower():
                return obj, name

        return None, None

    def _start_live_capture(self, interface: str) -> tuple[bool, str]:
        """Démarre la capture réelle Scapy avec AsyncSniffer."""
        resolved_iface, friendly_name = self._resolve_interface(interface)

        if resolved_iface is None:
            err = f"L'interface réseau '{interface}' est introuvable ou invalide sur ce système."
            with self.lock:
                self.last_error = err
                self.last_status_message = err
            return False, err

        # Séparation stricte : en mode capture réelle, vider les données précédentes si
        # elles provenaient de la démonstration ou d'un PCAP.
        with self.lock:
            if self.capture_mode != "LIVE":
                self.packets_data.clear()
                self.packet_counter = 0

            self.is_capturing = True
            self.is_demo_mode = False
            self.capture_mode = "LIVE"
            self.selected_interface = str(interface)
            self.selected_interface_name = friendly_name
            self.start_time = time.time()
            self.last_error = None
            self.last_status_message = f"Capture réelle en direct active sur {friendly_name}..."

        try:
            def _handle_pkt(pkt):
                if not self.is_capturing:
                    return
                self._add_packet(pkt, source="LIVE")

            # Utilisation du sniffer asynchrone natif de Scapy
            self._sniffer = AsyncSniffer(
                iface=resolved_iface,
                prn=_handle_pkt,
                store=False,
            )
            self._sniffer.start()
            return True, f"Capture réelle démarrée sur l'interface {friendly_name}."
        except Exception as e:
            with self.lock:
                self.is_capturing = False
                self.capture_mode = "NONE"
                self._sniffer = None
                self.last_error = str(e)
                self.last_status_message = f"Échec capture réelle : {e}"

            err_text = str(e)
            if "permission" in err_text.lower() or "winpcap" in err_text.lower() or "npcap" in err_text.lower():
                err_text += " (Vérifiez l'installation de Npcap et les privilèges d'accès réseau)."

            return False, f"Impossible de capturer sur {friendly_name} : {err_text}"

    def _start_demo_capture(self) -> tuple[bool, str]:
        """Démarre le flux continu en mode démonstration."""
        with self.lock:
            if self.capture_mode != "DEMO":
                self.packets_data.clear()
                self.packet_counter = 0

            self.is_capturing = True
            self.is_demo_mode = True
            self.capture_mode = "DEMO"
            self.selected_interface = "DEMO_MODE"
            self.selected_interface_name = "Simulateur Virtuel"
            self.start_time = time.time()
            self._stop_event.clear()
            self.last_status_message = "Mode démo actif : génération de trafic virtuel..."

        self._demo_thread = threading.Thread(target=self._demo_worker, daemon=True)
        self._demo_thread.start()
        return True, "Mode démonstration démarré avec succès."

    def stop_capture(self) -> tuple[bool, str]:
        """Arrête la capture active (en direct ou démo)."""
        with self.lock:
            if not self.is_capturing:
                return False, "Aucune capture n'est actuellement en cours."

            self.is_capturing = False
            self._stop_event.set()

        # Arrêt propre de l'AsyncSniffer
        if self._sniffer is not None:
            try:
                if getattr(self._sniffer, "running", False):
                    self._sniffer.stop()
            except Exception:
                pass
            finally:
                self._sniffer = None

        if self.is_demo_mode:
            self.last_status_message = "Mode démonstration arrêté."
        else:
            self.last_status_message = f"Capture réelle arrêtée ({len(self.packets_data)} paquets capturés)."

        return True, "Capture arrêtée avec succès."

    def clear_packets(self) -> None:
        """Réinitialise la liste des paquets capturés."""
        with self.lock:
            self.packets_data.clear()
            self.packet_counter = 0
            self.start_time = time.time()
            self.last_status_message = "Tampon de paquets réinitialisé."

    def _add_packet(self, pkt, source: str = "LIVE") -> None:
        """Traite et enregistre un paquet capturé dans le tampon mémoire."""
        with self.lock:
            self.packet_counter += 1
            pkt_id = self.packet_counter

            if self.start_time is None:
                self.start_time = time.time()

            pkt_scapy_time = getattr(pkt, "time", None)
            if pkt_scapy_time and pkt_scapy_time > 1000000000:
                rel_time = max(0.0, float(pkt_scapy_time) - self.start_time)
            else:
                rel_time = max(0.0, time.time() - self.start_time)

            summary = parse_packet_summary(pkt, pkt_id, rel_time, source=source)
            details = parse_packet_details(pkt, pkt_id, rel_time, source=source)

            self.packets_data.append({
                "summary": summary,
                "details": details,
                "scapy_pkt": pkt,
            })

            # Gestion de la limite mémoire circulaire
            if len(self.packets_data) > self.max_packets:
                self.packets_data.pop(0)

    def _demo_worker(self):
        """Worker thread générant du trafic de démo régulier et pédagogique."""
        try:
            while not self._stop_event.is_set():
                pkts = self._generate_realistic_event()
                for p in pkts:
                    if self._stop_event.is_set():
                        break
                    self._add_packet(p, source="DEMO")
                    time.sleep(random.uniform(0.1, 0.3))

                time.sleep(random.uniform(0.8, 1.8))
        except Exception as e:
            self.last_error = str(e)
            self.is_capturing = False

    def generate_demo_batch(self, count: int = 15) -> int:
        """Génère instantanément un lot de paquets variés pour tester immédiatement."""
        added = 0
        events = [
            self._generate_arp_exchange,
            self._generate_dns_exchange,
            self._generate_http_session,
            self._generate_icmp_ping,
            self._generate_tcp_handshake,
            self._generate_tls_handshake,
        ]

        with self.lock:
            if self.capture_mode == "LIVE":
                self.packets_data.clear()
                self.packet_counter = 0
            self.capture_mode = "DEMO"
            self.is_demo_mode = True

        for _ in range(count):
            event_func = random.choice(events)
            pkts = event_func()
            for p in pkts:
                self._add_packet(p, source="DEMO")
                added += 1

        self.last_status_message = f"{added} paquets de démonstration générés."
        return added

    def _generate_realistic_event(self) -> list:
        """Choisit aléatoirement un scénario réseau standard."""
        scenarios = [
            self._generate_dns_exchange,
            self._generate_http_session,
            self._generate_icmp_ping,
            self._generate_tcp_handshake,
            self._generate_arp_exchange,
            self._generate_tls_handshake,
        ]
        chosen = random.choice(scenarios)
        return chosen()

    def _generate_arp_exchange(self) -> list:
        """Génère une requête et une réponse ARP pédagogiques."""
        gateway_ip = "192.168.1.1"
        gateway_mac = "00:1a:2b:3c:4d:5e"
        client_ip = "192.168.1.37"
        client_mac = "74:d0:2b:99:4a:12"

        req = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=client_mac,
            psrc=client_ip,
            hwdst="00:00:00:00:00:00",
            pdst=gateway_ip,
        )

        rep = Ether(src=gateway_mac, dst=client_mac) / ARP(
            op=2,
            hwsrc=gateway_mac,
            psrc=gateway_ip,
            hwdst=client_mac,
            pdst=client_ip,
        )
        return [req, rep]

    def _generate_dns_exchange(self) -> list:
        """Génère une requête DNS standard et sa réponse correspondante."""
        domains = [
            ("esisa.ac.ma", "196.200.160.42"),
            ("github.com", "140.82.121.4"),
            ("google.com", "142.250.200.46"),
            ("wikipedia.org", "185.15.59.224"),
            ("python.org", "151.101.192.223"),
        ]
        domain, resolved_ip = random.choice(domains)
        dns_id = random.randint(1000, 65000)
        client_port = random.randint(49152, 65535)

        query = (
            Ether(src="74:d0:2b:99:4a:12", dst="00:1a:2b:3c:4d:5e")
            / IP(src="192.168.1.37", dst="8.8.8.8")
            / UDP(sport=client_port, dport=53)
            / DNS(
                id=dns_id,
                qr=0,
                opcode=0,
                rd=1,
                qd=DNSQR(qname=domain, qtype="A"),
            )
        )

        response = (
            Ether(src="00:1a:2b:3c:4d:5e", dst="74:d0:2b:99:4a:12")
            / IP(src="8.8.8.8", dst="192.168.1.37")
            / UDP(sport=53, dport=client_port)
            / DNS(
                id=dns_id,
                qr=1,
                aa=0,
                rd=1,
                ra=1,
                qd=DNSQR(qname=domain, qtype="A"),
                an=DNSRR(rrname=domain + ".", type="A", rdata=resolved_ip, ttl=300),
            )
        )
        return [query, response]

    def _generate_http_session(self) -> list:
        """Génère une transaction HTTP complète (GET et 200 OK)."""
        client_port = random.randint(49152, 65535)
        server_ip = "93.184.216.34"

        http_req = (
            Ether(src="74:d0:2b:99:4a:12", dst="00:1a:2b:3c:4d:5e")
            / IP(src="192.168.1.37", dst=server_ip)
            / TCP(sport=client_port, dport=80, flags="PA", seq=1001, ack=5001)
            / Raw(
                b"GET /index.html HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                b"Accept: text/html,application/xhtml+xml\r\n\r\n"
            )
        )

        http_resp = (
            Ether(src="00:1a:2b:3c:4d:5e", dst="74:d0:2b:99:4a:12")
            / IP(src=server_ip, dst="192.168.1.37")
            / TCP(sport=80, dport=client_port, flags="PA", seq=5001, ack=1150)
            / Raw(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=UTF-8\r\n"
                b"Server: ECS (dcb/7F3B)\r\n"
                b"Content-Length: 48\r\n\r\n"
                b"<!doctype html><html><h1>Hello Wireshark!</h1></html>"
            )
        )
        return [http_req, http_resp]

    def _generate_icmp_ping(self) -> list:
        """Génère un cycle ICMP Echo Request / Echo Reply (ping)."""
        target_ip = random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"])
        seq_num = random.randint(1, 100)
        icmp_id = random.randint(1, 500)

        req = (
            Ether(src="74:d0:2b:99:4a:12", dst="00:1a:2b:3c:4d:5e")
            / IP(src="192.168.1.37", dst=target_ip, ttl=128)
            / ICMP(type=8, code=0, id=icmp_id, seq=seq_num)
            / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
        )

        rep = (
            Ether(src="00:1a:2b:3c:4d:5e", dst="74:d0:2b:99:4a:12")
            / IP(src=target_ip, dst="192.168.1.37", ttl=56)
            / ICMP(type=0, code=0, id=icmp_id, seq=seq_num)
            / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
        )
        return [req, rep]

    def _generate_tcp_handshake(self) -> list:
        """Génère un 3-Way Handshake TCP (SYN, SYN-ACK, ACK)."""
        client_port = random.randint(49152, 65535)
        server_ip = "140.82.121.4"  # GitHub
        server_port = 443

        seq_client = random.randint(100000, 999999)
        seq_server = random.randint(500000, 888888)

        syn = (
            Ether(src="74:d0:2b:99:4a:12", dst="00:1a:2b:3c:4d:5e")
            / IP(src="192.168.1.37", dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=seq_client, window=64240)
        )

        syn_ack = (
            Ether(src="00:1a:2b:3c:4d:5e", dst="74:d0:2b:99:4a:12")
            / IP(src=server_ip, dst="192.168.1.37")
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=seq_server, ack=seq_client + 1, window=65535)
        )

        ack = (
            Ether(src="74:d0:2b:99:4a:12", dst="00:1a:2b:3c:4d:5e")
            / IP(src="192.168.1.37", dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=seq_client + 1, ack=seq_server + 1, window=64240)
        )
        return [syn, syn_ack, ack]

    def _generate_tls_handshake(self) -> list:
        """Génère un paquet TLS 1.3 Client Hello avec SNI."""
        client_port = random.randint(49152, 65535)
        server_ip = "142.250.200.46"

        tls_payload = (
            b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03"
            b"\x7b\x1a\x8e\x9f\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44"
            b"\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44"
            b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x74\x00\x00\x00\x0f\x00"
            b"\x0d\x00\x00\x0a\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d"
        )

        pkt = (
            Ether(src="74:d0:2b:99:4a:12", dst="00:1a:2b:3c:4d:5e")
            / IP(src="192.168.1.37", dst=server_ip)
            / TCP(sport=client_port, dport=443, flags="PA", seq=2000, ack=7000)
            / Raw(tls_payload)
        )
        return [pkt]

    def import_pcap(self, filepath: str) -> int:
        """Charge et analyse les paquets d'un fichier PCAP."""
        try:
            scapy_pkts = rdpcap(filepath)
            with self.lock:
                self.packets_data.clear()
                self.packet_counter = 0
                self.capture_mode = "PCAP"
                self.is_demo_mode = False
                self.is_capturing = False
                self.selected_interface = None
                self.selected_interface_name = os.path.basename(filepath)

                first_pkt_time = None
                for idx, pkt in enumerate(scapy_pkts, start=1):
                    pkt_time = float(getattr(pkt, "time", 0))
                    if first_pkt_time is None:
                        first_pkt_time = pkt_time

                    rel_time = max(0.0, pkt_time - first_pkt_time)
                    summary = parse_packet_summary(pkt, idx, rel_time, source="PCAP")
                    details = parse_packet_details(pkt, idx, rel_time, source="PCAP")

                    self.packets_data.append({
                        "summary": summary,
                        "details": details,
                        "scapy_pkt": pkt,
                    })

                self.packet_counter = len(self.packets_data)
                self.last_status_message = f"{len(self.packets_data)} paquets importés depuis {os.path.basename(filepath)}"
            return len(self.packets_data)
        except Exception as e:
            self.last_error = f"Erreur lors de l'import PCAP: {e}"
            return 0

    def export_pcap(self, filepath: str) -> bool:
        """Exporte tous les paquets capturés dans un fichier PCAP standard."""
        with self.lock:
            pkts_to_export = [item["scapy_pkt"] for item in self.packets_data]

        if not pkts_to_export:
            return False

        try:
            wrpcap(filepath, pkts_to_export)
            return True
        except Exception as e:
            self.last_error = f"Erreur export PCAP: {e}"
            return False

    def get_packets(
        self,
        protocol: Optional[str] = None,
        ip_filter: Optional[str] = None,
        port_filter: Optional[int] = None,
        query: Optional[str] = None,
        since_id: Optional[int] = None,
        limit: int = 500,
        offset: int = 0
    ) -> tuple[list[dict], int]:
        """
        Filtre et renvoie les paquets demandés.
        Supporte les filtres par protocole, IP, port, et recherche textuelle.
        """
        with self.lock:
            items = list(self.packets_data)

        # Filtre incrémental rapide (pour le polling temps réel)
        if since_id is not None:
            items = [item for item in items if item["summary"]["id"] > since_id]

        filtered = []
        protocol_lower = protocol.strip().lower() if protocol else None
        ip_lower = ip_filter.strip().lower() if ip_filter else None
        query_lower = query.strip().lower() if query else None

        for item in items:
            s = item["summary"]

            # Filtre Protocole
            if protocol_lower and protocol_lower != "all":
                if s["protocol"].lower() != protocol_lower:
                    continue

            # Filtre IP (source ou destination)
            if ip_lower:
                src_ip = s["src"].lower()
                dst_ip = s["dst"].lower()
                if ip_lower not in src_ip and ip_lower not in dst_ip:
                    continue

            # Filtre Port
            if port_filter is not None:
                src_p = s.get("src_port")
                dst_p = s.get("dst_port")
                if src_p != port_filter and dst_p != port_filter:
                    continue

            # Filtre Requête texte libre
            if query_lower:
                text_to_search = f"{s['src']} {s['dst']} {s['protocol']} {s['info']}".lower()
                if query_lower not in text_to_search:
                    continue

            filtered.append(s)

        total_matching = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total_matching

    def get_packet_detail(self, pkt_id: int) -> Optional[dict]:
        """Retourne la dissection détaillée et le dump hexadécimal d'un paquet."""
        with self.lock:
            for item in self.packets_data:
                if item["summary"]["id"] == pkt_id:
                    return item["details"]
        return None

    def get_stats(self) -> dict:
        """Calcule les statistiques globales du trafic capturé."""
        with self.lock:
            items = list(self.packets_data)
            duration = max(0.1, time.time() - (self.start_time or time.time()))

        total_pkts = len(items)
        protocols_count = {}
        top_ips = {}
        total_bytes = 0

        for item in items:
            s = item["summary"]
            proto = s["protocol"]
            protocols_count[proto] = protocols_count.get(proto, 0) + 1

            src = s["src"]
            dst = s["dst"]
            top_ips[src] = top_ips.get(src, 0) + 1
            top_ips[dst] = top_ips.get(dst, 0) + 1

            total_bytes += s["length"]

        sorted_protocols = sorted(protocols_count.items(), key=lambda x: x[1], reverse=True)
        sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 2),
            "packets_per_second": round(total_pkts / duration, 1) if duration > 0 else 0,
            "protocols": [{"name": k, "count": v, "percent": round((v / total_pkts) * 100, 1) if total_pkts else 0} for k, v in sorted_protocols],
            "top_ips": [{"ip": k, "count": v} for k, v in sorted_ips],
            "is_capturing": self.is_capturing,
            "is_demo_mode": self.is_demo_mode,
            "capture_mode": self.capture_mode,
            "selected_interface": self.selected_interface,
            "selected_interface_name": self.selected_interface_name,
            "last_status": self.last_status_message,
            "last_error": self.last_error,
        }
