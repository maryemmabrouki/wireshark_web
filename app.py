"""
Application Web Flask Wireshark (SharkWeb).
Fournit l'interface utilisateur et l'API REST pour l'analyse des paquets Scapy.
"""

import os
import time
import tempfile
from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

from capture_engine import CaptureEngine

# Initialisation de l'application Flask
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 Mo max pour les fichiers PCAP
app.config["JSON_AS_ASCII"] = False

# Instance unique du moteur de capture
engine = CaptureEngine()

# Chemin vers la capture d'exemple pré-générée
SAMPLE_PCAP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "sample_captures",
    "sample_traffic.pcap"
)

# Chargement automatique de l'exemple si le fichier existe
if os.path.exists(SAMPLE_PCAP_PATH):
    engine.import_pcap(SAMPLE_PCAP_PATH)
else:
    # Génération d'un lot initial si le fichier n'est pas encore présent
    engine.generate_demo_batch(8)


# ---------------------------------------------------------------------------
# Pages HTML
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Page principale : Tableau de bord inspiré de Wireshark."""
    return render_template("index.html")


@app.route("/packet/<int:pkt_id>")
def packet_detail_page(pkt_id: int):
    """Page dédiée aux détails complets d'un paquet spécifique."""
    details = engine.get_packet_detail(pkt_id)
    if not details:
        abort(404, description=f"Le paquet #{pkt_id} est introuvable ou a été effacé.")

    # Trouver l'ID du paquet précédent et suivant pour la navigation
    with engine.lock:
        all_ids = [item["summary"]["id"] for item in engine.packets_data]

    prev_id = None
    next_id = None
    if pkt_id in all_ids:
        idx = all_ids.index(pkt_id)
        if idx > 0:
            prev_id = all_ids[idx - 1]
        if idx < len(all_ids) - 1:
            next_id = all_ids[idx + 1]

    return render_template(
        "packet_detail.html",
        packet=details,
        prev_id=prev_id,
        next_id=next_id,
        total_packets=len(all_ids),
    )


# ---------------------------------------------------------------------------
# API REST JSON
# ---------------------------------------------------------------------------

@app.route("/api/status", methods=["GET"])
def get_status():
    """Retourne l'état courant de la capture et les métriques de base."""
    stats = engine.get_stats()
    return jsonify({
        "success": True,
        "is_capturing": engine.is_capturing,
        "is_demo_mode": engine.is_demo_mode,
        "capture_mode": engine.capture_mode,
        "selected_interface": engine.selected_interface,
        "selected_interface_name": getattr(engine, "selected_interface_name", "Aucune"),
        "total_packets": stats["total_packets"],
        "last_status": engine.last_status_message,
        "last_error": engine.last_error,
    })


@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Retourne les interfaces réseau détectées sur le système."""
    ifaces = engine.get_interfaces()
    return jsonify({
        "success": True,
        "interfaces": ifaces,
    })


@app.route("/api/start", methods=["POST"])
def start_capture():
    """Démarre la capture de paquets sur l'interface sélectionnée."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")

    if not interface:
        return jsonify({
            "success": False,
            "message": "Veuillez sélectionner une interface réseau valide.",
        }), 400

    success, message = engine.start_capture(interface)
    return jsonify({
        "success": success,
        "message": message,
        "is_capturing": engine.is_capturing,
        "is_demo_mode": engine.is_demo_mode,
        "capture_mode": engine.capture_mode,
        "interface_name": getattr(engine, "selected_interface_name", ""),
    }), (200 if success else 400)


@app.route("/api/stop", methods=["POST"])
def stop_capture():
    """Arrête la capture de paquets active."""
    success, message = engine.stop_capture()
    return jsonify({
        "success": success,
        "message": message,
        "is_capturing": engine.is_capturing,
        "capture_mode": engine.capture_mode,
    }), (200 if success else 400)


@app.route("/api/clear", methods=["POST"])
def clear_packets():
    """Vide le tampon des paquets capturés."""
    engine.clear_packets()
    return jsonify({
        "success": True,
        "message": "Tampon de paquets vidé.",
        "total_packets": 0,
    })


@app.route("/api/test_traffic", methods=["POST"])
def send_test_traffic():
    """
    Génère un paquet de test local autorisé (UDP, Multicast 224.1.1.1:5555 ou TCP)
    afin de valider la capture passive sans actions offensives.
    """
    import socket
    data = request.get_json(silent=True) or {}
    traffic_type = data.get("type", "udp").lower()
    target_ip = data.get("target_ip", "127.0.0.1")
    port = int(data.get("port", 5555))
    msg = data.get("message", "INDUTWIN_TEST_DATA")
    payload = msg.encode("utf-8")

    try:
        if traffic_type == "multicast" or target_ip.startswith("224."):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            # Liaison à l'IP d'interface active si disponible
            from scapy.all import conf
            for iface_obj in conf.ifaces.values():
                ip_cand = getattr(iface_obj, "ip", "")
                if ip_cand and not ip_cand.startswith("169.254") and ip_cand != "127.0.0.1":
                    try:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_cand))
                        break
                    except Exception:
                        pass
            sock.sendto(payload, (target_ip, port))
            sock.close()
            return jsonify({
                "success": True,
                "message": f"Paquet UDP Multicast émis vers {target_ip}:{port} ({len(payload)} octets).",
                "type": "multicast",
                "target": f"{target_ip}:{port}",
            })
        elif traffic_type == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(payload, (target_ip, port))
            sock.close()
            return jsonify({
                "success": True,
                "message": f"Paquet UDP émis vers {target_ip}:{port} ({len(payload)} octets).",
                "type": "udp",
                "target": f"{target_ip}:{port}",
            })
        elif traffic_type == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((target_ip, port))
                sock.sendall(payload)
                sock.close()
            except Exception:
                pass
            return jsonify({
                "success": True,
                "message": f"Tentative de connexion TCP effectuée vers {target_ip}:{port}.",
                "type": "tcp",
                "target": f"{target_ip}:{port}",
            })
        else:
            return jsonify({"success": False, "error": f"Type de trafic inconnu : {traffic_type}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """
    Retourne la liste des paquets avec filtres optionnels.
    Paramètres GET :
      - protocol : tcp, udp, dns, http, icmp, arp, tls, all
      - ip       : sous-chaîne IP (source ou destination)
      - port     : numéro de port entier
      - query    : recherche texte libre
      - since_id : ID minimal pour polling incrémental
      - limit    : nombre maximal (défaut 500)
      - offset   : décalage (défaut 0)
    """
    protocol = request.args.get("protocol")
    ip_filter = request.args.get("ip")
    port_str = request.args.get("port")
    query = request.args.get("query")
    since_id_str = request.args.get("since_id")
    limit = int(request.args.get("limit", 500))
    offset = int(request.args.get("offset", 0))

    port_filter = int(port_str) if (port_str and port_str.isdigit()) else None
    since_id = int(since_id_str) if (since_id_str and since_id_str.isdigit()) else None

    packets, total_matching = engine.get_packets(
        protocol=protocol,
        ip_filter=ip_filter,
        port_filter=port_filter,
        query=query,
        since_id=since_id,
        limit=limit,
        offset=offset,
    )

    with engine.lock:
        grand_total = len(engine.packets_data)

    return jsonify({
        "success": True,
        "packets": packets,
        "matching": total_matching,
        "total": grand_total,
        "is_capturing": engine.is_capturing,
    })


@app.route("/api/packets/<int:pkt_id>", methods=["GET"])
def get_packet_detail(pkt_id: int):
    """Retourne la dissection détaillée et le hexdump du paquet demandé."""
    details = engine.get_packet_detail(pkt_id)
    if not details:
        return jsonify({
            "success": False,
            "error": f"Paquet #{pkt_id} introuvable.",
        }), 404

    return jsonify({
        "success": True,
        "packet": details,
    })


@app.route("/api/demo/generate", methods=["POST"])
def generate_demo():
    """Génère immédiatement un lot de paquets de démonstration variés."""
    data = request.get_json(silent=True) or {}
    count = int(data.get("count", 10))
    added = engine.generate_demo_batch(count)
    return jsonify({
        "success": True,
        "message": f"{added} paquets virtuels générés avec succès.",
        "added": added,
        "total": len(engine.packets_data),
    })


@app.route("/api/demo/load_sample", methods=["POST"])
def load_sample_pcap():
    """Charge le fichier PCAP de démonstration fourni avec le projet."""
    if os.path.exists(SAMPLE_PCAP_PATH):
        count = engine.import_pcap(SAMPLE_PCAP_PATH)
        return jsonify({
            "success": True,
            "message": f"{count} paquets chargés depuis la capture de référence.",
            "total": count,
        })
    else:
        # Si absent, en génère un nouveau
        added = engine.generate_demo_batch(15)
        engine.export_pcap(SAMPLE_PCAP_PATH)
        return jsonify({
            "success": True,
            "message": f"{added} paquets de démonstration générés et enregistrés.",
            "total": added,
        })


@app.route("/api/upload_pcap", methods=["POST"])
def upload_pcap():
    """Téléversement et analyse d'un fichier PCAP externe."""
    if "pcap_file" not in request.files:
        return jsonify({"success": False, "error": "Aucun fichier reçu."}), 400

    file = request.files["pcap_file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "Nom de fichier vide."}), 400

    filename = secure_filename(file.filename)
    if not (filename.lower().endswith(".pcap") or filename.lower().endswith(".pcapng") or filename.lower().endswith(".cap")):
        return jsonify({"success": False, "error": "Format non supporté. Veuillez choisir un fichier .pcap ou .pcapng."}), 400

    # Sauvegarde temporaire pour Scapy rdpcap
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"upload_{int(time.time())}_{filename}")
    try:
        file.save(temp_path)
        count = engine.import_pcap(temp_path)
        return jsonify({
            "success": True,
            "message": f"Fichier '{filename}' analysé avec succès : {count} paquets chargés.",
            "total": count,
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Erreur lors de l'analyse PCAP : {e}"}), 500
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.route("/api/export_pcap", methods=["GET"])
def export_pcap():
    """Téléchargement de la capture courante au format PCAP standard."""
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"sharkweb_capture_{int(time.time())}.pcap")

    ok = engine.export_pcap(temp_path)
    if not ok or not os.path.exists(temp_path):
        return jsonify({"success": False, "error": "Aucun paquet à exporter ou erreur de génération."}), 400

    return send_file(
        temp_path,
        as_attachment=True,
        download_name="sharkweb_capture.pcap",
        mimetype="application/vnd.tcpdump.pcap"
    )


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Statistiques approfondies de capture : protocoles, débits, top adresses IP."""
    stats = engine.get_stats()
    return jsonify({
        "success": True,
        "stats": stats,
    })


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[SharkWeb] Wireshark Python demarre sur http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
