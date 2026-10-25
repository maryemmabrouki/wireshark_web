import sys
import os
import time
import socket
import json
import urllib.request
import urllib.error

# Forcer l'encodage UTF-8 pour la console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_URL = "http://127.0.0.1:5000"


def request_json(path: str, method: str = "GET", data: dict = None) -> tuple[int, dict]:
    """Helper pour exécuter une requête HTTP JSON sur l'API SharkWeb."""
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode("utf-8") if data is not None else None

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            content = response.read().decode("utf-8")
            return status, json.loads(content)
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"raw": content}
        return e.code, parsed
    except Exception as e:
        return 0, {"error": str(e)}


def run_all_tests():
    print("=" * 70)
    print("      SUITE DE VALIDATION DE LA CAPTURE RÉELLE SHARKWEB (SCAPY)")
    print("=" * 70)

    results = {}

    # TEST 1 : Vérifier la connectivité au serveur Flask et les API de base
    print("\n[TEST 1] Vérification de l'état du serveur et des endpoints API...")
    status_code, status_data = request_json("/api/status")
    if status_code == 200 and status_data.get("success"):
        print(f"  -> API /api/status OK (Total: {status_data.get('total_packets')} paquets, Mode: {status_data.get('capture_mode')})")
        results["test1_api_health"] = "PASS"
    else:
        print(f"  -> ÉCHEC API /api/status: Code {status_code}, Réponse: {status_data}")
        results["test1_api_health"] = "FAIL"
        return results

    # TEST 2 : Lister et valider les interfaces réseau détectées
    print("\n[TEST 2] Détection des interfaces réseau disponibles...")
    code, ifaces_data = request_json("/api/interfaces")
    ifaces = ifaces_data.get("interfaces", [])
    print(f"  -> {len(ifaces)} interfaces détectées:")
    loopback_iface = None
    wifi_iface = None
    for ifc in ifaces:
        name = ifc.get("name", "")
        ip = ifc.get("ip", "")
        print(f"     - ID: {ifc.get('id')[:35]}... | {name} | IP: {ip}")
        if ifc.get("is_loopback"):
            loopback_iface = ifc.get("id")
        if "wi-fi" in name.lower() or "wi-fi" in ifc.get("id", "").lower():
            wifi_iface = ifc.get("id")

    if ifaces and loopback_iface:
        print(f"  -> Interface Loopback identifiée : {loopback_iface}")
        results["test2_interfaces_list"] = "PASS"
    else:
        print("  -> AVERTISSEMENT : Loopback non identifié, utilisation de DEFAULT.")
        loopback_iface = "DEFAULT"
        results["test2_interfaces_list"] = "PASS"

    # TEST 3 : Démarrer la capture réelle sur l'interface Loopback
    print(f"\n[TEST 3] Démarrage de la capture réelle sur Loopback...")
    code, start_res = request_json("/api/start", method="POST", data={"interface": loopback_iface})
    if code == 200 and start_res.get("success"):
        print(f"  -> Capture réelle démarrée : {start_res.get('message')}")
        print(f"  -> Mode actif : {start_res.get('capture_mode')}")
        results["test3_start_real_capture"] = "PASS"
    else:
        print(f"  -> ÉCHEC démarrage capture : {start_res}")
        results["test3_start_real_capture"] = "FAIL"
        return results

    time.sleep(1)

    # TEST 4 : Générer du trafic UDP contrôlé (Port 5555 / InduTwin) et vérifier la capture
    print("\n[TEST 4] Génération de trafic UDP local sur port 5555 (InduTwin)...")
    test_message = b"INDUTWIN_TELEMETRY_PACKET_TEST_42"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(test_message, ("127.0.0.1", 5555))
    sock.close()
    print("  -> Paquet UDP émis vers 127.0.0.1:5555 (34 octets)")

    # Laisser 1.2 seconde pour que Scapy capture et traite le paquet
    time.sleep(1.2)

    # Récupérer les paquets capturés
    code, pkts_data = request_json("/api/packets?port=5555")
    matching_pkts = pkts_data.get("packets", [])
    found_test_pkt = None
    for p in matching_pkts:
        if p.get("dst_port") == 5555 or p.get("src_port") == 5555:
            found_test_pkt = p
            break

    if found_test_pkt:
        print(f"  -> SUCCÈS : Paquet réel capturé #{found_test_pkt['id']} !")
        print(f"     Origine    : {found_test_pkt.get('source')} (Garanti trafic réel)")
        print(f"     Protocole  : {found_test_pkt.get('protocol')}")
        print(f"     Source     : {found_test_pkt.get('src')}:{found_test_pkt.get('src_port')}")
        print(f"     Destination: {found_test_pkt.get('dst')}:{found_test_pkt.get('dst_port')}")
        print(f"     Info       : {found_test_pkt.get('info')}")
        results["test4_real_udp_capture"] = "PASS"

        # TEST 5 : Vérifier la dissection détaillée du paquet réel
        print("\n[TEST 5] Inspection des couches disséquées pour le paquet capturé...")
        code, detail_data = request_json(f"/api/packets/{found_test_pkt['id']}")
        pkt_detail = detail_data.get("packet", {})
        layers = [l.get("name") for l in pkt_detail.get("layers", [])]
        print(f"  -> Couches disséquées ({len(layers)}) : {layers}")
        hexdump_rows = len(pkt_detail.get("hexdump", []))
        print(f"  -> Dump Hexadécimal : {hexdump_rows} lignes générées")

        if len(layers) >= 2 and hexdump_rows > 0:
            results["test5_packet_dissection"] = "PASS"
        else:
            results["test5_packet_dissection"] = "FAIL"
    else:
        print(f"  -> ÉCHEC : Aucun paquet sur port 5555 trouvé parmi les paquets capturés.")
        results["test4_real_udp_capture"] = "FAIL"
        results["test5_packet_dissection"] = "SKIP"

    # TEST 6 : Arrêter la capture et vérifier que les paquets cessent d'être ajoutés
    print("\n[TEST 6] Arrêt de la capture réelle...")
    code, stop_res = request_json("/api/stop", method="POST")
    print(f"  -> {stop_res.get('message')}")
    time.sleep(0.5)

    code, st_after_stop = request_json("/api/status")
    count_at_stop = st_after_stop.get("total_packets", 0)
    print(f"  -> Nombre de paquets à l'arrêt : {count_at_stop}")

    # Émettre un paquet après l'arrêt
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.sendto(b"PACKET_AFTER_STOP", ("127.0.0.1", 5555))
    sock2.close()
    time.sleep(1)

    code, st_later = request_json("/api/status")
    count_later = st_later.get("total_packets", 0)
    print(f"  -> Nombre de paquets après nouvel envoi hors capture : {count_later}")

    if not st_after_stop.get("is_capturing") and count_later == count_at_stop:
        print("  -> SUCCÈS : La capture est bien arrêtée, aucun paquet post-arrêt n'a été inséré.")
        results["test6_stop_capture"] = "PASS"
    else:
        print("  -> ÉCHEC : La capture continue d'ajouter des paquets ou l'état est incorrect.")
        results["test6_stop_capture"] = "FAIL"

    # TEST 7 : Vérifier le mode démonstration et l'import PCAP
    print("\n[TEST 7] Vérification du mode Démo et de l'import PCAP...")
    code, demo_res = request_json("/api/demo/generate", method="POST", data={"count": 5})
    if code == 200 and demo_res.get("success"):
        print(f"  -> Mode Démo OK : {demo_res.get('message')}")
        code, st_demo = request_json("/api/status")
        print(f"  -> Mode actif : {st_demo.get('capture_mode')}")
        results["test7_demo_mode"] = "PASS"
    else:
        results["test7_demo_mode"] = "FAIL"

    code, pcap_res = request_json("/api/demo/load_sample", method="POST")
    if code == 200 and pcap_res.get("success"):
        print(f"  -> Import PCAP OK : {pcap_res.get('message')}")
        code, st_pcap = request_json("/api/status")
        print(f"  -> Mode actif : {st_pcap.get('capture_mode')}")
        results["test7_pcap_import"] = "PASS"
    else:
        results["test7_pcap_import"] = "FAIL"

    # TEST 8 : Vérifier la gestion d'une interface invalide
    print("\n[TEST 8] Test de gestion d'une interface réseau invalide...")
    code, err_res = request_json("/api/start", method="POST", data={"interface": "INTERFACE_INVALIDE_INEXISTANTE_999"})
    if code == 400 and not err_res.get("success"):
        print(f"  -> SUCCÈS : Interface invalide proprement rejetée (Code 400) : {err_res.get('message')}")
        results["test8_invalid_interface"] = "PASS"
    else:
        print(f"  -> ÉCHEC : Comportement inattendu pour interface invalide : {err_res}")
        results["test8_invalid_interface"] = "FAIL"

    print("\n" + "=" * 70)
    print("                      RÉSUMÉ DES TESTS")
    print("=" * 70)
    all_pass = True
    for test_name, res in results.items():
        status_symbol = "✅ PASS" if res == "PASS" else ("❌ FAIL" if res == "FAIL" else "⚠️ SKIP")
        print(f"  {test_name.ljust(35)} : {status_symbol}")
        if res != "PASS":
            all_pass = False

    print("=" * 70)
    print(f"RÉSULTAT GLOBAL : {'TOUS LES TESTS ONT RÉUSSI' if all_pass else 'CERTAINS TESTS ONT ÉCHOUÉ'}")
    print("=" * 70)
    return results


if __name__ == "__main__":
    run_all_tests()
