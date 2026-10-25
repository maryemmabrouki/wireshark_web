# 🦈 SharkWeb — Analyseur Réseau Web Inspiré de Wireshark

> **SharkWeb** est une application Web moderne développée en **Python (Flask + Scapy)** qui reproduit l'expérience et les fonctionnalités clés de **Wireshark** directement dans votre navigateur web.

---

## 📋 Table des Matières

1. [Présentation & Objectifs Pédagogiques](#-présentation--objectifs-pédagogiques)
2. [Architecture Technique](#-architecture-technique)
3. [Fonctionnalités Clés](#-fonctionnalités-clés)
4. [Détail des Protocoles Analysés](#-détail-des-protocoles-analysés)
5. [Installation & Démarrage](#-installation--démarrage)
6. [Guide d'Utilisation](#-guide-dutilisation)
7. [Sécurité & Éthique](#-sécurité--éthique)

---

## 🎯 Présentation & Objectifs Pédagogiques

Wireshark est l'outil de référence mondial pour l'analyse des trames et paquets réseau. Ce projet a pour but de comprendre en profondeur le fonctionnement d'un analyseur de paquets en construisant une version Web complète :
- **Capture passive** des paquets sur les interfaces réseau autorisées.
- **Dissection protocolaire** champ par champ (adresses MAC, en-têtes IP, flags TCP, requêtes DNS, méthodes HTTP, etc.).
- **Dump Hexadécimal & ASCII** pour l'inspection au niveau binaire (octet par octet).
- **Mode Démonstration & Simulateur** : permet d'analyser du trafic même sans accès administrateur ou sans connexion Internet active.
- **Gestion PCAP** : chargement et sauvegarde de fichiers de capture standard (`.pcap`).

---

## 🏗 Architecture Technique

L'application s'articule autour d'une architecture modulaire et multithreadée :

```
wireshark_web/
├── app.py                     # Serveur Flask et API REST
├── capture_engine.py          # Moteur de capture multithread Scapy + Simulateur
├── packet_parser.py           # Dissection des couches et formatage Hex/ASCII
├── requirements.txt           # Dépendances (Flask, Scapy)
├── sample_captures/
│   └── sample_traffic.pcap    # Fichier PCAP d'exemple inclus
├── static/
│   ├── css/
│   │   └── style.css          # Design Dark moderne inspiré de Wireshark
│   └── js/
│       └── app.js             # Polling temps réel, filtres et master-detail
└── templates/
    ├── index.html             # Interface principale (table + arborescence + hex)
    └── packet_detail.html     # Page dédiée de détails d'un paquet
```

### 1. `capture_engine.py` (Moteur de Capture & Démo)
- **Multithreading thread-safe** : exécute la capture Scapy en arrière-plan sans bloquer les requêtes Web.
- **Détection des interfaces** : interroge `conf.ifaces` pour lister les cartes réseau locales (Wi-Fi, Ethernet, Loopback).
- **Générateur de trafic virtuel** : simule des échanges réalistes (Requête/Réponse DNS, Handshake TCP 3-voies, Requêtes HTTP, Ping ICMP, Résolution ARP).
- **Lecteur / Exportateur PCAP** : utilise `rdpcap()` et `wrpcap()` de Scapy.

### 2. `packet_parser.py` (Dissecteur Protocolaire)
- Décompose chaque trame selon le modèle en couches OSI / TCP-IP :
  - **Couche 2 (Liaison)** : Ethernet II (Adresses MAC source/destination, Type de protocole).
  - **Couche 3 (Réseau)** : IPv4 (TTL, Checksum, Flags, IHL) ou ARP (Opcode, MACs, IPs).
  - **Couche 4 (Transport)** : TCP (Ports, Séquence, Acquittement, Flags SYN/ACK/FIN/RST/PSH, Fenêtre) ou UDP ou ICMP (Type, Code, Id, Seq).
  - **Couche 7 (Application)** : DNS (Nom de domaine, Type A/AAAA, Réponses), HTTP (Verbe, URI, Code statut), TLS (Handshake, Client Hello, SNI).
- Génère le **dump hexadécimal et ASCII** sous forme de lignes de 16 octets avec offset hexadécimal.

### 3. `app.py` & Interface Web
- API REST propre (`/api/status`, `/api/start`, `/api/stop`, `/api/packets`, `/api/stats`, etc.).
- Interface utilisateur avec disposition **Master-Detail** identique à Wireshark :
  - Haut : Tableau scrollable des paquets avec coloration selon le protocole.
  - Bas gauche : Arborescence hiérarchique dépliable (accordéon).
  - Bas droite : Visionneuse d'octets hexadécimaux et ASCII.
- Page de détails dédiée `/packet/<id>` pour l'inspection plein écran.

---

## ⚡ Fonctionnalités Clés

| Fonctionnalité | Description |
| :--- | :--- |
| **Capture en Direct** | Sniffing passif sur l'interface réseau autorisée de votre choix. |
| **Mode Démo Continu** | Flux simulé de paquets réseau pour tester sans contraintes de privilèges. |
| **Génération à la demande** | Bouton `+15 Paquets Démo` pour injecter immédiatement un lot diversifié. |
| **Filtres de Paquets** | Filtre textuel libre (ex: `dns`, `192.168.1.37`, `port 80`, `GET`) + Chips rapides par protocole. |
| **Arborescence des Couches** | Dissection détaillée et pliable pour chaque protocole de la trame. |
| **Dump Hexadécimal & ASCII** | Représentation binaire fidèle avec offset, octets hex et caractères ASCII. |
| **Import / Export PCAP** | Importez vos fichiers `.pcap` ou exportez votre capture pour l'ouvrir dans Wireshark officiel ! |
| **Statistiques Réseau** | Modale affichant la répartition des protocoles et les adresses IP les plus actives. |
| **Navigation Clavier** | Utilisez les touches `Flèche Haut` et `Flèche Bas` pour naviguer entre les paquets. |

---

## 🔍 Détail des Protocoles Analysés

- **ARP (Address Resolution Protocol)** : Résolution d'adresse IP en adresse MAC (`Who has X? Tell Y` et `X is at MAC`).
- **ICMP (Internet Control Message Protocol)** : Diagnostic réseau, requêtes et réponses Ping Echo.
- **DNS (Domain Name System)** : Requêtes de résolution de noms d'hôtes et réponses IP associées.
- **TCP (Transmission Control Protocol)** : Analyse des flags de connexion (`SYN`, `ACK`, `FIN`, `PSH`, `RST`) et des numéros de séquence.
- **UDP (User Datagram Protocol)** : Datagrammes sans connexion avec numéros de ports.
- **HTTP (Hypertext Transfer Protocol)** : Requêtes `GET` / `POST` et réponses `200 OK` avec aperçu de contenu.
- **TLS (Transport Layer Security)** : Détection des poignées de main sécurisées et extraction du champ **SNI** (*Server Name Indication*).

---

## 🚀 Installation & Démarrage

### Prérequis
- Python 3.10 ou supérieur.
- Npcap (recommandé sous Windows pour la capture en direct réelle). Si Npcap n'est pas présent, le **Mode Démo** et l'**Import PCAP** fonctionnent à 100% de manière autonome.

### 1. Installation des dépendances
Dans le terminal :
```bash
pip install -r wireshark_web/requirements.txt
```

### 2. Lancement du serveur Web
```bash
python wireshark_web/app.py
```

### 3. Accès à l'application
Ouvrez votre navigateur web à l'adresse :
👉 **http://127.0.0.1:5000**

---

## 📖 Guide d'Utilisation

1. **Observer les paquets d'exemple** : Dès l'ouverture, la capture de référence `sample_traffic.pcap` est automatiquement chargée.
2. **Inspecter un paquet** : Cliquez sur n'importe quelle ligne pour voir sa dissection et son dump hexadécimal.
3. **Tester les filtres** :
   - Cliquez sur le chip **DNS** pour n'afficher que les requêtes et réponses DNS.
   - Saisissez `192.168.1.37` ou `8.8.8.8` dans la barre de recherche et appuyez sur **Entrée**.
4. **Démarrer une capture** :
   - Pour tester le simulateur : sélectionnez `🧪 Simulateur / Mode Démo` puis cliquez sur **Démarrer**.
   - Pour capturer votre carte Wi-Fi : sélectionnez l'interface `Wi-Fi` puis cliquez sur **Démarrer**.
5. **Voir la page dédiée** : Double-cliquez sur une ligne ou cliquez sur **Ouvrir pleine page ↗** pour accéder à la vue complète du paquet.
6. **Consulter les statistiques** : Cliquez sur le bouton **Statistiques** dans l'en-tête pour voir les pourcentages protocolaires.
7. **Sauvegarder** : Cliquez sur **Exporter PCAP** pour enregistrer la capture sur votre machine.

---

## 🛡️ Sécurité & Éthique

- Cette application est un outil d'**analyse passive** (écoute et visualisation).
- Elle ne réalise **aucune injection offensive**, aucun scan de port non autorisé, aucune attaque de déni de service et aucun empoisonnement ARP.
- La capture de paquets doit toujours être réalisée sur votre propre machine ou sur un réseau pour lequel vous disposez d'une **autorisation explicite**.
