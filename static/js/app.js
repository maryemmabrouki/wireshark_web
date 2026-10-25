/**
 * SharkWeb - Logique Client JavaScript
 * Inspiré de Wireshark : capture temps réel, filtres, sélection maître-détail, hex dump
 */

document.addEventListener("DOMContentLoaded", () => {
    // -----------------------------------------------------------------------
    // État de l'application
    // -----------------------------------------------------------------------
    const state = {
        isCapturing: false,
        isDemoMode: false,
        selectedPacketId: null,
        autoScroll: true,
        filterProto: "all",
        filterQuery: "",
        lastSinceId: 0,
        pollingTimer: null,
        packetsMap: new Map(), // ID -> résumé du paquet
    };

    // -----------------------------------------------------------------------
    // Éléments du DOM
    // -----------------------------------------------------------------------
    const elements = {
        // En-tête et Métriques
        statusPill: document.getElementById("status-pill"),
        statusText: document.getElementById("status-text"),
        activeModeBadge: document.getElementById("active-mode-badge"),
        metricTotalPkts: document.getElementById("metric-total-pkts"),
        metricPktRate: document.getElementById("metric-pkt-rate"),
        btnStatsModal: document.getElementById("btn-stats-modal"),
        btnLoadSample: document.getElementById("btn-load-sample"),
        btnUploadTrigger: document.getElementById("btn-upload-trigger"),
        inputPcapFile: document.getElementById("input-pcap-file"),
        btnExportPcap: document.getElementById("btn-export-pcap"),

        // Toolbar
        btnStart: document.getElementById("btn-start"),
        btnStop: document.getElementById("btn-stop"),
        btnClear: document.getElementById("btn-clear"),
        selectInterface: document.getElementById("select-interface"),
        btnTestIndutwin: document.getElementById("btn-test-indutwin"),
        btnGenerateDemo: document.getElementById("btn-generate-demo"),
        checkAutoscroll: document.getElementById("check-autoscroll"),

        // Bannière d'erreur
        errorBanner: document.getElementById("error-banner"),
        errorBannerText: document.getElementById("error-banner-text"),
        btnCloseError: document.getElementById("btn-close-error"),

        // Filtres
        inputFilter: document.getElementById("input-filter"),
        btnApplyFilter: document.getElementById("btn-apply-filter"),
        btnResetFilter: document.getElementById("btn-reset-filter"),
        filterChips: document.querySelectorAll(".chip"),

        // Tableau des paquets
        tableWrapper: document.getElementById("packet-table-wrapper"),
        packetTbody: document.getElementById("packet-tbody"),

        // Volet de détails (Dissection & Hex Dump)
        detailSection: document.getElementById("details-section"),
        detailPacketBadge: document.getElementById("detail-packet-badge"),
        btnFullPageDetail: document.getElementById("btn-full-page-detail"),
        layerTreeContainer: document.getElementById("layer-tree-container"),
        hexdumpLenBadge: document.getElementById("hexdump-len-badge"),
        hexdumpContainer: document.getElementById("hexdump-container"),
        btnCopyHex: document.getElementById("btn-copy-hex"),

        // Footer
        footerPacketCount: document.getElementById("footer-packet-count"),
        footerInterface: document.getElementById("footer-interface"),
        footerStatusMsg: document.getElementById("footer-status-msg"),

        // Modale de Statistiques
        statsModal: document.getElementById("stats-modal"),
        btnCloseStats: document.getElementById("btn-close-stats"),
        statTotalPkts: document.getElementById("stat-total-pkts"),
        statTotalBytes: document.getElementById("stat-total-bytes"),
        statDuration: document.getElementById("stat-duration"),
        statRate: document.getElementById("stat-rate"),
        statsProtocolsBars: document.getElementById("stats-protocols-bars"),
        statsTopIps: document.getElementById("stats-top-ips"),
    };

    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------
    async function init() {
        setupEventListeners();
        await loadInterfaces();
        await checkStatus();
        await reloadPackets();

        // Démarrage de la boucle de rafraîchissement
        startPolling();
    }

    // -----------------------------------------------------------------------
    // Gestion des Événements
    // -----------------------------------------------------------------------
    function setupEventListeners() {
        // Boutons de capture
        elements.btnStart.addEventListener("click", handleStartCapture);
        elements.btnStop.addEventListener("click", handleStopCapture);
        elements.btnClear.addEventListener("click", handleClearPackets);
        elements.btnGenerateDemo.addEventListener("click", handleGenerateDemo);
        elements.btnLoadSample.addEventListener("click", handleLoadSample);

        if (elements.btnTestIndutwin) {
            elements.btnTestIndutwin.addEventListener("click", handleSendTestTraffic);
        }

        if (elements.btnCloseError) {
            elements.btnCloseError.addEventListener("click", () => {
                if (elements.errorBanner) elements.errorBanner.style.display = "none";
            });
        }

        // Auto-scroll
        elements.checkAutoscroll.addEventListener("change", (e) => {
            state.autoScroll = e.target.checked;
        });

        // Détection de défilement manuel dans le tableau
        elements.tableWrapper.addEventListener("scroll", () => {
            const el = elements.tableWrapper;
            const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
            if (!isAtBottom && state.autoScroll && elements.checkAutoscroll.checked) {
                // L'utilisateur navigue manuellement
            }
        });

        // Import PCAP
        elements.btnUploadTrigger.addEventListener("click", () => elements.inputPcapFile.click());
        elements.inputPcapFile.addEventListener("change", handleUploadPcap);

        // Filtre textuel
        elements.btnApplyFilter.addEventListener("click", applyFilter);
        elements.inputFilter.addEventListener("keydown", (e) => {
            if (e.key === "Enter") applyFilter();
        });
        elements.btnResetFilter.addEventListener("click", resetFilter);

        // Chips de filtre rapide par protocole
        elements.filterChips.forEach((chip) => {
            chip.addEventListener("click", () => {
                elements.filterChips.forEach((c) => c.classList.remove("active"));
                chip.classList.add("active");
                state.filterProto = chip.dataset.proto;
                reloadPackets();
            });
        });

        // Modale Statistiques
        elements.btnStatsModal.addEventListener("click", openStatsModal);
        elements.btnCloseStats.addEventListener("click", closeStatsModal);
        elements.statsModal.addEventListener("click", (e) => {
            if (e.target === elements.statsModal) closeStatsModal();
        });

        // Copier Hex
        elements.btnCopyHex.addEventListener("click", () => {
            if (elements.hexdumpContainer.dataset.rawHex) {
                navigator.clipboard.writeText(elements.hexdumpContainer.dataset.rawHex);
                showToast("Octets bruts hexadécimaux copiés !");
            }
        });

        // Navigation Clavier (Flèche Haut / Bas pour changer de paquet)
        document.addEventListener("keydown", handleKeyNavigation);
    }

    // -----------------------------------------------------------------------
    // Chargement des Interfaces
    // -----------------------------------------------------------------------
    async function loadInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            const data = await res.json();
            if (data.success && data.interfaces) {
                elements.selectInterface.innerHTML = "";
                data.interfaces.forEach((iface) => {
                    const opt = document.createElement("option");
                    opt.value = iface.id;
                    opt.textContent = `${iface.name} ${iface.ip && iface.ip !== "Non configurée" ? `(${iface.ip})` : ""}`;
                    elements.selectInterface.appendChild(opt);
                });
            }
        } catch (err) {
            console.error("Erreur chargement interfaces :", err);
        }
    }

    // -----------------------------------------------------------------------
    // Vérification de l'État de Capture
    // -----------------------------------------------------------------------
    async function checkStatus() {
        try {
            const res = await fetch("/api/status");
            const data = await res.json();
            if (data.success) {
                updateUIState(
                    data.is_capturing,
                    data.is_demo_mode,
                    data.capture_mode,
                    data.last_status,
                    data.last_error,
                    data.selected_interface_name
                );
                elements.metricTotalPkts.textContent = data.total_packets;
            }
        } catch (err) {
            console.error("Erreur check status :", err);
        }
    }

    function updateUIState(isCapturing, isDemoMode, captureMode, statusMsg, lastError, ifaceName) {
        state.isCapturing = isCapturing;
        state.isDemoMode = isDemoMode;
        state.captureMode = captureMode || "NONE";

        elements.btnStart.disabled = isCapturing;
        elements.btnStop.disabled = !isCapturing;
        elements.selectInterface.disabled = isCapturing;

        // Mise à jour de la pilule d'état
        elements.statusPill.className = "status-pill";
        if (lastError) {
            elements.statusPill.classList.add("status-error");
            elements.statusText.textContent = "Erreur";
        } else if (!isCapturing) {
            elements.statusPill.classList.add("status-stopped");
            elements.statusText.textContent = "Arrêté";
        } else if (isDemoMode || captureMode === "DEMO") {
            elements.statusPill.classList.add("status-demo");
            elements.statusText.textContent = "Mode Démo";
        } else {
            elements.statusPill.classList.add("status-running");
            elements.statusText.textContent = "En Direct (Réel)";
        }

        // Mise à jour du badge d'origine
        if (elements.activeModeBadge) {
            elements.activeModeBadge.className = "badge-source";
            if (captureMode === "LIVE") {
                elements.activeModeBadge.classList.add("badge-source-live");
                elements.activeModeBadge.textContent = `🟢 Source : Capture Réelle (${ifaceName || "En direct"})`;
            } else if (captureMode === "PCAP") {
                elements.activeModeBadge.classList.add("badge-source-pcap");
                elements.activeModeBadge.textContent = "📁 Source : Fichier PCAP";
            } else if (captureMode === "DEMO") {
                elements.activeModeBadge.classList.add("badge-source-demo");
                elements.activeModeBadge.textContent = "🧪 Source : Démonstration (Simulée)";
            } else {
                elements.activeModeBadge.textContent = "⚪ Source : Inactive";
            }
        }

        // Gestion de la bannière d'erreur
        if (elements.errorBanner) {
            if (lastError) {
                elements.errorBanner.style.display = "flex";
                if (elements.errorBannerText) elements.errorBannerText.textContent = lastError;
            } else {
                elements.errorBanner.style.display = "none";
            }
        }

        if (statusMsg) {
            elements.footerStatusMsg.textContent = statusMsg;
        }

        const currentIfaceName = ifaceName || elements.selectInterface.options[elements.selectInterface.selectedIndex]?.text || "Inconnue";
        elements.footerInterface.textContent = `Interface : ${currentIfaceName}`;
    }

    // -----------------------------------------------------------------------
    // Actions de Capture
    // -----------------------------------------------------------------------
    async function handleStartCapture() {
        const chosenInterface = elements.selectInterface.value;
        try {
            const res = await fetch("/api/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ interface: chosenInterface }),
            });
            const data = await res.json();
            if (data.success) {
                updateUIState(true, data.is_demo_mode, data.capture_mode, data.message, null, data.interface_name);
                showToast(data.message, "success");
                await reloadPackets();
            } else {
                updateUIState(false, false, "NONE", data.message, data.message);
                showToast(`Échec du démarrage : ${data.message}`, "error");
            }
        } catch (err) {
            updateUIState(false, false, "NONE", err.message, err.message);
            showToast(`Erreur réseau : ${err.message}`, "error");
        }
    }

    async function handleStopCapture() {
        try {
            const res = await fetch("/api/stop", { method: "POST" });
            const data = await res.json();
            if (data.success) {
                updateUIState(false, false, data.capture_mode, data.message, null);
                showToast(data.message);
            }
        } catch (err) {
            showToast(`Erreur : ${err.message}`, "error");
        }
    }

    async function handleSendTestTraffic() {
        showToast("Émission d'un paquet de test local UDP Multicast (224.1.1.1:5555)...");
        try {
            const res = await fetch("/api/test_traffic", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    type: "multicast",
                    target_ip: "224.1.1.1",
                    port: 5555,
                    message: "INDUTWIN_TEST_TELEMETRY"
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message, "success");
            } else {
                showToast(`Erreur émission test : ${data.error}`, "error");
            }
        } catch (err) {
            showToast(`Erreur : ${err.message}`, "error");
        }
    }

    async function handleClearPackets() {
        try {
            const res = await fetch("/api/clear", { method: "POST" });
            const data = await res.json();
            if (data.success) {
                state.packetsMap.clear();
                state.lastSinceId = 0;
                state.selectedPacketId = null;
                elements.packetTbody.innerHTML = `
                    <tr class="empty-row">
                        <td colspan="7">
                            <div class="empty-state">
                                <p>Tampon vidé. Démarrez une capture ou cliquez sur "+15 Paquets Démo".</p>
                            </div>
                        </td>
                    </tr>
                `;
                resetDetailsPanes();
                updateCounts(0, 0);
                showToast(data.message);
            }
        } catch (err) {
            showToast(`Erreur : ${err.message}`, "error");
        }
    }

    async function handleGenerateDemo() {
        try {
            const res = await fetch("/api/demo/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ count: 8 }),
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message, "success");
                await reloadPackets();
            }
        } catch (err) {
            showToast(`Erreur : ${err.message}`, "error");
        }
    }

    async function handleLoadSample() {
        try {
            const res = await fetch("/api/demo/load_sample", { method: "POST" });
            const data = await res.json();
            if (data.success) {
                showToast(data.message, "success");
                await reloadPackets();
            }
        } catch (err) {
            showToast(`Erreur : ${err.message}`, "error");
        }
    }

    async function handleUploadPcap(e) {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append("pcap_file", file);

        showToast(`Analyse du fichier PCAP "${file.name}" en cours...`);

        try {
            const res = await fetch("/api/upload_pcap", {
                method: "POST",
                body: formData,
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message, "success");
                await reloadPackets();
            } else {
                showToast(`Erreur PCAP : ${data.error}`, "error");
            }
        } catch (err) {
            showToast(`Erreur téléversement : ${err.message}`, "error");
        } finally {
            elements.inputPcapFile.value = "";
        }
    }

    // -----------------------------------------------------------------------
    // Filtrage des Paquets
    // -----------------------------------------------------------------------
    function applyFilter() {
        state.filterQuery = elements.inputFilter.value.trim();
        reloadPackets();
    }

    function resetFilter() {
        elements.inputFilter.value = "";
        state.filterQuery = "";
        state.filterProto = "all";
        elements.filterChips.forEach((c) => {
            if (c.dataset.proto === "all") c.classList.add("active");
            else c.classList.remove("active");
        });
        reloadPackets();
    }

    // -----------------------------------------------------------------------
    // Chargement et Rendu des Paquets
    // -----------------------------------------------------------------------
    async function reloadPackets() {
        const params = new URLSearchParams();
        if (state.filterProto && state.filterProto !== "all") {
            params.append("protocol", state.filterProto);
        }
        if (state.filterQuery) {
            params.append("query", state.filterQuery);
        }
        params.append("limit", "1000");

        try {
            const res = await fetch(`/api/packets?${params.toString()}`);
            const data = await res.json();
            if (data.success) {
                renderPacketTable(data.packets);
                updateCounts(data.matching, data.total);
                if (data.packets.length > 0) {
                    state.lastSinceId = data.packets[data.packets.length - 1].id;
                }
            }
        } catch (err) {
            console.error("Erreur reload packets :", err);
        }
    }

    function renderPacketTable(packets) {
        state.packetsMap.clear();

        if (packets.length === 0) {
            elements.packetTbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="8">
                        <div class="empty-state">
                            <p>Aucun paquet ne correspond aux filtres actuels.</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        const fragment = document.createDocumentFragment();

        packets.forEach((p) => {
            state.packetsMap.set(p.id, p);
            const tr = createPacketRow(p);
            fragment.appendChild(tr);
        });

        elements.packetTbody.innerHTML = "";
        elements.packetTbody.appendChild(fragment);

        // Si un paquet était sélectionné, restaurer la sélection
        if (state.selectedPacketId && state.packetsMap.has(state.selectedPacketId)) {
            const row = document.getElementById(`pkt-row-${state.selectedPacketId}`);
            if (row) row.classList.add("selected");
        }

        // Auto-scroll si activé
        if (state.autoScroll) {
            elements.tableWrapper.scrollTop = elements.tableWrapper.scrollHeight;
        }
    }

    function createPacketRow(p) {
        const tr = document.createElement("tr");
        tr.id = `pkt-row-${p.id}`;
        tr.dataset.pktId = p.id;

        // Origine du paquet (LIVE, PCAP, DEMO)
        const srcMode = (p.source || "LIVE").toUpperCase();
        const originBadgeClass = srcMode === "LIVE" ? "badge-origin-live" : (srcMode === "PCAP" ? "badge-origin-pcap" : "badge-origin-demo");
        const originLabel = srcMode === "LIVE" ? "LIVE" : (srcMode === "PCAP" ? "PCAP" : "DÉMO");

        // Classe de surbrillance légère basée sur le protocole
        const protoLower = p.protocol.toLowerCase();
        tr.classList.add(`row-${protoLower}`);

        tr.innerHTML = `
            <td class="col-no">${p.id}</td>
            <td class="col-src-mode"><span class="badge-origin ${originBadgeClass}">${originLabel}</span></td>
            <td class="col-time">${p.time}</td>
            <td class="col-src" title="${escapeHtml(p.src)}">${escapeHtml(p.src)}</td>
            <td class="col-dst" title="${escapeHtml(p.dst)}">${escapeHtml(p.dst)}</td>
            <td class="col-proto"><span class="badge ${p.badge_class}">${escapeHtml(p.protocol)}</span></td>
            <td class="col-len">${p.length}</td>
            <td class="col-info" title="${escapeHtml(p.info)}">${escapeHtml(p.info)}</td>
        `;

        tr.addEventListener("click", () => selectPacket(p.id));
        tr.addEventListener("dblclick", () => {
            window.open(`/packet/${p.id}`, "_blank");
        });

        return tr;
    }

    function updateCounts(displayed, total) {
        elements.footerPacketCount.textContent = `${displayed} paquet(s) affiché(s) sur ${total} au total`;
        elements.metricTotalPkts.textContent = total;
    }

    // -----------------------------------------------------------------------
    // Sélection et Dissection d'un Paquet
    // -----------------------------------------------------------------------
    async function selectPacket(pktId) {
        state.selectedPacketId = pktId;

        // Mise à jour visuelle de la sélection dans la table
        document.querySelectorAll(".packet-table tbody tr").forEach((r) => r.classList.remove("selected"));
        const row = document.getElementById(`pkt-row-${pktId}`);
        if (row) row.classList.add("selected");

        // Affichage de l'état de chargement dans les volets de détails
        elements.detailPacketBadge.textContent = `Paquet #${pktId}`;
        elements.btnFullPageDetail.style.display = "inline-flex";
        elements.btnFullPageDetail.href = `/packet/${pktId}`;
        elements.btnCopyHex.style.display = "inline-flex";

        try {
            const res = await fetch(`/api/packets/${pktId}`);
            const data = await res.json();
            if (data.success && data.packet) {
                renderDissectionTree(data.packet);
                renderHexDump(data.packet);
            }
        } catch (err) {
            console.error("Erreur récupération détails paquet :", err);
        }
    }

    function renderDissectionTree(packet) {
        if (!packet.layers || packet.layers.length === 0) {
            elements.layerTreeContainer.innerHTML = "<p>Aucune couche protocolaire analysable.</p>";
            return;
        }

        const container = document.createElement("div");
        container.className = "layers-accordion";

        packet.layers.forEach((layer, idx) => {
            const card = document.createElement("div");
            card.className = "layer-card";

            const header = document.createElement("div");
            header.className = "layer-header";
            header.innerHTML = `
                <span class="layer-chevron">▼</span>
                <span class="layer-badge-tag">${escapeHtml(layer.badge)}</span>
                <span class="layer-title-text">${escapeHtml(layer.name)}</span>
            `;
            header.addEventListener("click", () => card.classList.toggle("collapsed"));

            const body = document.createElement("div");
            body.className = "layer-body";

            const table = document.createElement("table");
            table.className = "fields-table";
            table.innerHTML = `
                <tbody>
                    ${layer.fields
                        .map(
                            (f) => `
                        <tr>
                            <td class="field-name">${escapeHtml(f.name)}</td>
                            <td class="field-val"><code>${escapeHtml(f.value)}</code></td>
                        </tr>
                    `
                        )
                        .join("")}
                </tbody>
            `;

            body.appendChild(table);
            card.appendChild(header);
            card.appendChild(body);
            container.appendChild(card);
        });

        elements.layerTreeContainer.innerHTML = "";
        elements.layerTreeContainer.appendChild(container);
    }

    function renderHexDump(packet) {
        elements.hexdumpLenBadge.textContent = `${packet.length} octets`;
        elements.hexdumpContainer.dataset.rawHex = packet.raw_hex || "";

        if (!packet.hexdump || packet.hexdump.length === 0) {
            elements.hexdumpContainer.innerHTML = "<p>Dump indisponible.</p>";
            return;
        }

        const linesHtml = packet.hexdump
            .map((line) => {
                const hexBytesHtml = line.bytes_hex
                    .map((b) => `<span class="hex-byte">${b}</span>`)
                    .join("");
                return `
                <div class="hex-row">
                    <span class="hex-offset">${line.offset}</span>
                    <span class="hex-bytes">${hexBytesHtml}</span>
                    <span class="hex-ascii">${escapeHtml(line.bytes_ascii)}</span>
                </div>
            `;
            })
            .join("");

        elements.hexdumpContainer.innerHTML = linesHtml;
    }

    function resetDetailsPanes() {
        elements.detailPacketBadge.textContent = "Sélectionnez un paquet";
        elements.btnFullPageDetail.style.display = "none";
        elements.btnCopyHex.style.display = "none";
        elements.layerTreeContainer.innerHTML = `
            <div class="unselected-message">
                <svg viewBox="0 0 24 24" class="placeholder-icon"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                <p>Cliquez sur une ligne du tableau ci-dessus pour inspecter les couches.</p>
            </div>
        `;
        elements.hexdumpLenBadge.textContent = "0 octets";
        elements.hexdumpContainer.innerHTML = `
            <div class="unselected-message">
                <p>Les octets bruts s'afficheront ici en hexadécimal et ASCII.</p>
            </div>
        `;
    }

    // -----------------------------------------------------------------------
    // Boucle de Polling Temps Réel
    // -----------------------------------------------------------------------
    function startPolling() {
        if (state.pollingTimer) clearInterval(state.pollingTimer);

        state.pollingTimer = setInterval(async () => {
            if (!state.isCapturing) return;

            // Récupération des nouveaux paquets incrémentaux
            try {
                const params = new URLSearchParams();
                if (state.filterProto && state.filterProto !== "all") params.append("protocol", state.filterProto);
                if (state.filterQuery) params.append("query", state.filterQuery);
                params.append("since_id", state.lastSinceId.toString());

                const res = await fetch(`/api/packets?${params.toString()}`);
                const data = await res.json();
                if (data.success && data.packets.length > 0) {
                    appendIncrementalPackets(data.packets);
                    updateCounts(state.packetsMap.size, data.total);
                    state.lastSinceId = data.packets[data.packets.length - 1].id;
                }

                // Mise à jour périodique des métriques de débit
                const statsRes = await fetch("/api/stats");
                const statsData = await statsRes.json();
                if (statsData.success) {
                    elements.metricPktRate.textContent = `${statsData.stats.packets_per_second} pkts/s`;
                }
            } catch (err) {
                console.error("Polling error :", err);
            }
        }, 800);
    }

    function appendIncrementalPackets(newPackets) {
        // Enlever la ligne vide si présente
        const emptyRow = elements.packetTbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const fragment = document.createDocumentFragment();

        newPackets.forEach((p) => {
            if (!state.packetsMap.has(p.id)) {
                state.packetsMap.set(p.id, p);
                const tr = createPacketRow(p);
                fragment.appendChild(tr);
            }
        });

        elements.packetTbody.appendChild(fragment);

        if (state.autoScroll) {
            elements.tableWrapper.scrollTop = elements.tableWrapper.scrollHeight;
        }
    }

    // -----------------------------------------------------------------------
    // Modale Statistiques
    // -----------------------------------------------------------------------
    async function openStatsModal() {
        elements.statsModal.classList.add("active");
        try {
            const res = await fetch("/api/stats");
            const data = await res.json();
            if (data.success) {
                const s = data.stats;
                elements.statTotalPkts.textContent = s.total_packets;
                elements.statTotalBytes.textContent = formatBytes(s.total_bytes);
                elements.statDuration.textContent = `${s.duration_seconds} s`;
                elements.statRate.textContent = `${s.packets_per_second} /s`;

                // Barres de répartition par protocole
                elements.statsProtocolsBars.innerHTML = s.protocols
                    .map(
                        (p) => `
                    <div class="proto-bar-item">
                        <span class="proto-bar-name">${escapeHtml(p.name)}</span>
                        <div class="proto-bar-track">
                            <div class="proto-bar-fill" style="width: ${p.percent}%;"></div>
                        </div>
                        <span class="proto-bar-pct">${p.count} (${p.percent}%)</span>
                    </div>
                `
                    )
                    .join("");

                // Top Talkers IP
                elements.statsTopIps.innerHTML = s.top_ips
                    .map(
                        (ip) => `
                    <div class="top-ip-row">
                        <span class="top-ip-addr">${escapeHtml(ip.ip)}</span>
                        <span class="top-ip-count">${ip.count} paquets</span>
                    </div>
                `
                    )
                    .join("");
            }
        } catch (err) {
            console.error("Erreur stats :", err);
        }
    }

    function closeStatsModal() {
        elements.statsModal.classList.remove("active");
    }

    // -----------------------------------------------------------------------
    // Navigation Clavier
    // -----------------------------------------------------------------------
    function handleKeyNavigation(e) {
        if (!state.selectedPacketId) return;
        if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;

        const allIds = Array.from(state.packetsMap.keys());
        const currIdx = allIds.indexOf(state.selectedPacketId);
        if (currIdx === -1) return;

        if (e.key === "ArrowDown" && currIdx < allIds.length - 1) {
            e.preventDefault();
            selectPacket(allIds[currIdx + 1]);
            scrollToSelectedRow();
        } else if (e.key === "ArrowUp" && currIdx > 0) {
            e.preventDefault();
            selectPacket(allIds[currIdx - 1]);
            scrollToSelectedRow();
        }
    }

    function scrollToSelectedRow() {
        const row = document.getElementById(`pkt-row-${state.selectedPacketId}`);
        if (row) {
            row.scrollIntoView({ block: "nearest", behavior: "smooth" });
        }
    }

    // -----------------------------------------------------------------------
    // Utilitaires
    // -----------------------------------------------------------------------
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "Ko", "Mo", "Go"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function showToast(message, type = "info") {
        const existing = document.querySelector(".toast-notification");
        if (existing) existing.remove();

        const toast = document.createElement("div");
        toast.className = `toast-notification toast-${type}`;
        toast.textContent = message;
        toast.style.position = "fixed";
        toast.style.bottom = "36px";
        toast.style.right = "20px";
        toast.style.background = type === "error" ? "#ef4444" : type === "success" ? "#10b981" : "#1e293b";
        toast.style.color = "white";
        toast.style.padding = "8px 16px";
        toast.style.borderRadius = "6px";
        toast.style.fontSize = "12px";
        toast.style.fontWeight = "500";
        toast.style.boxShadow = "0 4px 15px rgba(0,0,0,0.4)";
        toast.style.zIndex = "9999";
        toast.style.transition = "opacity 0.3s ease";

        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = "0";
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    }

    // Lancement
    init();
});
