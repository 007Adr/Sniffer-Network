import customtkinter as ctk
from scapy.all import sniff, IP, UDP, wrpcap
import time
import threading
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import os
import csv
import statistics
import requests
from prometheus_client import start_http_server, Gauge

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
CONFIG_FILE = "config_jeux.txt"

class SnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Analyseur Réseau (Prometheus & Geo-IP)")
        self.geometry("1300x850")
        self.minsize(1100, 700)

        # --- INITIALISATION PROMETHEUS ---
        self.prom_tickrate = Gauge('game_tickrate_hz', 'Tickrate du serveur')
        self.prom_jitter = Gauge('game_jitter_ms', 'Jitter en millisecondes')
        self.prom_packet_loss = Gauge('game_packet_loss_pct', 'Pourcentage de perte de paquets')
        self.prom_cpu = Gauge('local_cpu_usage_pct', 'Charge CPU locale')
        self.prom_server_started = False

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.target_executables = self.load_or_create_config()

        # --- PANNEAU LATÉRAL (ONGLETS VERTICAUX) ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        self.title_label = ctk.CTkLabel(self.sidebar, text="Menu Principal", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        # Boutons de navigation
        self.btn_tab_dash = ctk.CTkButton(self.sidebar, text="📊 Tableau de Bord", command=lambda: self.select_tab("dash"), fg_color="transparent", border_width=1)
        self.btn_tab_dash.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.btn_tab_logs = ctk.CTkButton(self.sidebar, text="📝 Console & Logs", command=lambda: self.select_tab("logs"), fg_color="transparent", border_width=1)
        self.btn_tab_logs.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_tab_settings = ctk.CTkButton(self.sidebar, text="⚙️ Paramètres", command=lambda: self.select_tab("settings"), fg_color="transparent", border_width=1)
        self.btn_tab_settings.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        # Bouton d'action global (Reste toujours visible)
        self.start_btn = ctk.CTkButton(self.sidebar, text="▶ Lancer l'Analyse", fg_color="#16a34a", hover_color="#15803d", command=self.toggle_capture)
        self.start_btn.grid(row=6, column=0, padx=20, pady=30)

        # --- VUES (Frames) ---
        self.frames = {}
        
        # 1. Vue : Tableau de Bord
        self.frames["dash"] = ctk.CTkFrame(self, fg_color="transparent")
        self.frames["dash"].grid_rowconfigure(0, weight=1)
        self.frames["dash"].grid_columnconfigure(0, weight=1)
        self.graph_frame = ctk.CTkFrame(self.frames["dash"])
        self.graph_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 2. Vue : Logs & Geo-IP
        self.frames["logs"] = ctk.CTkFrame(self, fg_color="transparent")
        self.frames["logs"].grid_rowconfigure(1, weight=1)
        self.frames["logs"].grid_columnconfigure(0, weight=1)
        
        self.geoip_label = ctk.CTkLabel(self.frames["logs"], text="🌍 Cible : En attente d'identification...", font=ctk.CTkFont(size=14))
        self.geoip_label.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        
        self.console = ctk.CTkTextbox(self.frames["logs"], font=ctk.CTkFont(family="Consolas", size=12))
        self.console.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        # 3. Vue : Paramètres
        self.frames["settings"] = ctk.CTkFrame(self, fg_color="transparent")
        self.frames["settings"].grid_columnconfigure(0, weight=1)
        
        self.detect_btn = ctk.CTkButton(self.frames["settings"], text="🔍 Auto-détecter Jeu (Recommandé)", fg_color="#d97706", hover_color="#b45309", command=self.auto_detect_game)
        self.detect_btn.grid(row=0, column=0, padx=20, pady=20)

        self.ip_entry = ctk.CTkEntry(self.frames["settings"], placeholder_text="IP Serveur")
        self.ip_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.port_entry = ctk.CTkEntry(self.frames["settings"], placeholder_text="Port UDP")
        self.port_entry.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.pcap_switch = ctk.CTkSwitch(self.frames["settings"], text="Enregistrer PCAP brut")
        self.pcap_switch.grid(row=3, column=0, padx=20, pady=20, sticky="w")
        
        self.prom_switch = ctk.CTkSwitch(self.frames["settings"], text="Activer Serveur Prometheus (Port 8000)")
        self.prom_switch.grid(row=4, column=0, padx=20, pady=10, sticky="w")

        self.export_md_btn = ctk.CTkButton(self.frames["settings"], text="📄 Exporter Markdown", state="disabled", command=self.export_markdown)
        self.export_md_btn.grid(row=5, column=0, padx=20, pady=10, sticky="ew")
        
        self.export_csv_btn = ctk.CTkButton(self.frames["settings"], text="📊 Exporter CSV", state="disabled", command=self.export_csv)
        self.export_csv_btn.grid(row=6, column=0, padx=20, pady=10, sticky="ew")

        # Variables système
        self.packet_timestamps = []
        self.hardware_stats = []
        self.raw_packets = []
        self.capture_running = False
        self.last_metrics = {}
        self.deltas_ms = []

        # Démarrage
        self.console.insert("0.0", "[*] Application initialisée.\n")
        self.console.configure(state="disabled")
        self.select_tab("settings") # Ouvre l'onglet Paramètres par défaut

    def select_tab(self, tab_name):
        """Système de navigation par onglets verticaux."""
        for name, frame in self.frames.items():
            if name == tab_name:
                frame.grid(row=0, column=1, sticky="nsew")
            else:
                frame.grid_forget()

    def load_or_create_config(self):
        default_games = ["valorant-win64-shipping.exe", "rocketleague.exe", "cs2.exe"]
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                for game in default_games: f.write(f"{game}\n")
            return default_games
        with open(CONFIG_FILE, "r") as f:
            return [line.strip().lower() for line in f.readlines() if line.strip()]

    def log_to_console(self, message):
        self.console.configure(state="normal")
        self.console.insert("end", message + "\n")
        self.console.configure(state="disabled")
        self.console.see("end")

    def resolve_geoip(self, ip):
        """Résout l'IP via une API gratuite (ip-api.com)."""
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if res.get("status") == "success":
                info = f"🌍 Serveur : {res['country']}, {res['city']} | 🏢 ASN: {res['isp']}"
                self.geoip_label.configure(text=info)
                self.log_to_console(f"[+] Localisation identifiée : {res['isp']} ({res['country']})")
            else:
                self.geoip_label.configure(text="🌍 Serveur : Localisation inconnue (IP Privée ?)")
        except:
            self.geoip_label.configure(text="🌍 Serveur : Erreur de résolution Geo-IP")

    def auto_detect_game(self):
        self.log_to_console("\n[*] Recherche de processus...")
        found = False
        for conn in psutil.net_connections(kind='udp'):
            if conn.status == 'NONE' and conn.raddr:
                try:
                    proc = psutil.Process(conn.pid)
                    if proc.name().lower() in self.target_executables:
                        self.ip_entry.delete(0, 'end'); self.ip_entry.insert(0, conn.raddr.ip)
                        self.port_entry.delete(0, 'end'); self.port_entry.insert(0, conn.raddr.port)
                        self.log_to_console(f"[+] Succès : {proc.name()} ({conn.raddr.ip}:{conn.raddr.port})")
                        threading.Thread(target=self.resolve_geoip, args=(conn.raddr.ip,), daemon=True).start()
                        found = True
                        break
                except: continue
        if not found: self.log_to_console("[-] Aucun jeu détecté.")

    def toggle_capture(self):
        if not self.capture_running:
            target_ip = self.ip_entry.get()
            target_port = self.port_entry.get()
            if not target_ip: return

            if self.prom_switch.get() == 1 and not self.prom_server_started:
                start_http_server(8000)
                self.prom_server_started = True
                self.log_to_console("[+] Serveur Prometheus démarré (localhost:8000/metrics)")

            self.start_btn.configure(text="⏹ Arrêter l'Analyse", fg_color="#dc2626")
            self.packet_timestamps = []; self.hardware_stats = []; self.raw_packets = []; self.deltas_ms = []
            self.capture_running = True
            for widget in self.graph_frame.winfo_children(): widget.destroy()

            self.select_tab("logs")
            self.log_to_console(f"\n[*] Capture démarrée sur {target_ip}:{target_port}...")
            
            # Si on a entré l'IP à la main, on met à jour la GeoIP
            threading.Thread(target=self.resolve_geoip, args=(target_ip,), daemon=True).start()
            threading.Thread(target=self.monitor_hardware, daemon=True).start()
            threading.Thread(target=self.network_sniffer, args=(target_ip, target_port), daemon=True).start()
        else:
            self.capture_running = False
            self.start_btn.configure(state="disabled", text="Calcul...")

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(UDP):
            self.packet_timestamps.append(time.time())
            if self.pcap_switch.get() == 1: self.raw_packets.append(packet)

    def network_sniffer(self, target_ip, target_port):
        bpf_filter = f"udp and host {target_ip} and port {target_port}"
        while self.capture_running:
            sniff(filter=bpf_filter, prn=self.process_packet, store=False, timeout=1)
        self.after(0, self.finalize_analysis)

    def monitor_hardware(self):
        psutil.cpu_percent(interval=None)
        net_io_start = psutil.net_io_counters()
        while self.capture_running:
            time.sleep(1)
            net_io_end = psutil.net_io_counters()
            dl_mbps = ((net_io_end.bytes_recv - net_io_start.bytes_recv) * 8) / 1_000_000
            net_io_start = net_io_end
            cpu = psutil.cpu_percent(interval=None)
            self.hardware_stats.append((time.time(), cpu, dl_mbps))
            
            # Mise à jour de Prometheus en temps réel
            if self.prom_server_started:
                self.prom_cpu.set(cpu)

    def finalize_analysis(self):
        self.start_btn.configure(state="normal", text="▶ Lancer l'Analyse", fg_color="#16a34a")
        if len(self.packet_timestamps) < 5: return
        self.calculate_metrics()
        self.generate_embedded_graph()
        self.export_md_btn.configure(state="normal")
        self.export_csv_btn.configure(state="normal")
        if self.pcap_switch.get() == 1: self.export_pcap()
        self.select_tab("dash") # Bascule sur le tableau de bord à la fin

    def calculate_metrics(self):
        self.deltas_ms = [(self.packet_timestamps[i] - self.packet_timestamps[i-1]) * 1000 for i in range(1, len(self.packet_timestamps))]
        jitter_ms = sum([abs(self.deltas_ms[i] - self.deltas_ms[i-1]) for i in range(1, len(self.deltas_ms))]) / (len(self.deltas_ms) - 1)

        median_delta = statistics.median(self.deltas_ms)
        tickrate = 1000 / median_delta if median_delta > 0 else 0
        
        packet_loss_count = sum(1 for d in self.deltas_ms if d > median_delta * 1.5)
        loss_percentage = (packet_loss_count / len(self.packet_timestamps)) * 100

        # Envoi des résultats finaux à Prometheus
        if self.prom_server_started:
            self.prom_tickrate.set(tickrate)
            self.prom_jitter.set(jitter_ms)
            self.prom_packet_loss.set(loss_percentage)

        self.last_metrics = {"ip": self.ip_entry.get(), "port": self.port_entry.get(), "tickrate": tickrate, "jitter": jitter_ms, "loss_pct": loss_percentage}

    def generate_embedded_graph(self):
        start_time = self.packet_timestamps[0]
        net_x = [t - start_time for t in self.packet_timestamps[1:]]
        
        plt.style.use('dark_background')
        fig = plt.figure(figsize=(10, 5))
        fig.patch.set_facecolor('#2b2b2b')
        gs = fig.add_gridspec(1, 2, width_ratios=[2, 1])
        
        ax1 = fig.add_subplot(gs[0, 0])
        ax1.plot(net_x, self.deltas_ms, color='#ef4444', linewidth=1)
        ax1.set_title("Stabilité du Tickrate", color='white')
        
        ax2 = fig.add_subplot(gs[0, 1])
        ax2.hist(self.deltas_ms, bins=30, color='#8b5cf6')
        ax2.set_title("Histogramme Jitter", color='white')

        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def export_pcap(self): pass # Resté identique au précédent
    def export_markdown(self): pass # Resté identique au précédent
    def export_csv(self): pass # Resté identique au précédent

if __name__ == "__main__":
    app = SnifferApp()
    app.mainloop()