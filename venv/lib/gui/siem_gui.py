import tkinter as tk
from tkinter import filedialog, messagebox
from modules.PcapAnalyzer.payload_scanner import scan_payloads
from modules.PcapAnalyzer.connection_analyzer import detect_heavy_senders
from modules.PcapAnalyzer.flow_extractor import extract_flow

from AiEngine.model_predictor import predict_flow_df
from modules.logger.log_manager import log_anomaly
from FireWallUpdate.rule_generator import generate_rule
from FireWallUpdate.fw_interface import apply_rule

import os
import threading
import tempfile
import pyshark
import asyncio


class SIEMGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SIEM-Sec-Guardian")

        self.interface_var = tk.StringVar(value="en0")  # macOS default interface
        tk.Label(root, text="Network Interface (for live capture):").pack()
        tk.Entry(root, textvariable=self.interface_var).pack()

        self.live_button = tk.Button(root, text="📡 Analyze Live Capture", command=self.analyze_live)
        self.live_button.pack(pady=5)
        self.file_button = tk.Button(root, text="📂 Analyze PCAP File", command=self.choose_pcap)
        self.file_button.pack(pady=5)

        self.status_label = tk.Label(root, text="", fg="blue")
        self.status_label.pack()

    def analyze_live(self):
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Error", "Interface must not be empty")
            return
        self._toggle_buttons(state="disabled")
        self.status_label.config(text=f"Capturing on {interface}...")
        threading.Thread(target=self._live_capture, args=(interface,), daemon=True).start()

    def choose_pcap(self):
        filepath = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if filepath:
            self._toggle_buttons(state="disabled")
            self.status_label.config(text=f"Analyzing {filepath}...")
            threading.Thread(target=self.perform_analysis, args=(filepath,), daemon=True).start()

    def _live_capture(self, interface):
        # Create and set a new event loop for this thread
        asyncio.set_event_loop(asyncio.new_event_loop())

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            temp_path = tmp.name
        try:
            capture = pyshark.LiveCapture(interface=interface, output_file=temp_path)
            capture.sniff(timeout=10)  # blocking call, don't wrap with run_until_complete
            capture.close()
            self.perform_analysis(temp_path)
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Capture Error", str(e)))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            self.root.after(0, lambda: self._toggle_buttons(state="normal"))

    def perform_analysis(self, pcap_path):
        # Create and set new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            flow_df = extract_flow(pcap_path)
            payload_alerts = scan_payloads(pcap_path)
            conn_alerts = detect_heavy_senders(pcap_path)
            ai_alerts = predict_flow_df(flow_df)  # This might call async internally

            alerts = ai_alerts + payload_alerts + conn_alerts
            if not alerts:
                self.root.after(0, lambda: self.status_label.config(text="✅ No threats detected."))
                return

            log_anomaly(alerts)
            rules = generate_rule(alerts)
            for rule in rules:
                apply_rule(rule)

            self.root.after(0, lambda: self.status_label.config(
                text=f"⚠️ Detected and responded to {len(alerts)} threats."
            ))
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Analysis Error", str(e)))
        finally:
            self.root.after(0, lambda: self._toggle_buttons(state="normal"))
            # Close the loop explicitly if needed
            loop.close()

    def _toggle_buttons(self, state):
        self.live_button.config(state=state)
        self.file_button.config(state=state)
