#!/usr/bin/env python3
"""
Basic GUI wrapper for the dc_log_analyzer tool.

This script provides a minimal Tkinter-based graphical interface for
analyzing Windows domain controller event logs.  Users can select a
log file, optional configuration file, and optional known-bad IP file,
then choose which detection modules to run via checkboxes.  Results
are displayed in a scrollable text area using a green-on-black
"hacker terminal" aesthetic.

Usage:

    python dc_log_analyzer_gui.py

The GUI requires Tkinter (included with standard Python installs).
It imports and uses functions from `dc_log_analyzer.py` located in
the same directory.  Make sure that file is present and accessible.
"""

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import pandas as pd  # Required for DataFrame to_string

# Ensure the dc_log_analyzer module can be imported
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

try:
    import dc_log_analyzer as dcla
except ImportError as exc:
    raise ImportError(
        "Could not import dc_log_analyzer module. Ensure dc_log_analyzer.py is in the same directory."
    ) from exc


class AnalyzerGUI:
    """GUI class encapsulating the Tkinter interface."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("DC Log Analyzer")
        # Apply hacker-style aesthetics: green text on black background
        self.root.configure(bg="black")

        # Variables for file paths and detection options
        self.log_path_var = tk.StringVar()
        self.config_path_var = tk.StringVar()
        self.ip_path_var = tk.StringVar()
        self.opt_kerberoast = tk.BooleanVar(value=False)
        self.opt_brute = tk.BooleanVar(value=False)
        self.opt_priv = tk.BooleanVar(value=False)
        self.opt_accounts = tk.BooleanVar(value=False)
        self.opt_tgt = tk.BooleanVar(value=False)
        self.opt_enumerations = tk.BooleanVar(value=False)

        # Build the UI
        self._build_file_selectors()
        self._build_options()
        self._build_output_area()
        self._build_run_button()

    def _build_file_selectors(self) -> None:
        """Create file selector widgets."""
        # Log file selector
        frame = tk.Frame(self.root, bg="black")
        frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(frame, text="Log file:", fg="green", bg="black").pack(side=tk.LEFT)
        tk.Entry(frame, textvariable=self.log_path_var, fg="green", bg="black", insertbackground="green", width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Browse", command=self._browse_log, fg="green", bg="black", activebackground="#003300", activeforeground="green").pack(side=tk.LEFT)

        # Config file selector
        frame_cfg = tk.Frame(self.root, bg="black")
        frame_cfg.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(frame_cfg, text="Config file:", fg="green", bg="black").pack(side=tk.LEFT)
        tk.Entry(frame_cfg, textvariable=self.config_path_var, fg="green", bg="black", insertbackground="green", width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_cfg, text="Browse", command=self._browse_config, fg="green", bg="black", activebackground="#003300", activeforeground="green").pack(side=tk.LEFT)

        # Known bad IPs file selector
        frame_ip = tk.Frame(self.root, bg="black")
        frame_ip.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(frame_ip, text="Bad IP file:", fg="green", bg="black").pack(side=tk.LEFT)
        tk.Entry(frame_ip, textvariable=self.ip_path_var, fg="green", bg="black", insertbackground="green", width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_ip, text="Browse", command=self._browse_ip, fg="green", bg="black", activebackground="#003300", activeforeground="green").pack(side=tk.LEFT)

    def _build_options(self) -> None:
        """Create checkboxes for detection options."""
        opts_frame = tk.Frame(self.root, bg="black")
        opts_frame.pack(fill=tk.X, padx=5, pady=4)
        tk.Label(opts_frame, text="Detections:", fg="green", bg="black").pack(anchor=tk.W)

        # Each checkbox uses black background and green text
        tk.Checkbutton(opts_frame, text="Kerberoasting (4769)", variable=self.opt_kerberoast, fg="green", bg="black", activebackground="#003300", selectcolor="#002200").pack(anchor=tk.W)
        tk.Checkbutton(opts_frame, text="Brute force / spray (4625)", variable=self.opt_brute, fg="green", bg="black", activebackground="#003300", selectcolor="#002200").pack(anchor=tk.W)
        tk.Checkbutton(opts_frame, text="Privileged logons (4672)", variable=self.opt_priv, fg="green", bg="black", activebackground="#003300", selectcolor="#002200").pack(anchor=tk.W)
        tk.Checkbutton(opts_frame, text="Account creation (4720)", variable=self.opt_accounts, fg="green", bg="black", activebackground="#003300", selectcolor="#002200").pack(anchor=tk.W)
        tk.Checkbutton(opts_frame, text="TGT anomalies (4768)", variable=self.opt_tgt, fg="green", bg="black", activebackground="#003300", selectcolor="#002200").pack(anchor=tk.W)
        tk.Checkbutton(opts_frame, text="Group enumerations (4798/4799)", variable=self.opt_enumerations, fg="green", bg="black", activebackground="#003300", selectcolor="#002200").pack(anchor=tk.W)

    def _build_output_area(self) -> None:
        """Create scrolled text widget for output display."""
        self.output = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, fg="green", bg="black", insertbackground="green", width=100, height=25)
        self.output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _build_run_button(self) -> None:
        """Create the run analysis button."""
        btn_frame = tk.Frame(self.root, bg="black")
        btn_frame.pack(fill=tk.X, padx=5, pady=4)
        tk.Button(btn_frame, text="Run Analysis", command=self.run_analysis, fg="green", bg="black", activebackground="#003300", activeforeground="green").pack()

    def _browse_log(self) -> None:
        """Open file dialog to select the log file."""
        file_path = filedialog.askopenfilename(title="Select log file", filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            self.log_path_var.set(file_path)

    def _browse_config(self) -> None:
        """Open file dialog to select the config file."""
        file_path = filedialog.askopenfilename(title="Select config file", filetypes=[("YAML files", "*.yaml;*.yml"), ("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            self.config_path_var.set(file_path)

    def _browse_ip(self) -> None:
        """Open file dialog to select the known bad IP file."""
        file_path = filedialog.askopenfilename(title="Select IP file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.ip_path_var.set(file_path)

    def _append_output(self, text: str) -> None:
        """Append text to the output area with a newline."""
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def run_analysis(self) -> None:
        """Perform the selected analyses and display results."""
        log_path = self.log_path_var.get().strip()
        if not log_path:
            messagebox.showerror("Missing file", "Please select a log file.")
            return
        # Clear previous output
        self.output.delete('1.0', tk.END)
        self._append_output(f"Loading log file: {log_path}")
        try:
            df = dcla.load_logs(log_path)
        except Exception as exc:
            messagebox.showerror("Error loading logs", str(exc))
            return
        # Load config if provided
        config_path = self.config_path_var.get().strip()
        cfg = {}
        if config_path:
            self._append_output(f"Loading config: {config_path}")
            try:
                cfg = dcla.load_config(config_path)
            except Exception as exc:
                messagebox.showerror("Error loading config", str(exc))
                return
        # Enrich with bad IPs if provided
        ip_path = self.ip_path_var.get().strip()
        if ip_path:
            self._append_output(f"Enriching with bad IPs from: {ip_path}")
            try:
                df = dcla.enrich_with_bad_ips(df, ip_path)
            except Exception as exc:
                messagebox.showerror("Error enriching IPs", str(exc))
                return
        # Determine brute force threshold and window from config
        brute_threshold = cfg.get('brute_force', {}).get('threshold', 5)
        brute_window = cfg.get('brute_force', {}).get('window_minutes', 5)
        # Run selected detections
        if self.opt_kerberoast.get():
            self._append_output("=== Kerberoasting Events ===")
            events = dcla.detect_kerberoasting(df)
            if events.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events.to_string(index=False))
        if self.opt_brute.get():
            self._append_output("=== Brute Force/Password Spray Events ===")
            events = dcla.detect_brute_force(df, threshold=brute_threshold, window_minutes=brute_window)
            if events.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events.to_string(index=False))
        if self.opt_priv.get():
            self._append_output("=== Privileged Logon Events ===")
            events = dcla.detect_privileged_logon(df)
            if events.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events.to_string(index=False))
        if self.opt_accounts.get():
            self._append_output("=== Account Creation Events ===")
            events = dcla.detect_account_creation(df)
            if events.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events.to_string(index=False))
        if self.opt_tgt.get():
            self._append_output("=== Suspicious TGT Requests ===")
            allowed_enc = cfg.get('tgt_anomalies', {}).get('allowed_encryptions', ['0x11', '0x12'])
            events = dcla.detect_tgt_anomalies(df, allowed_encryptions=allowed_enc)
            if events.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events.to_string(index=False))
        if self.opt_enumerations.get():
            self._append_output("=== User Group Enumeration Events (4798) ===")
            events_4798 = dcla.detect_group_enumeration(df)
            if events_4798.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events_4798.to_string(index=False))
            self._append_output("=== Security Group Enumeration Events (4799) ===")
            events_4799 = dcla.detect_security_group_enumeration(df)
            if events_4799.empty:
                self._append_output("No events detected.")
            else:
                self._append_output(events_4799.to_string(index=False))


def main() -> None:
    root = tk.Tk()
    app = AnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()