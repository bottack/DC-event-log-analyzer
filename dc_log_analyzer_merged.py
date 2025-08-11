#!/usr/bin/env python3
"""
dc_log_analyzer_merged.py
=========================

This single Python module combines the functionality of the original
``dc_log_analyzer.py`` (command‑line tool) and ``dc_log_analyzer_gui.py``
into one file.  It exposes the same detection functions for analysing
Windows domain controller event logs and adds an optional graphical user
interface (GUI).  When run with the ``--gui`` flag, the Tkinter GUI is
launched; otherwise, the command‑line interface (CLI) behaves exactly
like the standalone analyzer.

The core detection logic focuses on a handful of high‑value Windows
event IDs:

* **Kerberoasting (4769)** – RC4‑HMAC TGS requests (0x17) issued by
  non‑machine accounts can indicate attempts to dump service account
  hashes【205783421775050†L190-L218】.
* **Brute force/Password spray (4625)** – repeated failed logons from the
  same IP within a short time window are a hallmark of password
  guessing attacks【985813946893414†L28-L31】.
* **Privileged logons (4672)** – logons granted sensitive privileges such
  as ``SeDebugPrivilege`` may reveal lateral movement attempts
  【268805509240126†L169-L181】.
* **Account creation (4720)** – new user accounts can be legitimate or
  used for persistence.
* **TGT anomalies (4768)** – encryption types other than AES (0x11 or
  0x12) on Ticket‑Granting Ticket requests warrant scrutiny
  【800595494679302†L860-L863】.
* **Group enumerations (4798/4799)** – enumeration of local or
  security‑enabled group membership is often used during reconnaissance
  【931580698648778†L24-L35】【868449646569748†L176-L183】【868449646569748†L319-L327】.

The GUI portion lets users select a log file, an optional config file
(YAML or JSON) and a list of known bad IP addresses, choose which
detections to run, and view the results in a green‑on‑black "hacker"
style window.  The CLI accepts similar flags and prints concise
tabular reports.

This module is designed to be self‑contained: it does not rely on
another ``dc_log_analyzer`` file.  Optional dependencies for EVTX
support (``python-evtx`` and ``xmltodict``) are handled gracefully.  If
those packages are absent and the user attempts to analyze an ``.evtx``
file, a clear runtime error is raised instructing them to install the
missing packages.

Usage examples:

```
# CLI mode (default): analyse logs.csv for kerberoasting and brute force
python dc_log_analyzer_merged.py --file logs.csv --kerberoast --brute

# Launch GUI mode
python dc_log_analyzer_merged.py --gui

# CLI with config and IP enrichment
python dc_log_analyzer_merged.py --file logs.csv --tgt --enumerations \
    --config settings.yaml --enrich-ip-file bad_ips.txt
```

"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import pandas as pd

# Optional YAML support
try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # yaml parsing will be unavailable

# Optional EVTX support.  These imports may fail if the packages are not
# installed.  In that case, _EVTX_OK remains False and .evtx files
# cannot be parsed.
try:
    from Evtx.Evtx import Evtx  # type: ignore
    import xmltodict  # type: ignore
    _EVTX_OK = True
except Exception:
    _EVTX_OK = False

# ---------------------------------------------------------------------------
# Timestamp parsing

def parse_timestamp(value: str) -> datetime:
    """Convert a timestamp string into a `datetime` object.

    Windows event log exports can contain fractional seconds and vary in
    date format.  This function tries a handful of common patterns and
    falls back to ``pandas.to_datetime`` for robustness.

    Args:
        value: The timestamp string from the log file.

    Returns:
        A `datetime` object.
    """
    # Patterns to try explicitly before falling back.  Add more if your
    # environment uses other formats.
    patterns = [
        "%Y-%m-%d %H:%M:%S.%f",  # e.g. 2025-08-07 15:32:11.123
        "%Y-%m-%d %H:%M:%S",     # e.g. 2025-08-07 15:32:11
        "%m/%d/%Y %I:%M:%S %p",  # e.g. 8/7/2025 3:32:11 PM
    ]
    for pattern in patterns:
        try:
            return datetime.strptime(value, pattern)
        except ValueError:
            continue
    # Fall back to pandas for anything else
    return pd.to_datetime(value).to_pydatetime()

# ---------------------------------------------------------------------------
# EVTX parsing helpers

def _flatten_eventdata(evt_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the EventData section of an EVTX event into key/value pairs.

    ``xmltodict`` converts EventData into a nested structure where each
    Data node is either a dict with ``@Name`` and ``#text`` keys or a
    list of such dicts.  This helper extracts those into a flat dict
    mapping names to values.

    Args:
        evt_dict: Parsed XML dictionary for a single event.

    Returns:
        A flat dictionary of EventData name/value pairs.
    """
    out: Dict[str, Any] = {}
    data = evt_dict.get("Event", {}).get("EventData", {}).get("Data")
    if isinstance(data, list):
        for item in data:
            name = item.get("@Name")
            val = item.get("#text")
            if name:
                out[name] = val
    elif isinstance(data, dict):
        name = data.get("@Name")
        val = data.get("#text")
        if name:
            out[name] = val
    return out


def load_evtx(path: str) -> pd.DataFrame:
    """Load events from an EVTX file into a DataFrame.

    This function requires the optional ``python-evtx`` and ``xmltodict``
    packages.  If they are missing, a ``RuntimeError`` is raised.  The
    resulting DataFrame normalizes common fields used by the detection
    functions: timestamp, eventid, accountname, ipaddress, etc.

    Args:
        path: Path to the ``.evtx`` file.

    Returns:
        A pandas DataFrame containing the parsed events.

    Raises:
        RuntimeError: If EVTX parsing dependencies are missing.
    """
    if not _EVTX_OK:
        raise RuntimeError(
            "EVTX support requires the 'python-evtx' and 'xmltodict' packages. "
            "Install them with `pip install python-evtx xmltodict` and try again."
        )
    records = []
    with Evtx(path) as evtx:
        for record in evtx.records():
            xml = record.xml()
            evt = xmltodict.parse(xml)
            sys_part = evt.get("Event", {}).get("System", {})
            # EventID may be nested dict or simple string
            event_id_obj = sys_part.get("EventID")
            if isinstance(event_id_obj, dict):
                event_id = event_id_obj.get("#text") or event_id_obj.get("@Qualifiers")
            else:
                event_id = event_id_obj
            try:
                event_id_int = int(event_id)
            except Exception:
                continue  # skip unknown events
            tc = sys_part.get("TimeCreated", {})
            ts = tc.get("@SystemTime")
            row: Dict[str, Any] = {
                "eventid": event_id_int,
                "timecreated": ts,
                "computer": sys_part.get("Computer"),
                "channel": sys_part.get("Channel"),
                "recordid": sys_part.get("EventRecordID"),
            }
            row.update(_flatten_eventdata(evt))
            records.append(row)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    # Normalize column names to lower case for ease of use
    df.columns = [c.lower() for c in df.columns]
    # Attempt to consolidate common fields used by detectors
    field_map = [
        ("ipaddress", "ipaddress"),
        ("clientaddress", "ipaddress"),
        ("sourceip", "ipaddress"),
        ("ip", "ipaddress"),
        ("targetusername", "accountname"),
        ("accountname", "accountname"),
        ("ticketencryptiontype", "ticketencryptiontype"),
        ("privileges", "privilegelist"),
    ]
    for src, dest in field_map:
        if src in df.columns and dest not in df.columns:
            df[dest] = df[src]
    # Choose a timestamp column and convert
    ts_col = None
    for cand in ("timecreated", "@timestamp", "timestamp", "created", "eventtime"):
        if cand in df.columns:
            ts_col = cand
            break
    if ts_col is None:
        raise ValueError("No parseable timestamp column found in EVTX file")
    df["timestamp"] = pd.to_datetime(df[ts_col], errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    df["eventid"] = pd.to_numeric(df["eventid"], errors="coerce")
    df = df.dropna(subset=["eventid"]).copy()
    df["eventid"] = df["eventid"].astype(int)
    return df

# ---------------------------------------------------------------------------
# Generic log loader

def load_logs(file_path: str) -> pd.DataFrame:
    """Load event logs from CSV, JSON or EVTX into a pandas DataFrame.

    Args:
        file_path: Path to the log file.  Supported extensions are
            ``.csv``, ``.tsv``, ``.json`` and ``.evtx`` (EVTX requires optional
            packages).

    Returns:
        A DataFrame with normalized column names (lowercase) and a
        ``timestamp`` column of type ``datetime``.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".evtx":
        return load_evtx(file_path)
    if ext in {".csv", ".tsv"}:
        # Use python engine for robust parsing; on_bad_lines='skip' to ignore
        df = pd.read_csv(file_path, engine="python")
    elif ext == ".json":
        # Try reading as NDJSON (one JSON object per line) first
        try:
            df = pd.read_json(file_path, lines=True)
        except ValueError:
            df = pd.read_json(file_path)
    else:
        raise ValueError("Unsupported file type. Provide CSV, JSON or EVTX.")
    # Normalize column names to lower case
    df.columns = [c.lower() for c in df.columns]
    # Map possible timestamp columns to 'timestamp'
    time_col = None
    for candidate in ["timecreated", "timestamp", "time", "created", "@timestamp"]:
        if candidate in df.columns:
            time_col = candidate
            break
    if time_col is None:
        raise ValueError(
            "No recognizable timestamp column found. "
            "Expected one of: timecreated, timestamp, time, created, @timestamp."
        )
    df["timestamp"] = df[time_col].apply(
        lambda x: parse_timestamp(str(x)) if pd.notnull(x) else pd.NaT
    )
    df = df.dropna(subset=["timestamp"]).copy()
    # Convert eventid to numeric
    if "eventid" not in df.columns:
        raise ValueError("EventID column not found in the log file.")
    df["eventid"] = pd.to_numeric(df["eventid"], errors="coerce")
    df = df.dropna(subset=["eventid"]).copy()
    df["eventid"] = df["eventid"].astype(int)
    return df

# ---------------------------------------------------------------------------
# Configuration and enrichment

def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load detection configuration from YAML or JSON.

    Allows overriding thresholds, allowed encryption types, and other
    parameters without modifying the code.  If ``config_path`` is None,
    returns an empty dict.  If the file does not exist or parsing fails,
    appropriate errors are raised.
    """
    cfg: Dict[str, Any] = {}
    if not config_path:
        return cfg
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    ext = os.path.splitext(config_path)[1].lower()
    with open(config_path, "r", encoding="utf-8") as fh:
        if ext in {".yaml", ".yml"}:
            if yaml is None:
                raise ImportError(
                    "PyYAML is required for YAML config files. Install it with `pip install PyYAML`."
                )
            cfg = yaml.safe_load(fh) or {}
        else:
            cfg = json.load(fh)
    if not isinstance(cfg, dict):
        raise ValueError("Configuration file must define a JSON/YAML object at the top level.")
    return cfg


def enrich_with_bad_ips(df: pd.DataFrame, ip_file: Optional[str]) -> pd.DataFrame:
    """Mark events whose IP addresses appear in a known bad list.

    Adds a boolean ``known_bad_ip`` column to the DataFrame.  If
    ``ip_file`` is None or the file cannot be found, returns the
    original DataFrame with ``known_bad_ip`` set to False for all
    rows.  Lines beginning with ``#`` or blank lines are ignored.

    Args:
        df: Event log DataFrame.
        ip_file: Path to a newline‑delimited list of IP addresses.

    Returns:
        The DataFrame with an additional ``known_bad_ip`` column.
    """
    df = df.copy()
    df["known_bad_ip"] = False
    if not ip_file:
        return df
    if not os.path.isfile(ip_file):
        raise FileNotFoundError(f"Known bad IP file not found: {ip_file}")
    with open(ip_file, "r", encoding="utf-8") as f:
        bad_ips = {line.strip() for line in f if line.strip() and not line.startswith("#")}
    ip_col = None
    for candidate in ["ipaddress", "sourceip", "ip", "clientaddress"]:
        if candidate in df.columns:
            ip_col = candidate
            break
    if ip_col is None:
        # If no IP column, enrichment has no effect
        return df
    df["known_bad_ip"] = df[ip_col].astype(str).isin(bad_ips)
    return df

# ---------------------------------------------------------------------------
# Detection functions

def detect_kerberoasting(df: pd.DataFrame) -> pd.DataFrame:
    """Detect potential kerberoasting (event 4769, RC4, non‑machine accounts).

    Filters for event ID 4769 and returns rows where the
    ``ticketencryptiontype`` is ``0x17`` (RC4‑HMAC) and the
    ``accountname`` does not end with ``$``.  If either column is
    missing, returns an empty DataFrame.
    """
    subset = df[df["eventid"] == 4769].copy()
    if "ticketencryptiontype" not in subset.columns:
        return pd.DataFrame(columns=subset.columns)
    if "accountname" not in subset.columns:
        return pd.DataFrame(columns=subset.columns)
    subset["ticketencryptiontype"] = subset["ticketencryptiontype"].astype(str).str.lower()
    subset["accountname"] = subset["accountname"].astype(str)
    suspicious = subset[(subset["ticketencryptiontype"] == "0x17") & (~subset["accountname"].str.endswith("$"))]
    return suspicious


def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 5,
    source_ip_field: str = "ipaddress",
) -> pd.DataFrame:
    """Identify potential brute force or password spraying attacks (event 4625).

    Groups failed logon events (4625) by source IP and flags any IP that
    produces at least ``threshold`` failures within ``window_minutes``.  The
    first detected window for each IP is returned.  If no IP address
    column can be determined, returns an empty DataFrame.

    Args:
        df: Event log DataFrame.
        threshold: Minimum number of failures within the window to
            constitute a brute force attack.
        window_minutes: Size of the sliding time window in minutes.
        source_ip_field: Preferred column name for source IPs.  If the
            DataFrame doesn't contain this column, fall back to other
            plausible names.

    Returns:
        DataFrame containing the suspicious events for each offending IP.
    """
    failures = df[df["eventid"] == 4625].copy()
    # Determine IP column
    ip_col = None
    for candidate in [source_ip_field.lower(), "sourceip", "ipaddress", "ip", "clientaddress"]:
        if candidate in failures.columns:
            ip_col = candidate
            break
    if ip_col is None:
        return pd.DataFrame(columns=failures.columns)
    failures = failures.dropna(subset=[ip_col]).sort_values("timestamp")
    suspicious_records: List[pd.DataFrame] = []
    for ip, group in failures.groupby(ip_col):
        times = group["timestamp"].tolist()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > timedelta(minutes=window_minutes):
                start += 1
            if end - start + 1 >= threshold:
                suspicious_records.append(group.iloc[start : end + 1])
                break  # One detection per IP
    if not suspicious_records:
        return pd.DataFrame(columns=failures.columns)
    return pd.concat(suspicious_records, ignore_index=True)


def detect_privileged_logon(df: pd.DataFrame) -> pd.DataFrame:
    """Return events for privileged logons (event 4672)."""
    return df[df["eventid"] == 4672].copy()


def detect_account_creation(df: pd.DataFrame) -> pd.DataFrame:
    """Return events for new account creation (event 4720)."""
    return df[df["eventid"] == 4720].copy()


def detect_tgt_anomalies(
    df: pd.DataFrame,
    allowed_encryptions: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Detect suspicious Ticket‑Granting Ticket requests (event 4768).

    Event ID 4768 corresponds to TGT requests.  Microsoft recommends
    monitoring for encryption types other than AES (0x11, 0x12)【800595494679302†L860-L863】.
    This function returns 4768 events whose ``ticketencryptiontype`` is
    *not* in ``allowed_encryptions``.  If the column is missing,
    returns an empty DataFrame.
    """
    subset = df[df["eventid"] == 4768].copy()
    if "ticketencryptiontype" not in subset.columns:
        return pd.DataFrame(columns=subset.columns)
    subset["ticketencryptiontype"] = subset["ticketencryptiontype"].astype(str).str.lower()
    if not allowed_encryptions:
        allowed_encryptions = ["0x11", "0x12"]
    allowed_lower = [e.lower() for e in allowed_encryptions]
    suspicious = subset[~subset["ticketencryptiontype"].isin(allowed_lower)]
    return suspicious


def detect_group_enumeration(df: pd.DataFrame) -> pd.DataFrame:
    """Return events for user local group membership enumeration (event 4798)."""
    return df[df["eventid"] == 4798].copy()


def detect_security_group_enumeration(df: pd.DataFrame) -> pd.DataFrame:
    """Return events for security‑enabled group membership enumeration (event 4799)."""
    return df[df["eventid"] == 4799].copy()

# ---------------------------------------------------------------------------
# Utility: print report for CLI

def print_report(title: str, events: pd.DataFrame, max_rows: Optional[int] = 10) -> None:
    """Print a concise table of detected events.

    Args:
        title: The section header to print.
        events: DataFrame of events to display.
        max_rows: Maximum number of rows to print.  If ``None``, print all.
    """
    print(f"\n=== {title} ===")
    if events.empty:
        print("No events detected.")
    else:
        print(events.head(max_rows).to_string(index=False))
        if max_rows is not None and len(events) > max_rows:
            print(f"... ({len(events) - max_rows} more) ...")

# ---------------------------------------------------------------------------
# Graphical User Interface

class AnalyzerGUI:
    """Tkinter GUI for the DC Log Analyzer.

    Presents file selectors, detection option checkboxes, and a scrollable
    output pane in a green‑on‑black aesthetic.  Analysis runs on a
    background thread to prevent the UI from freezing.  Results are
    truncated to at most 200 rows per section to keep the interface
    responsive.
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("DC Log Analyzer")
        # Apply hacker-style colour scheme
        self.root.configure(bg="black")

        # File and option variables
        self.log_path_var = tk.StringVar()
        self.config_path_var = tk.StringVar()
        self.ip_path_var = tk.StringVar()
        self.opt_kerberoast = tk.BooleanVar(value=False)
        self.opt_brute = tk.BooleanVar(value=False)
        self.opt_priv = tk.BooleanVar(value=False)
        self.opt_accounts = tk.BooleanVar(value=False)
        self.opt_tgt = tk.BooleanVar(value=False)
        self.opt_enumerations = tk.BooleanVar(value=False)

        # Build UI components
        self._build_file_selectors()
        self._build_options()
        self._build_output_area()
        self._build_run_button()

    # UI construction helpers
    def _build_file_selectors(self) -> None:
        # Log file selector
        frame_log = tk.Frame(self.root, bg="black")
        frame_log.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(frame_log, text="Log file:", fg="green", bg="black").pack(side=tk.LEFT)
        tk.Entry(frame_log, textvariable=self.log_path_var, fg="green", bg="black", insertbackground="green", width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_log, text="Browse", command=self._browse_log, fg="green", bg="black", activebackground="#003300", activeforeground="green").pack(side=tk.LEFT)
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
        opts_frame = tk.Frame(self.root, bg="black")
        opts_frame.pack(fill=tk.X, padx=5, pady=4)
        tk.Label(opts_frame, text="Detections:", fg="green", bg="black").pack(anchor=tk.W)
        # Define a helper to create checkbuttons consistently
        def add_check(text: str, var: tk.BooleanVar) -> None:
            tk.Checkbutton(
                opts_frame,
                text=text,
                variable=var,
                fg="green",
                bg="black",
                activebackground="#003300",
                selectcolor="#002200",
            ).pack(anchor=tk.W)
        add_check("Kerberoasting (4769)", self.opt_kerberoast)
        add_check("Brute force / spray (4625)", self.opt_brute)
        add_check("Privileged logons (4672)", self.opt_priv)
        add_check("Account creation (4720)", self.opt_accounts)
        add_check("TGT anomalies (4768)", self.opt_tgt)
        add_check("Group enumerations (4798/4799)", self.opt_enumerations)

    def _build_output_area(self) -> None:
        # Use scrolledtext for output, with monospace font if available
        self.output = scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            fg="green",
            bg="black",
            insertbackground="green",
            width=100,
            height=25,
        )
        try:
            self.output.configure(font=("Courier New", 10))
        except Exception:
            pass
        self.output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _build_run_button(self) -> None:
        btn_frame = tk.Frame(self.root, bg="black")
        btn_frame.pack(fill=tk.X, padx=5, pady=4)
        self.run_btn = tk.Button(
            btn_frame,
            text="Run Analysis",
            command=self._run_analysis_threaded,
            fg="green",
            bg="black",
            activebackground="#003300",
            activeforeground="green",
        )
        self.run_btn.pack()

    # File dialogs
    def _browse_log(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select log file",
            filetypes=[
                ("EVTX files", "*.evtx"),
                ("CSV files", "*.csv *.tsv"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self.log_path_var.set(file_path)

    def _browse_config(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select config file",
            filetypes=[
                ("YAML files", "*.yml *.yaml"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self.config_path_var.set(file_path)

    def _browse_ip(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select IP file",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self.ip_path_var.set(file_path)

    # Output helper (runs on UI thread)
    def _append_output(self, text: str) -> None:
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    # Analysis orchestration
    def _run_analysis_threaded(self) -> None:
        # Launch analysis in a background thread to avoid freezing the UI
        if not self.log_path_var.get().strip():
            messagebox.showerror("Missing file", "Please select a log file.")
            return
        # Disable run button
        self.run_btn.config(state="disabled")
        # Clear previous output
        self.output.delete("1.0", tk.END)
        self._append_output("[*] Starting analysis...")
        thread = threading.Thread(target=self._perform_analysis, daemon=True)
        thread.start()

    def _perform_analysis(self) -> None:
        try:
            self._do_analysis()
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc)))
        finally:
            # Re‑enable run button on completion
            self.root.after(0, lambda: self.run_btn.config(state="normal"))

    def _do_analysis(self) -> None:
        log_path = self.log_path_var.get().strip()
        # Load logs
        try:
            df = load_logs(log_path)
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Error loading logs", str(exc)))
            return
        # Load config
        cfg: Dict[str, Any] = {}
        config_path = self.config_path_var.get().strip()
        if config_path:
            try:
                cfg = load_config(config_path)
            except Exception as exc:
                self.root.after(0, lambda: messagebox.showerror("Error loading config", str(exc)))
                return
        # Enrich with bad IPs
        ip_path = self.ip_path_var.get().strip()
        if ip_path:
            try:
                df = enrich_with_bad_ips(df, ip_path)
            except Exception as exc:
                self.root.after(0, lambda: messagebox.showerror("Error enriching IPs", str(exc)))
                return
        # Determine brute force params from config
        brute_cfg = cfg.get("brute_force", {}) if isinstance(cfg, dict) else {}
        brute_threshold = brute_cfg.get("threshold", 5)
        brute_window = brute_cfg.get("window_minutes", 5)
        # Allowed encryptions for TGT anomalies
        tgt_cfg = cfg.get("tgt_anomalies", {}) if isinstance(cfg, dict) else {}
        allowed_enc = tgt_cfg.get("allowed_encryptions", ["0x11", "0x12"])
        # Begin reporting
        # Use root.after to append output on UI thread
        def out(section: str, events: pd.DataFrame) -> None:
            self.root.after(0, lambda: self._append_output(section))
            if events.empty:
                self.root.after(0, lambda: self._append_output("No events detected."))
            else:
                # Limit to first 200 rows to keep UI responsive
                txt = events.head(200).to_string(index=False)
                self.root.after(0, lambda: self._append_output(txt))
        # Run selected detections
        if self.opt_kerberoast.get():
            out("=== Kerberoasting Events ===", detect_kerberoasting(df))
        if self.opt_brute.get():
            out(
                "=== Brute Force/Password Spray Events ===",
                detect_brute_force(df, threshold=int(brute_threshold), window_minutes=int(brute_window)),
            )
        if self.opt_priv.get():
            out("=== Privileged Logon Events ===", detect_privileged_logon(df))
        if self.opt_accounts.get():
            out("=== Account Creation Events ===", detect_account_creation(df))
        if self.opt_tgt.get():
            out(
                "=== Suspicious TGT Requests ===",
                detect_tgt_anomalies(df, allowed_encryptions=allowed_enc),
            )
        if self.opt_enumerations.get():
            out("=== User Group Enumeration Events (4798) ===", detect_group_enumeration(df))
            out("=== Security Group Enumeration Events (4799) ===", detect_security_group_enumeration(df))

# ---------------------------------------------------------------------------
# Command‑line interface

def run_cli(argv: Optional[List[str]] = None) -> None:
    """Entry point for the command‑line interface.

    Parses arguments, loads data, applies enrichment and configuration,
    runs the requested detections, and prints reports to stdout.
    """
    parser = argparse.ArgumentParser(
        description="Analyze Windows DC event logs for suspicious activity.",
        epilog="Use --gui to launch the graphical interface."
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the log file (CSV/JSON/EVTX) to analyse.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the GUI instead of running in the terminal.",
    )
    parser.add_argument("--kerberoast", action="store_true", help="Detect kerberoasting (event 4769).")
    parser.add_argument("--brute", action="store_true", help="Detect brute force/password spraying (event 4625).")
    parser.add_argument("--priv", action="store_true", help="List privileged logon events (event 4672).")
    parser.add_argument("--accounts", action="store_true", help="List new account creation events (event 4720).")
    parser.add_argument("--tgt", action="store_true", help="Detect suspicious TGT requests (event 4768).")
    parser.add_argument("--enumerations", action="store_true", help="List group enumeration events (4798/4799).")
    parser.add_argument("--threshold", type=int, default=None, help="Brute force threshold override.")
    parser.add_argument("--window", type=int, default=None, help="Brute force window (minutes) override.")
    parser.add_argument("--config", help="Path to YAML or JSON config file.")
    parser.add_argument("--enrich-ip-file", dest="enrich_ip_file", help="Path to known bad IP list for enrichment.")
    args = parser.parse_args(argv)
    # If GUI flag is set, launch the GUI and exit
    if args.gui:
        # Remove '--gui' from sys.argv to avoid confusion with argparse in GUI
        # but we simply launch GUI here; CLI flags will be ignored
        root = tk.Tk()
        gui = AnalyzerGUI(root)
        root.mainloop()
        return
    # Otherwise, run CLI detection
    df = load_logs(args.file)
    df = enrich_with_bad_ips(df, args.enrich_ip_file)
    config = load_config(args.config)
    brute_threshold = args.threshold if args.threshold is not None else config.get('brute_force', {}).get('threshold', 5)
    brute_window = args.window if args.window is not None else config.get('brute_force', {}).get('window_minutes', 5)
    any_requested = False
    if args.kerberoast:
        any_requested = True
        events = detect_kerberoasting(df)
        print_report("Kerberoasting Events", events)
    if args.brute:
        any_requested = True
        events = detect_brute_force(df, threshold=int(brute_threshold), window_minutes=int(brute_window))
        print_report("Brute Force/Password Spray Events", events)
    if args.priv:
        any_requested = True
        events = detect_privileged_logon(df)
        print_report("Privileged Logon Events", events)
    if args.accounts:
        any_requested = True
        events = detect_account_creation(df)
        print_report("Account Creation Events", events)
    if args.tgt:
        any_requested = True
        allowed_enc = config.get('tgt_anomalies', {}).get('allowed_encryptions', ['0x11', '0x12'])
        events = detect_tgt_anomalies(df, allowed_encryptions=allowed_enc)
        print_report("Suspicious TGT Requests", events)
    if args.enumerations:
        any_requested = True
        enum1 = detect_group_enumeration(df)
        print_report("User Group Enumeration Events (4798)", enum1)
        enum2 = detect_security_group_enumeration(df)
        print_report("Security Group Enumeration Events (4799)", enum2)
    if not any_requested:
        parser.error(
            "No detection type specified. Use one or more of --kerberoast, --brute, --priv, --accounts, --tgt, or --enumerations, or use --gui to launch the graphical interface."
        )


def main() -> None:
    """Entry point of the script."""
    run_cli()


if __name__ == "__main__":
    main()