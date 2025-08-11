# DC Log Analyzer – README

## Introduction

`dc_log_analyzer_merged.py` is a comprehensive tool for triaging Windows domain controller event logs for signs of compromise.  It integrates the functionality of a command-line analyzer and a Tkinter-based graphical interface (GUI) into a single script.  The tool can parse CSV, JSON, and EVTX log formats, enrich events with a list of known malicious IP addresses, and detect a variety of suspicious behaviours commonly associated with credential attacks, privilege escalation, and reconnaissance.

The script supports two modes of operation:

- **Command-line interface (CLI)** – invoked by default.  You specify the log file and one or more detection flags, and the results print to standard output.
- **Graphical user interface (GUI)** – invoked by passing `--gui`.  This opens a window where you can choose the log file, optional configuration and IP list, select detection modules via checkboxes, and view the results in a scrollable text area styled with green text on a black background.

## Dependencies

- Python 3.8 or newer
- `pandas` – required for data processing
- `PyYAML` (optional) – for YAML configuration files
- `python-evtx` and `xmltodict` (optional) – required to parse `.evtx` files directly.  If these libraries are not installed, EVTX analysis will not be available and an error message will be shown when attempting to load such files.
- Tkinter (bundled with standard Python) – required for the GUI

To install the optional dependencies, run:

```bash
pip install pandas PyYAML python-evtx xmltodict
```

## Running the Tool

The script can be run from the command line or as a GUI.

### CLI Usage

```bash
python dc_log_analyzer_merged.py --file <path> [options]
```

Options include:

| Argument                 | Description |
|---|---|
| `--file`                 | **Required.** Path to the log file (CSV/JSON/EVTX) to analyze. |
| `--gui`                  | Launch the graphical interface instead of running in the terminal. |
| `--kerberoast`           | Detect Kerberos service ticket requests using RC4 (0x17) by user accounts (event 4769). |
| `--brute`                | Detect brute force or password spraying by counting failed logons (event 4625). |
| `--priv`                 | List privileged logon events (event 4672). |
| `--accounts`             | List account creation events (event 4720). |
| `--tgt`                  | Detect Ticket‑Granting Ticket anomalies (event 4768). |
| `--enumerations`         | List group enumeration events (events 4798 and 4799). |
| `--threshold`            | Override the brute‑force detection threshold (number of failed logons). |
| `--window`               | Override the brute‑force time window in minutes. |
| `--config`               | Path to a YAML or JSON configuration file for custom settings. |
| `--enrich-ip-file`       | Path to a file containing known bad IP addresses (one per line) to enrich logs. |

If no detection flags are provided and `--gui` is not used, the script will display an error prompting you to select at least one detection or launch the GUI.

### GUI Usage

Launch the GUI with:

```bash
python dc_log_analyzer_merged.py --gui
```

The GUI allows you to:

1. **Choose Files** – Browse for a log file, an optional configuration file, and an optional file listing known bad IPs.
2. **Select Detections** – Check the boxes for the detections you wish to perform.
3. **Run Analysis** – Click **Run Analysis** to start.  The analysis runs in a background thread to keep the interface responsive.  Results are shown in the output pane, truncated to the first 200 rows per section.

## Configuration File

Configuration files (YAML or JSON) allow you to adjust detection parameters without editing the code.  The top-level keys correspond to detection names.  For example:

```yaml
brute_force:
  threshold: 8         # Require eight failed logons to trigger an alert
  window_minutes: 10   # Within a 10‑minute sliding window

tgt_anomalies:
  allowed_encryptions:
    - 0x11
    - 0x12
```

In the absence of a configuration file, defaults are used (e.g. 5 failures within 5 minutes for brute force, AES only for TGT).

## Function Reference

Below is a low‑level description of each function defined in the script.

### `parse_timestamp(value: str) -> datetime`

Attempts to parse a timestamp string into a Python `datetime` object using several common formats.  If all predefined patterns fail, it falls back to `pandas.to_datetime`.  This function normalises timestamps regardless of whether they come from CSV, JSON, or EVTX sources.

### `_flatten_eventdata(evt_dict: dict) -> dict`

A helper used when parsing EVTX files.  It extracts name/value pairs from the `EventData` section of an event, producing a flat dictionary.  Only used internally.

### `load_evtx(path: str) -> pd.DataFrame`

Parses an EVTX file using the optional `python-evtx` and `xmltodict` libraries.  It returns a DataFrame with common fields normalised (lower‑case column names) and attempts to map alternative column names to those expected by the detectors (`accountname`, `ipaddress`, `ticketencryptiontype`, etc.).  Timestamps and event IDs are converted to appropriate types.  If the required libraries are missing, it raises a `RuntimeError` instructing the user to install them.

### `load_logs(file_path: str) -> pd.DataFrame`

Loads a log file in CSV, TSV, JSON (either multi‑JSON or newline‑delimited JSON) or EVTX format.  For CSV/TSV, it uses pandas’ Python engine for robustness.  For JSON, it tries NDJSON first and then falls back to normal JSON.  It normalises column names to lower case, determines a timestamp column, parses timestamps via `parse_timestamp`, converts `eventid` to numeric, and drops rows with missing or invalid timestamps and event IDs.

### `load_config(config_path: Optional[str]) -> dict`

Reads a YAML or JSON configuration file into a dictionary.  YAML support requires `PyYAML`.  If no path is provided, it returns an empty dict.  Invalid formats raise informative exceptions.

### `enrich_with_bad_ips(df: pd.DataFrame, ip_file: Optional[str]) -> pd.DataFrame`

Adds a boolean column `known_bad_ip` to the DataFrame, marking rows whose IP address is listed in the provided IP file.  The function searches for the first matching IP column among `ipaddress`, `sourceip`, `ip`, or `clientaddress`.  If no IP column is found, enrichment is skipped.  Comment lines starting with `#` and empty lines in the IP file are ignored.

### `detect_kerberoasting(df: pd.DataFrame) -> pd.DataFrame`

Filters for event ID 4769 (Service Ticket Requested) and returns rows where `ticketencryptiontype` equals `0x17` (RC4‑HMAC) and `accountname` does not end with a `$` (machine accounts typically end in `$`).  These conditions align with common Kerberoasting tactics where attackers request RC4 tickets for user accounts so they can attempt offline password cracking【205783421775050†L190-L218】.

### `detect_brute_force(df: pd.DataFrame, threshold: int = 5, window_minutes: int = 5, source_ip_field: str = "ipaddress") -> pd.DataFrame`

Detects repeated failed logon attempts (Event ID 4625) from the same IP address within a sliding time window.  It groups failures by IP, sorts them by timestamp, and uses two indices to find the first window where at least `threshold` failures occur within `window_minutes`.  It returns the first matching window per offending IP.

### `detect_privileged_logon(df: pd.DataFrame) -> pd.DataFrame`

Returns all events with ID 4672, which are logged when a logon is granted sensitive privileges such as `SeDebugPrivilege`, `SeBackupPrivilege`, and `SeCreateTokenPrivilege`【268805509240126†L169-L181】.  These events are not necessarily malicious but warrant attention.

### `detect_account_creation(df: pd.DataFrame) -> pd.DataFrame`

Returns all events with ID 4720, indicating a new user account was created.  Unexpected account creation can signal persistence.

### `detect_tgt_anomalies(df: pd.DataFrame, allowed_encryptions: Optional[List[str]] = None) -> pd.DataFrame`

Filters event ID 4768 (Ticket‑Granting Ticket requests) and returns rows where `ticketencryptiontype` is **not** in the list of allowed encryption types.  By default, only AES types `0x11` and `0x12` are allowed.  Non‑AES types or unknown values may indicate misconfiguration or exploitation【800595494679302†L860-L863】.  If the column is missing, the function returns an empty DataFrame.

### `detect_group_enumeration(df: pd.DataFrame) -> pd.DataFrame`

Returns events with ID 4798, which are logged when a process enumerates the local groups to which a user belongs.  Attackers commonly perform group membership enumeration during reconnaissance【931580698648778†L24-L35】.

### `detect_security_group_enumeration(df: pd.DataFrame) -> pd.DataFrame`

Returns events with ID 4799, which are logged when a process enumerates the members of a security‑enabled local group【868449646569748†L176-L183】.  Monitoring these events for critical groups can help identify enumeration attempts【868449646569748†L319-L327】.

### `print_report(title: str, events: pd.DataFrame, max_rows: Optional[int] = 10) -> None`

Utility to print a table of events to standard output with a heading.  It displays up to `max_rows` rows (default 10) and notes if additional rows were omitted.

### `AnalyzerGUI` (class)

Encapsulates the Tkinter user interface.  Major components and methods:

- **File selectors** – Entries and browse buttons for the log file, config file, and IP list.  Supported log extensions include `.csv`, `.tsv`, `.json`, and `.evtx` (if EVTX support is available).
- **Detection checkboxes** – Boolean variables bound to checkboxes for each detection module.
- **Scrolled output area** – A text widget with scrollbars and a monospace font, styled green on black.
- **Run Analysis button** – Launches analysis on a background thread to keep the UI responsive.  Calls `_perform_analysis`, which loads data, config, and IP lists, runs selected detectors, and appends results to the output pane.  Each section of results is truncated to the first 200 rows.

Internal methods such as `_browse_log`, `_browse_config`, and `_browse_ip` use Tkinter file dialogs to choose files.  `_append_output` inserts lines into the output widget.  `_run_analysis_threaded` starts a background thread and disables the run button while analysis is in progress.

### `run_cli(argv: Optional[List[str]] = None) -> None`

The main entry for CLI usage.  Parses command‑line arguments, handles the `--gui` flag, loads the log file and applies enrichment and configuration, runs the requested detections, and prints reports using `print_report`.  If no detections are specified without `--gui`, it triggers an error.  Invoked by `main()`.

### `main() -> None`

Simple wrapper that calls `run_cli()` when the script is executed as a program.  If `--gui` is passed, it launches the GUI instead of running CLI logic.

## Low‑Level Workflow

1. **Log Loading** – The script determines the file type by extension.  For CSV/TSV it uses `pandas.read_csv`, for JSON it tries newline‑delimited JSON first, and for EVTX it calls `load_evtx` if the optional dependencies are available.  It normalises column names to lower case and converts timestamps to `datetime` objects.  Event IDs are cast to integers.
2. **Configuration and IP Enrichment** – If a configuration file is provided, it is loaded into a dictionary.  The `brute_force` and `tgt_anomalies` keys can override default thresholds and allowed encryptions.  If an IP list is provided, the script adds a `known_bad_ip` column to the DataFrame marking rows with IPs found in the list.
3. **Detection Dispatch** – Depending on the selected flags (CLI) or checkboxes (GUI), the appropriate detector functions are called.  Each detector returns a DataFrame of matching events.
4. **Reporting** – In CLI mode, results are printed to standard output using `print_report`.  In GUI mode, results are appended to the output text widget.  The GUI truncates each report to the first 200 rows to prevent memory and rendering issues.
5. **Error Handling** – The script checks for missing files, missing required columns, and absent dependencies.  In GUI mode, errors are presented via message boxes; in CLI mode, exceptions propagate to the terminal.

## Notes and Limitations

- **EVTX Parsing** – Requires `python-evtx` and `xmltodict`.  Without these, EVTX analysis is unavailable.
- **Timestamps and Event IDs** – The script expects a valid timestamp column and an `EventID` column.  If your logs use different names, you may need to rename columns before analysis.
- **False Positives** – The detectors flag potentially suspicious activity but do not conclusively identify malicious behaviour.  Further investigation is required to determine whether an alert is benign or malicious.
- **Large Logs** – Analysis of very large logs can consume significant memory.  For best performance, filter logs to relevant event IDs before analysis or increase resources accordingly.
- **GUI Limitations** – The GUI truncates output to 200 rows per section and runs a single analysis session at a time.  It does not allow exporting results directly; use the CLI for automation and full output.

---

For any questions or contributions, please refer to the code or reach out to the maintainer.
