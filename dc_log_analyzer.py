#!/usr/bin/env python3
"""
dc_log_analyzer.py
===================

This script provides a simple way to triage Windows domain controller (DC) event
logs for common signs of abuse or malicious activity.  It focuses on a handful
of high‑value event IDs that are often used by attackers and can reveal
evidence of password spraying, privileged logon abuse, Kerberos service ticket
requests ("kerberoasting"), and unauthorized account creation.  The detection
patterns implemented here are based on published guidance:

* **Kerberoasting:** Attackers request Kerberos service tickets for user
  accounts and then attempt to crack the returned ticket offline.  Normal
  traffic uses AES encryption (`0x11` or `0x12`), whereas most kerberoasting
  tools force RC4‐HMAC (`0x17`).  Additionally, machine accounts end with a
  trailing dollar sign (`$`); TGS requests for user accounts without `$`,
  especially in large volumes, are suspicious【205783421775050†L190-L218】.

* **Brute force/password spraying:** Event ID 4625 records every failed logon
  attempt【985813946893414†L28-L31】.  Repeated failures from the same source in a
  short time window can indicate a password guessing attack.

* **Privileged logon:** Event ID 4672 is logged when a new logon is assigned
  administrative or sensitive privileges.  These include `SeDebugPrivilege`,
  `SeBackupPrivilege`, `SeCreateTokenPrivilege`, etc., and are often abused by
  attackers to perform lateral movement【268805509240126†L169-L181】.

* **Account creation:** Event ID 4720 indicates a new user account has been
  created.  Monitoring these events helps spot unauthorized account creation.

* **Kerberos TGT anomalies:** Event ID 4768 logs when a Ticket‑Granting Ticket
  (TGT) is requested.  Encryption types other than 0x11 and 0x12 (AES) should
  be scrutinized【800595494679302†L860-L863】, as older algorithms like DES or RC4
  may suggest misconfiguration or exploitation.  The script can flag such
  anomalies with the ``--tgt`` option.

* **Group membership enumeration:** Events 4798 and 4799 record when a process
  enumerates the members of a local group (4798)【931580698648778†L24-L35】 or a
  security‑enabled local group (4799)【868449646569748†L176-L183】.  Attackers may
  perform these enumerations to understand group assignments.  Monitoring these
  events, particularly for critical groups, can highlight reconnaissance
  activity【868449646569748†L319-L327】.

The script accepts a CSV or JSON file exported from `Get‑WinEvent` or a
SIEM.  It expects at minimum the following columns (case insensitive):

* `EventID` – The numeric Windows event ID.
* `TimeCreated` or `Timestamp` – The date/time the event was generated.
* `AccountName` – The user or service account associated with the event.
* Optional fields for specific detections:
  * `TicketEncryptionType` – Used for kerberoasting detection (e.g. `0x17`).
  * `IpAddress` or `SourceIp` – The remote address generating the event.
  * `PrivilegeList` – A semicolon‑delimited list of privileges granted during
    privileged logons.

Usage example:

```bash
python dc_log_analyzer.py --file example_logs.csv --kerberoast --brute --priv --accounts
python dc_log_analyzer.py --file example_logs.csv --tgt --enumerations --config settings.yaml --enrich-ip-file bad_ips.txt
```

This will parse `example_logs.csv` and print any suspected kerberoasting
events, brute force attempts (5+ failed logons within 5 minutes), privileged
logon events, and newly created accounts.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import pandas as pd
try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # yaml parsing will be unavailable


def parse_timestamp(value: str) -> datetime:
    """Convert a timestamp string into a `datetime` object.

    The Windows event log export formats sometimes contain fractional seconds
    and time zone information.  This function tries several common formats.

    Args:
        value: The timestamp string from the log file.

    Returns:
        A `datetime` object in local time.
    """
    # Try a few patterns; extend as needed
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
    # As a fallback try pandas to_datetime which is slower but robust
    return pd.to_datetime(value).to_pydatetime()


def load_logs(file_path: str) -> pd.DataFrame:
    """Load event logs from a CSV or JSON file into a pandas DataFrame.

    Args:
        file_path: Path to a CSV or JSON file containing exported event logs.

    Returns:
        A DataFrame with normalized column names (lowercase) and a
        `timestamp` column of type `datetime`.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()
    if ext in {".csv", ".tsv"}:
        df = pd.read_csv(file_path)
    elif ext == ".json":
        df = pd.read_json(file_path, lines=True)
    else:
        raise ValueError("Unsupported file type. Please provide CSV or JSON.")

    # Normalize column names to lower case for easier access
    df.columns = [c.lower() for c in df.columns]
    # Map possible timestamp columns to a unified 'timestamp'
    time_col = None
    for candidate in ["timecreated", "timestamp", "time", "created", "@timestamp"]:
        if candidate in df.columns:
            time_col = candidate
            break
    if time_col is None:
        raise ValueError("No recognizable timestamp column found. Expected one of: timecreated, timestamp, time, created, @timestamp.")

    # Parse timestamps to datetime; errors='coerce' converts invalid dates to NaT
    df["timestamp"] = df[time_col].apply(lambda x: parse_timestamp(str(x)) if pd.notnull(x) else pd.NaT)
    # Drop rows without valid timestamp
    df = df.dropna(subset=["timestamp"])

    # Convert eventid to numeric for comparison (errors='coerce' sets invalid to NaN)
    if "eventid" in df.columns:
        df["eventid"] = pd.to_numeric(df["eventid"], errors="coerce")
    else:
        raise ValueError("EventID column not found in the log file.")

    return df


def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load detection configuration from a YAML or JSON file.

    The configuration file allows you to adjust detection thresholds, specify
    additional suspicious encryption types, or provide allowlists and blocklists
    without modifying the code.  The top‑level keys correspond to the
    detection functions (e.g. ``kerberoast``, ``brute_force``, ``tgt_anomalies``).

    Args:
        config_path: Path to the configuration file, or ``None`` if no
            configuration should be loaded.

    Returns:
        A nested dictionary of configuration values.  Unknown keys are ignored.
    """
    config: Dict[str, Any] = {}
    if not config_path:
        return config
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    ext = os.path.splitext(config_path)[1].lower()
    try:
        with open(config_path, 'r', encoding='utf-8') as fh:
            if ext in {'.yaml', '.yml'}:
                if yaml is None:
                    raise ImportError("PyYAML is required for YAML config files")
                config = yaml.safe_load(fh) or {}
            else:
                config = json.load(fh)
    except Exception as exc:
        raise ValueError(f"Failed to load configuration: {exc}")
    return config


def enrich_with_bad_ips(df: pd.DataFrame, ip_file: Optional[str]) -> pd.DataFrame:
    """Mark events whose IP addresses appear in a known bad list.

    Args:
        df: DataFrame containing an IP address column (e.g. ``ipaddress`` or
            ``sourceip``).  The function attempts to find the first matching
            column.
        ip_file: Path to a file containing one IP address per line.  If
            ``None``, no enrichment is performed.

    Returns:
        The original DataFrame with an added boolean ``known_bad_ip`` column.
    """
    df = df.copy()
    df['known_bad_ip'] = False
    if not ip_file:
        return df
    if not os.path.isfile(ip_file):
        raise FileNotFoundError(f"Known bad IP file not found: {ip_file}")
    with open(ip_file, 'r', encoding='utf-8') as f:
        bad_ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}
    # Determine IP column
    ip_col = None
    for candidate in ['ipaddress', 'sourceip', 'ip', 'clientaddress']:
        if candidate in df.columns:
            ip_col = candidate
            break
    if ip_col is None:
        return df
    df['known_bad_ip'] = df[ip_col].astype(str).isin(bad_ips)
    return df


def detect_kerberoasting(df: pd.DataFrame) -> pd.DataFrame:
    """Identify potential kerberoasting activity from event 4769 logs.

    The function filters for event ID 4769 (Service Ticket Requested) where the
    ticket encryption type is RC4‐HMAC (`0x17`) and the account name does not
    end with `$`.  Machine accounts typically end in `$`, so user accounts
    requesting RC4 tickets are more likely to be malicious.  Optionally
    additional heuristics could include rate‑based detection (e.g. dozens of
    requests within minutes).

    Args:
        df: DataFrame of event logs.

    Returns:
        DataFrame of suspicious 4769 events.
    """
    subset = df[df["eventid"] == 4769].copy()
    if "ticketencryptiontype" not in subset.columns:
        return pd.DataFrame(columns=subset.columns)
    if "accountname" not in subset.columns:
        return pd.DataFrame(columns=subset.columns)
    # Normalize strings to lowercase; remove nulls
    subset["ticketencryptiontype"] = subset["ticketencryptiontype"].astype(str).str.lower()
    subset["accountname"] = subset["accountname"].astype(str)
    susp = subset[(subset["ticketencryptiontype"] == "0x17") & (~subset["accountname"].str.endswith("$"))]
    return susp


def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 5,
    source_ip_field: str = "ipaddress",
) -> pd.DataFrame:
    """Detect possible brute force or password spraying attacks.

    The algorithm looks for repeated failed logon attempts (Event ID 4625) from
    the same IP within a sliding time window.  If a source IP records at
    least `threshold` failures within `window_minutes`, it is flagged.

    Args:
        df: DataFrame of event logs.
        threshold: Minimum number of failures within the window to trigger an alert.
        window_minutes: Time window length in minutes.
        source_ip_field: Name of the column that contains the source IP.

    Returns:
        DataFrame containing the suspicious IP addresses and the events that
        triggered the detection.
    """
    # Filter to 4625 (failed logon) events
    failures = df[df["eventid"] == 4625].copy()
    # Determine the correct IP field name (ipaddress vs sourceip vs hostname)
    for candidate in [source_ip_field.lower(), "sourceip", "ipaddress", "ip", "clientaddress"]:
        if candidate in failures.columns:
            ip_col = candidate
            break
    else:
        # If no IP column, cannot detect brute force
        return pd.DataFrame(columns=failures.columns)

    # Drop rows with null IP
    failures = failures.dropna(subset=[ip_col])
    # Sort by timestamp for window scanning
    failures = failures.sort_values("timestamp")
    suspicious_records = []
    # Group by IP address
    for ip, group in failures.groupby(ip_col):
        times = group["timestamp"].tolist()
        start_idx = 0
        for end_idx in range(len(times)):
            # Advance window start until difference within window_minutes
            while times[end_idx] - times[start_idx] > timedelta(minutes=window_minutes):
                start_idx += 1
            if end_idx - start_idx + 1 >= threshold:
                # Append all events for this IP within the window
                suspicious_records.append(group.iloc[start_idx : end_idx + 1])
                break  # Stop scanning after first detection per IP
    if not suspicious_records:
        return pd.DataFrame(columns=failures.columns)
    return pd.concat(suspicious_records, ignore_index=True)


def detect_privileged_logon(df: pd.DataFrame) -> pd.DataFrame:
    """Return events indicating privileged logons (Event ID 4672).

    Privileged logons assign sensitive privileges such as `SeDebugPrivilege` and
    `SeBackupPrivilege`【268805509240126†L169-L181】.  Unexpected occurrences may indicate
    abuse or misconfiguration.  This function simply filters for event ID
    4672.  Additional filtering (e.g. whitelist known service accounts) can be
    implemented by the caller.

    Args:
        df: DataFrame of event logs.

    Returns:
        DataFrame containing privileged logon events.
    """
    return df[df["eventid"] == 4672].copy()


def detect_account_creation(df: pd.DataFrame) -> pd.DataFrame:
    """Return events for new user account creation (Event ID 4720).

    Args:
        df: DataFrame of event logs.

    Returns:
        DataFrame containing account creation events.
    """
    return df[df["eventid"] == 4720].copy()


def detect_tgt_anomalies(
    df: pd.DataFrame,
    allowed_encryptions: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Identify Kerberos Ticket‑Granting Ticket (TGT) requests with unusual encryption.

    Event ID 4768 logs when a user or service requests a TGT.  According to
    Microsoft's security monitoring guidance, encryption types other than
    ``0x11`` (AES128) and ``0x12`` (AES256) should be scrutinized
    【800595494679302†L860-L863】.  This function returns all 4768 events whose
    `TicketEncryptionType` is not in the allowed list.  If the encryption type
    column isn't present, an empty DataFrame is returned.

    Args:
        df: DataFrame of event logs.
        allowed_encryptions: List of permitted encryption type hex strings
            (e.g. ['0x11', '0x12']).  If ``None``, defaults to these values.

    Returns:
        DataFrame of 4768 events with suspicious encryption types.
    """
    subset = df[df['eventid'] == 4768].copy()
    if 'ticketencryptiontype' not in subset.columns:
        return pd.DataFrame(columns=subset.columns)
    # Normalize
    subset['ticketencryptiontype'] = subset['ticketencryptiontype'].astype(str).str.lower()
    if not allowed_encryptions:
        allowed_encryptions = ['0x11', '0x12']
    # Return events with encryption type not in allowed list
    susp = subset[~subset['ticketencryptiontype'].isin([e.lower() for e in allowed_encryptions])]
    return susp


def detect_group_enumeration(df: pd.DataFrame) -> pd.DataFrame:
    """Return events where a user's local group membership was enumerated (Event 4798).

    Event 4798 is logged when a process enumerates the local groups a user belongs
    to.  It can signal reconnaissance by attackers as they discover local group
    memberships【931580698648778†L24-L35】.  This function simply filters for
    event ID 4798.

    Args:
        df: DataFrame of event logs.

    Returns:
        DataFrame of 4798 events.
    """
    return df[df['eventid'] == 4798].copy()


def detect_security_group_enumeration(df: pd.DataFrame) -> pd.DataFrame:
    """Return events where a security‑enabled local group membership was enumerated (Event 4799).

    Event 4799 is logged when a process enumerates the members of a security‑enabled
    local group on a computer or device【868449646569748†L176-L183】.  Monitoring
    these events for critical groups can help identify reconnaissance attempts
    【868449646569748†L319-L327】.  This function filters for event ID 4799.

    Args:
        df: DataFrame of event logs.

    Returns:
        DataFrame of 4799 events.
    """
    return df[df['eventid'] == 4799].copy()


def print_report(title: str, events: pd.DataFrame, max_rows: Optional[int] = 10) -> None:
    """Print a concise report of suspicious events.

    Args:
        title: Section title for the report.
        events: DataFrame containing the events to display.
        max_rows: Maximum number of rows to print (defaults to 10).  If
            set to `None`, print all rows.
    """
    print(f"\n=== {title} ===")
    if events.empty:
        print("No events detected.")
    else:
        print(events.head(max_rows).to_string(index=False))
        if max_rows is not None and len(events) > max_rows:
            print(f"... ({len(events) - max_rows} more) ...")


def main(argv: Optional[List[str]] = None) -> None:
    """Parse command‑line arguments and perform requested detections."""
    parser = argparse.ArgumentParser(
        description="Analyze Windows DC event logs for suspicious activity.",
        epilog="See script header for detection details and references."
    )
    parser.add_argument("--file", required=True, help="Path to the CSV or JSON log file to analyze.")
    parser.add_argument(
        "--kerberoast",
        action="store_true",
        help="Detect kerberoasting: event 4769 with RC4 (0x17) and non‑machine accounts.",
    )
    parser.add_argument(
        "--brute",
        action="store_true",
        help="Detect brute force/password spray attacks (event 4625).",
    )
    parser.add_argument(
        "--priv",
        action="store_true",
        help="List privileged logon events (event 4672).",
    )
    parser.add_argument(
        "--accounts",
        action="store_true",
        help="List new account creations (event 4720).",
    )
    parser.add_argument(
        "--tgt",
        action="store_true",
        help="Detect suspicious TGT requests (event 4768) using unusual encryption types.",
    )
    parser.add_argument(
        "--enumerations",
        action="store_true",
        help="List enumeration events for local and security‑enabled groups (events 4798 and 4799).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Brute force threshold of failed logons. Overrides config value.",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help="Brute force time window in minutes. Overrides config value.",
    )
    parser.add_argument(
        "--config",
        help="Path to a YAML or JSON configuration file for detection settings.",
    )
    parser.add_argument(
        "--enrich-ip-file",
        dest="enrich_ip_file",
        help="Path to a file containing known bad IP addresses, one per line, for enrichment.",
    )
    args = parser.parse_args(argv)

    # Load logs and enrich
    df = load_logs(args.file)
    df = enrich_with_bad_ips(df, args.enrich_ip_file)
    # Load configuration (may override defaults)
    config = load_config(args.config)

    # Determine brute force parameters: CLI overrides > config > default
    brute_threshold = args.threshold
    brute_window = args.window
    if brute_threshold is None:
        brute_threshold = config.get('brute_force', {}).get('threshold', 5)
    if brute_window is None:
        brute_window = config.get('brute_force', {}).get('window_minutes', 5)

    any_requested = False
    # Kerberoasting detection
    if args.kerberoast:
        any_requested = True
        kerb_events = detect_kerberoasting(df)
        print_report("Kerberoasting Events", kerb_events)
    # Brute force detection
    if args.brute:
        any_requested = True
        brute_events = detect_brute_force(
            df,
            threshold=int(brute_threshold),
            window_minutes=int(brute_window),
        )
        print_report("Brute Force/Password Spray Events", brute_events)
    # Privileged logon events
    if args.priv:
        any_requested = True
        priv_events = detect_privileged_logon(df)
        print_report("Privileged Logon Events", priv_events)
    # Account creations
    if args.accounts:
        any_requested = True
        acct_events = detect_account_creation(df)
        print_report("Account Creation Events", acct_events)
    # Suspicious TGT requests
    if args.tgt:
        any_requested = True
        tgt_cfg = config.get('tgt_anomalies', {})
        allowed_enc = tgt_cfg.get('allowed_encryptions', ['0x11', '0x12'])
        tgt_events = detect_tgt_anomalies(df, allowed_encryptions=allowed_enc)
        print_report("Suspicious TGT Requests", tgt_events)
    # Enumeration events
    if args.enumerations:
        any_requested = True
        enum_user_events = detect_group_enumeration(df)
        enum_sec_events = detect_security_group_enumeration(df)
        print_report("User Group Enumeration Events (4798)", enum_user_events)
        print_report("Security Group Enumeration Events (4799)", enum_sec_events)
    if not any_requested:
        parser.error(
            "No detection type specified. Use one or more of --kerberoast, --brute, --priv, --accounts, --tgt, or --enumerations."
        )


if __name__ == "__main__":
    main()