#analysis.py
import os
import csv
import glob
import json
import subprocess
import datetime
from pathlib import Path
from typing import List, Tuple, Optional

from findings import (
    Finding,
    Module,
    Severity,
    IndicatorType,
    finalize_finding,
)

# Third-party libs
from Evtx.Evtx import Evtx

# Optional (not strictly required for core flow); retained for future enhancement
try:
    from Registry import Registry
except Exception:
    Registry = None


def _safe_ts(dt: datetime.datetime) -> str:
    try:
        return dt.isoformat(sep=" ")
    except Exception:
        return str(dt)


def _filetime_to_dt(ft: int) -> Optional[datetime.datetime]:
    """
    Convert Windows FILETIME (100-ns intervals since 1601-01-01 UTC)
    to a Python UTC datetime.
    """
    try:
        # FILETIME base offset: 1601-01-01 to 1970-01-01 in 100-ns steps
        return datetime.datetime.utcfromtimestamp(
            (ft - 116444736000000000) / 10_000_000
        )
    except Exception:
        return None


def evtx_paths(drive_letter: str) -> List[str]:
    base = Path(f"{drive_letter}:\\Windows\\System32\\winevt\\Logs")
    if not base.exists():
        return []
    return [str(p) for p in base.glob("*.evtx")]


def check_event_log_tamper(
    drive_letter: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Heuristic: if Security.evtx exists, scan for events that often indicate tampering.
    - 1102 (The audit log was cleared)
    - 1100 (The event logging service has shut down)
    - 104  (The audit log was cleared / service restart, older sources)
    For structured findings we primarily flag 1100/104 as 'service stopped' style events.
    """
    sec_log = Path(f"{drive_letter}:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    if not sec_log.exists():
        log_callback("[!] Security.evtx not found; cannot evaluate tamper indicators.")
        return

    suspects = {1102, 1100, 104}
    hits = 0
    tamp_hits = 0  # structured finding counter for 1100/104

    try:
        with Evtx(str(sec_log)) as ev:
            for rec in ev.records():
                try:
                    eid = int(rec.lxml().xpath("System/EventID/text()")[0])
                    if eid in suspects:
                        ts = rec.timestamp()
                        log_callback(
                            f"[!] Possible tamper indicator EventID={eid} at {ts}"
                        )
                        hits += 1

                        # Structured findings for service-stop style events (1100/104)
                        if add_finding and eid in (1100, 104):
                            tamp_hits += 1
                            ts_str = ts.isoformat()
                            f = Finding(
                                id=f"EVTX-TAMP-{tamp_hits:04d}",
                                module=Module.EVTX,
                                indicator_type=IndicatorType.EVENTLOG_SERVICE_STOPPED,
                                severity=Severity.MEDIUM,
                                resource_type="eventlog",
                                file_path=str(sec_log),
                                related_artifact=f"Record {rec.record_id()}",
                                evidence_summary=(
                                    f"Event logging service tamper-type event "
                                    f"(EventID {eid}) at {ts_str}"
                                ),
                                details={
                                    "log_name": "Security",
                                    "evtx_file_path": str(sec_log),
                                    "event_id": eid,
                                    "record_id": rec.record_id(),
                                    "event_time": ts_str,
                                    "user_sid": None,  # could be parsed from XML later
                                },
                                tags=["evtx", "tamper"],
                            )
                            add_finding(finalize_finding(f))
                except Exception:
                    continue
    except Exception as e:
        log_callback(f"[!] Error reading Security.evtx: {e}")

    if hits == 0:
        log_callback(
            "[+] No obvious EVTX tamper indicators (1102/1100/104) found in Security.evtx."
        )


def find_log_deletions(
    drive_letter: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Look for Security 1102 events (audit log cleared).
    Emits high-severity findings for each 1102 instance if add_finding is provided.
    """
    sec_log = Path(f"{drive_letter}:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    if not sec_log.exists():
        log_callback("[!] Security.evtx not found; cannot check log deletions.")
        return

    count_1102 = 0
    try:
        with Evtx(str(sec_log)) as ev:
            for rec in ev.records():
                try:
                    eid = int(rec.lxml().xpath("System/EventID/text()")[0])
                    if eid == 1102:
                        count_1102 += 1
                        ts = rec.timestamp()
                        log_callback(f"[!] Security log cleared (1102) at {ts}")

                        if add_finding:
                            f = Finding(
                                id=f"EVTX-1102-{count_1102:04d}",
                                module=Module.EVTX,
                                indicator_type=IndicatorType.EVENTLOG_CLEARED,
                                severity=Severity.HIGH,
                                resource_type="eventlog",
                                file_path=str(sec_log),
                                related_artifact=f"Record {rec.record_id()}",
                                evidence_summary=(
                                    f"Security log cleared (EventID 1102) at {ts}"
                                ),
                                details={
                                    "log_name": "Security",
                                    "evtx_file_path": str(sec_log),
                                    "event_id": 1102,
                                    "record_id": rec.record_id(),
                                    "event_time": ts.isoformat(),
                                    "user_sid": None,  # you can parse SID from XML if needed
                                },
                                tags=["evtx", "log_cleared"],
                            )
                            add_finding(finalize_finding(f))
                except Exception:
                    continue
    except Exception as e:
        log_callback(f"[!] Error reading Security.evtx: {e}")
        return

    if count_1102 > 0:
        log_callback(
            f"[!] Detected {count_1102} instances of EventID 1102 (audit log cleared)."
        )
    else:
        log_callback("[+] No Security 1102 (audit log cleared) events detected.")


def count_events_by_date_range(
    drive_letter: str,
    start: datetime.datetime,
    end: datetime.datetime,
    log_callback=print,
) -> None:
    """
    Iterate all EVTX logs in standard path and count records within [start, end].
    """
    logs = evtx_paths(drive_letter)
    if not logs:
        log_callback("[!] No EVTX logs found under standard path.")
        return

    log_callback(f"[i] Counting EVTX records between {start} and {end}...")

    total = 0
    per_file = []
    for p in logs:
        count = 0
        try:
            with Evtx(p) as ev:
                for rec in ev.records():
                    try:
                        ts = rec.timestamp()
                        if start <= ts <= end:
                            count += 1
                    except Exception:
                        continue
            per_file.append((os.path.basename(p), count))
            total += count
        except Exception as e:
            log_callback(f"[!] Error reading {p}: {e}")

    for fname, cnt in per_file:
        log_callback(f"[+] {fname}: {cnt} events in range.")
    log_callback(f"[=] Total events in range: {total}")


def run_mftecmd_and_detect_timestomp(
    drive_letter: str,
    tools_dir: str,
    output_dir: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Run MFTECmd.exe to parse $MFT and output CSV. Then diff StandardInfo vs FileName timestamps.
    Flags entries where Created/Modified/Accessed differ suspiciously.
    """
    exe_path = Path(tools_dir) / "MFTECmd.exe"
    if not exe_path.exists():
        log_callback("[!] tools/MFTECmd.exe not found. Skipping MFT analysis.")
        return

    os.makedirs(output_dir, exist_ok=True)
    out_csv = Path(output_dir) / "mftecmd_mft.csv"

    # Prefer device path for performance (may require admin): \\.\I:
    device_path = f"\\\\.\\{drive_letter}:"

    cmd = [
        str(exe_path),
        "-f",
        f"{device_path}\\$MFT",
        "--csv",
        str(out_csv),
        "--csvf",
        "mft.csv",
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_callback("[+] MFTECmd completed. Analyzing timestamps...")
    except Exception as e:
        log_callback(f"[!] MFTECmd failed: {e}")
        return

    suspicious = 0
    checked = 0
    try:
        with open(out_csv, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                checked += 1
                # Field names depend on MFTECmd version; keep robust keys
                si_ct = row.get("SI Creation", "") or row.get("SI Created", "")
                fn_ct = row.get("FN Creation", "") or row.get("FN Created", "")
                si_m = row.get("SI Last Modification", "") or row.get(
                    "SI Last Modified", ""
                )
                fn_m = row.get("FN Last Modification", "") or row.get(
                    "FN Last Modified", ""
                )
                si_a = row.get("SI Last Access", "")
                fn_a = row.get("FN Last Access", "")

                # Flag if large divergence exists
                def differs(a: str, b: str) -> bool:
                    return (a and b) and (a != b)

                if any(
                    [
                        differs(si_ct, fn_ct),
                        differs(si_m, fn_m),
                        (si_a and fn_a and si_a != fn_a),
                    ]
                ):
                    suspicious += 1
                    path = row.get("Path", row.get("File Path", ""))
                    log_callback(f"[!] Possible timestomp: {path} | SI vs FN mismatch")
                    if add_finding:
                        # Rough delta in days for created time if both present
                        created_delta_days = None
                        try:
                            if si_ct and fn_ct:
                                si_dt = datetime.datetime.fromisoformat(
                                    si_ct.replace("Z", "+00:00")
                                )
                                fn_dt = datetime.datetime.fromisoformat(
                                    fn_ct.replace("Z", "+00:00")
                                )
                                created_delta_days = abs((fn_dt - si_dt).days)
                        except Exception:
                            pass

                        details = {
                            "mft_record_id": row.get("EntryNumber")
                            or row.get("Entry", ""),
                            "standard_info": {
                                "created": si_ct,
                                "modified": si_m,
                                "accessed": si_a,
                            },
                            "file_name_attr": {
                                "created": fn_ct,
                                "modified": fn_m,
                                "accessed": fn_a,
                            },
                            "timestamp_deltas": {
                                "created_delta_days": created_delta_days,
                            },
                            "suspicious_fields": [
                                name
                                for name, cond in [
                                    ("created", differs(si_ct, fn_ct)),
                                    ("modified", differs(si_m, fn_m)),
                                    ("accessed", si_a and fn_a and si_a != fn_a),
                                ]
                                if cond
                            ],
                            "reason": "SI and FN timestamps differ; potential timestomp.",
                        }

                        sev = (
                            Severity.HIGH
                            if (created_delta_days or 0) > 30
                            else Severity.MEDIUM
                        )

                        f = Finding(
                            id=f"MFT-{suspicious:06d}",
                            module=Module.MFT,
                            indicator_type=IndicatorType.TIMESTAMP_MISMATCH_LARGE,
                            severity=sev,
                            resource_type="file",
                            file_path=path,
                            related_artifact=f"Entry {row.get('EntryNumber', '')}",
                            evidence_summary=f"SI/FN timestamp mismatch for {path}",
                            details=details,
                            tags=["mft", "timestomp"],
                        )
                        add_finding(finalize_finding(f))

        log_callback(
            f"[=] Timestomp check complete. Checked {checked} records, flagged {suspicious}."
        )
    except Exception as e:
        log_callback(f"[!] Error analyzing MFTECmd CSV: {e}")


def _parse_recycle_i_file(
    info_path: Path,
) -> Tuple[Optional[str], Optional[datetime.datetime], Optional[int]]:
    """
    Parse a Windows $I recycle bin info file (Win7+ layout).

    Layout (simplified):
      0x00: 8 bytes header/version (ignored)
      0x08: 8 bytes original file size (little-endian, unsigned)
      0x10: 8 bytes deletion time (FILETIME)
      0x18: UTF-16LE original path (null-terminated)
    """
    try:
        data = info_path.read_bytes()
        if len(data) < 0x18:
            return None, None, None

        size = int.from_bytes(data[0x08:0x10], "little", signed=False)
        ft = int.from_bytes(data[0x10:0x18], "little", signed=False)
        deleted_dt = _filetime_to_dt(ft)

        raw_path = data[0x18:]
        try:
            # decode as UTF-16LE and stop at first null
            path_str = raw_path.decode("utf-16le", errors="ignore").split("\x00", 1)[0]
        except Exception:
            path_str = None

        return path_str, deleted_dt, size
    except Exception:
        return None, None, None


def inspect_recycle_bin(
    drive_letter: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Enumerate $Recycle.Bin and list $I* (info) and $R* (data) files per SID.
    Also emits structured findings for each deleted file info record if add_finding is provided.
    """
    base = Path(f"{drive_letter}:\\$Recycle.Bin")
    if not base.exists():
        log_callback("[!] $Recycle.Bin not found.")
        return

    finding_count = 0

    for sid_dir in base.iterdir():
        if not sid_dir.is_dir():
            continue
        items = list(sid_dir.glob("$I*"))
        data_files = list(sid_dir.glob("$R*"))
        if not items and not data_files:
            continue

        log_callback(
            f"[+] Recycle Bin SID {sid_dir.name}: {len(items)} info files, {len(data_files)} data files."
        )

        # Build a quick mapping of data files by stem (to associate $Ixxxx with $Rxxxx)
        data_map = {p.name.replace("$R", "", 1): p for p in data_files}

        for info in items:
            original_path, deleted_dt, size_bytes = _parse_recycle_i_file(info)
            # Map info file to data file if present
            key = info.name.replace("$I", "", 1)
            data_path = data_map.get(key)

            if original_path or deleted_dt:
                log_callback(
                    f"[i] Recycle entry: SID={sid_dir.name}, "
                    f"Deleted '{original_path}' at {deleted_dt} (size={size_bytes} bytes)"
                )

            if add_finding:
                finding_count += 1
                f = Finding(
                    id=f"RECYCLE-{finding_count:06d}",
                    module=Module.RECYCLE_BIN,
                    indicator_type=IndicatorType.RECYCLE_DELETED_FILE,
                    severity=Severity.LOW,
                    resource_type="recycle_item",
                    file_path=str(data_path) if data_path else str(info),
                    related_artifact=str(info),
                    evidence_summary=(
                        f"Deleted file record for '{original_path}' (Recycle Bin entry)."
                        if original_path
                        else "Deleted file record in Recycle Bin."
                    ),
                    details={
                        "sid": sid_dir.name,
                        "recycle_folder": str(sid_dir),
                        "info_file": info.name,
                        "data_file": data_path.name if data_path else None,
                        "original_path": original_path,
                        "deleted_time": deleted_dt.isoformat()
                        if deleted_dt
                        else None,
                        "size_bytes": size_bytes,
                    },
                    tags=["recycle_bin", "deleted_file"],
                )
                add_finding(finalize_finding(f))


def check_vss_presence(
    drive_letter: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Heuristic check for Volume Shadow Copy (VSS) artifacts in
    'System Volume Information'.

    - Handles PermissionError cleanly (no crash if not run as admin).
    - Optionally creates a VSS / shadow-copy finding.
    """
    svi = Path(f"{drive_letter}:\\System Volume Information")

    if not svi.exists():
        log_callback("[!] System Volume Information not present (or root access denied).")
        return

    try:
        # Just listing the directory itself can raise PermissionError
        entries = list(svi.iterdir())
    except PermissionError:
        log_callback(
            "[!] Access denied to 'System Volume Information'. "
            "Run AFDT as Administrator to enumerate VSS snapshots."
        )
        return
    except Exception as e:
        log_callback(f"[!] Error accessing 'System Volume Information': {e}")
        return

    # Look for typical VSS / snapshot related entries
    interesting_names = {"spp", "systemrestore", "trackings.log", "tracking.log",
                         "efasidat", "indexervolumeguid"}
    hits = []

    for p in entries:
        name = p.name.lower()

        # Generic heuristics
        if "shadow" in name or "restore" in name:
            hits.append(p)
            continue

        if name in interesting_names:
            hits.append(p)
            continue

    if not hits:
        log_callback("[i] No obvious VSS artifacts found (heuristic; they may still exist).")
        return

    # Deduplicate
    hits = list({str(p) for p in hits})
    log_callback(
        f"[+] Found {len(hits)} VSS-related artifacts under System Volume Information."
    )
    for h in hits:
        log_callback(f"[i]   VSS artifact: {h}")

    # Optional structured finding
    if add_finding:
        f = Finding(
            id=f"VSS-{drive_letter}-0001",
            module=Module.VSS,
            indicator_type=IndicatorType.SHADOW_COPY,
            severity=Severity.LOW,  # normal but important context
            resource_type="filesystem",
            file_path=str(svi),
            evidence_summary=(
                f"Detected {len(hits)} VSS-related artifacts in 'System Volume Information'."
            ),
            details={
                "snapshot_id": ", ".join(Path(h).name for h in hits),
                "paths": hits,
            },
            tags=["vss", "shadow_copy"],
        )
        add_finding(finalize_finding(f))


def detect_anti_forensic_apps(
    drive_letter: str,
    signatures_path: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Compare Program Files directories content vs known signatures.
    Emits high-severity findings for matching executables if add_finding is provided.
    """
    try:
        with open(signatures_path, "r", encoding="utf-8") as f:
            sig = json.load(f)
    except Exception as e:
        log_callback(f"[!] Cannot load signatures: {e}")
        return

    exec_names = set(x.lower() for x in sig.get("executables", []))
    folder_keys = [x.lower() for x in sig.get("folders_keywords", [])]

    roots = [
        Path(f"{drive_letter}:\\Program Files"),
        Path(f"{drive_letter}:\\Program Files (x86)"),
        Path(f"{drive_letter}:\\Users"),
    ]

    hits = 0
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            try:
                name = p.name.lower()
                if p.is_file() and name in exec_names:
                    log_callback(f"[!] Anti-forensic executable found: {p}")
                    hits += 1

                    if add_finding:
                        f = Finding(
                            id=f"AF-{hits:06d}",
                            module=Module.ANTI_FORENSICS,
                            indicator_type=IndicatorType.ANTIFORENSIC_TOOL,
                            severity=Severity.HIGH,
                            resource_type="file",
                            file_path=str(p),
                            related_artifact=None,
                            evidence_summary=f"Known anti-forensics/wiping tool detected: {p.name}",
                            details={
                                "program_name": p.name,
                                "exe_path": str(p),
                                "match_type": "executable_name",
                                "signature_name": p.name,
                            },
                            tags=["anti_forensics", "tool"],
                        )
                        add_finding(finalize_finding(f))

                # Folder keyword matches (logged only for now)
                if any(k in name for k in folder_keys):
                    if p.is_dir():
                        log_callback(f"[i] Suspicious folder match: {p}")
            except Exception:
                continue

    if hits == 0:
        log_callback("[+] No anti-forensic executables detected by signature scan.")
# ---------------------------------------------------------------------------
# Folder-mode helpers (for artifact collections like E:\Artifact_Collection)
# Layout expected:
#   root/EVTX/*.evtx
#   root/RecycleBin/$Recycle.Bin/<SID>/*
# ---------------------------------------------------------------------------

def check_event_log_tamper_folder(
    root_dir: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Folder-mode version of check_event_log_tamper.
    Expects Security.evtx at: <root_dir>/EVTX/Security.evtx
    """
    base = Path(root_dir)
    sec_log = base / "EVTX" / "Security.evtx"
    if not sec_log.exists():
        log_callback("[!] (folder mode) Security.evtx not found under EVTX; cannot evaluate tamper indicators.")
        return

    suspects = {1102, 1100, 104}
    hits = 0
    try:
        with Evtx(str(sec_log)) as ev:
            for rec in ev.records():
                try:
                    eid = int(rec.lxml().xpath("System/EventID/text()")[0])
                    if eid in suspects:
                        ts = rec.timestamp()
                        log_callback(f"[!] (folder mode) Possible tamper indicator EventID={eid} at {ts}")
                        hits += 1
                except Exception:
                    continue
    except Exception as e:
        log_callback(f"[!] (folder mode) Error reading Security.evtx: {e}")

    if hits == 0:
        log_callback("[+] (folder mode) No obvious EVTX tamper indicators found in Security.evtx.")


def find_log_deletions_folder(
    root_dir: str,
    log_callback=print,
    add_finding=None,
) -> None:
    """
    Folder-mode version of find_log_deletions.
    Expects Security.evtx at: <root_dir>/EVTX/Security.evtx
    """
    base = Path(root_dir)
    sec_log = base / "EVTX" / "Security.evtx"
    if not sec_log.exists():
        log_callback("[!] (folder mode) Security.evtx not found; cannot check log deletions.")
        return

    count_1102 = 0
    try:
        with Evtx(str(sec_log)) as ev:
            for rec in ev.records():
                try:
                    eid = int(rec.lxml().xpath("System/EventID/text()")[0])
                    if eid == 1102:
                        count_1102 += 1
                        ts = rec.timestamp()
                        log_callback(f"[!] (folder mode) Security log cleared (1102) at {ts}")
                        # You can add folder-mode findings here later if you want
                except Exception:
                    continue
    except Exception as e:
        log_callback(f"[!] (folder mode) Error reading Security.evtx: {e}")
        return

    if count_1102 > 0:
        log_callback(f"[!] (folder mode) Detected {count_1102} instances of EventID 1102 (audit log cleared).")
    else:
        log_callback("[+] (folder mode) No Security 1102 (audit log cleared) events detected.")


def count_events_by_date_range_folder(
    root_dir: str,
    start: datetime.datetime,
    end: datetime.datetime,
    log_callback=print,
) -> None:
    """
    Folder-mode version of count_events_by_date_range.
    Expects EVTX files at: <root_dir>/EVTX/*.evtx
    """
    evtx_root = Path(root_dir) / "EVTX"
    if not evtx_root.exists():
        log_callback("[!] (folder mode) EVTX folder not found under root; cannot count events.")
        return

    logs = [str(p) for p in evtx_root.glob("*.evtx")]
    if not logs:
        log_callback("[!] (folder mode) No EVTX logs found in EVTX folder.")
        return

    log_callback(f"[i] (folder mode) Counting EVTX records between {start} and {end}...")

    total = 0
    per_file = []
    for p in logs:
        count = 0
        try:
            with Evtx(p) as ev:
                for rec in ev.records():
                    try:
                        ts = rec.timestamp()
                        if start <= ts <= end:
                            count += 1
                    except Exception:
                        continue
            per_file.append((os.path.basename(p), count))
            total += count
        except Exception as e:
            log_callback(f"[!] (folder mode) Error reading {p}: {e}")

    for fname, cnt in per_file:
        log_callback(f"[+] (folder mode) {fname}: {cnt} events in range.")
    log_callback(f"[=] (folder mode) Total events in range: {total}")


def inspect_recycle_bin_folder(
    root_dir: str,
    log_callback=print,
) -> None:
    """
    Folder-mode version of inspect_recycle_bin.
    Expects RecycleBin layout at: <root_dir>/RecycleBin/$Recycle.Bin/...
    """
    base = Path(root_dir) / "RecycleBin" / "$Recycle.Bin"
    if not base.exists():
        log_callback("[!] (folder mode) RecycleBin/$Recycle.Bin not found under root.")
        return

    for sid_dir in base.iterdir():
        if not sid_dir.is_dir():
            continue
        items = list(sid_dir.glob("$I*"))
        data = list(sid_dir.glob("$R*"))
        if not items and not data:
            continue
        log_callback(
            f"[+] (folder mode) Recycle Bin SID {sid_dir.name}: {len(items)} info files, {len(data)} data files."
        )
