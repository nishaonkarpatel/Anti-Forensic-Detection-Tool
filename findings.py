# findings.py
import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# -------------------- Enums / constants --------------------

class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Module:
    MFT = "mft"
    EVTX = "evtx"
    RECYCLE_BIN = "recycle_bin"
    ANTI_FORENSICS = "anti_forensics"
    STEGO = "stego"
    CARVING = "carving"
    VSS = "vss"


# You can extend this list as needed
class IndicatorType:
    TIMESTAMP_MISMATCH_LARGE = "timestamp_mismatch_large_delta"
    EVENTLOG_CLEARED = "eventlog_cleared"
    EVENTLOG_SERVICE_STOPPED = "eventlog_service_stopped"
    STEGO_SUSPICIOUS_IMAGE = "stego_suspicious_image"
    STEGO_TEXT_PAYLOAD = "stego_text_payload_detected"
    STEGO_CODE_PAYLOAD = "stego_code_like_payload_detected"
    ANTIFORENSIC_TOOL = "anti_forensic_tool_detected"
    RECYCLE_DELETED_FILE = "deleted_file_record"
    CARVED_FILE = "recovered_deleted_file"
    SHADOW_COPY = "shadow_copy_present"


# -------------------- Dataclass --------------------

@dataclass
class Finding:
    id: str
    module: str
    indicator_type: str
    severity: str

    resource_type: str
    file_path: str
    related_artifact: Optional[str] = None

    evidence_summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    priority_score: int = 0
    executive_summary_bullet: str = ""

    tags: List[str] = field(default_factory=list)
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)


# -------------------- Scoring --------------------

def _severity_weight(sev: str) -> int:
    if sev == Severity.HIGH:
        return 100
    if sev == Severity.MEDIUM:
        return 50
    return 10


def _module_weight(module: str) -> int:
    if module == Module.EVTX:
        return 30
    if module == Module.MFT:
        return 25
    if module == Module.STEGO:
        return 25
    if module == Module.ANTI_FORENSICS:
        return 20
    if module == Module.CARVING:
        return 10
    if module == Module.VSS:
        return 10
    if module == Module.RECYCLE_BIN:
        return 5
    return 0


def _indicator_weight(ind: str) -> int:
    if ind == IndicatorType.EVENTLOG_CLEARED:
        return 40
    if ind == IndicatorType.EVENTLOG_SERVICE_STOPPED:
        return 30
    if ind == IndicatorType.TIMESTAMP_MISMATCH_LARGE:
        return 30
    if ind == IndicatorType.STEGO_CODE_PAYLOAD:
        return 40
    if ind == IndicatorType.STEGO_TEXT_PAYLOAD:
        return 30
    if ind == IndicatorType.ANTIFORENSIC_TOOL:
        return 35
    if ind == IndicatorType.CARVED_FILE:
        return 20
    if ind == IndicatorType.STEGO_SUSPICIOUS_IMAGE:
        return 10
    if ind == IndicatorType.SHADOW_COPY:
        return 10
    if ind == IndicatorType.RECYCLE_DELETED_FILE:
        return 10
    return 0


def _context_bonus(f: Finding) -> int:
    bonus = 0
    fp = (f.file_path or "").lower()

    # Paths
    if "\\users\\" in fp:
        bonus += 10
    if "\\windows\\system32" in fp or "\\program files" in fp:
        bonus += 10
    if "\\appdata\\roaming" in fp:
        bonus += 10

    # You can add case time-window / correlation bonuses later if needed
    return bonus


def score_finding(f: Finding) -> None:
    """Compute and set f.priority_score in-place."""
    base = _severity_weight(f.severity)
    base += _module_weight(f.module)
    base += _indicator_weight(f.indicator_type)
    base += _context_bonus(f)
    f.priority_score = base


# -------------------- Executive summary bullets --------------------

def _filename_from_path(path: str) -> str:
    if not path:
        return ""
    return path.rstrip("\\/").split("\\")[-1].split("/")[-1]


def generate_executive_summary(f: Finding) -> None:
    fn = _filename_from_path(f.file_path)

    # MFT
    if f.module == Module.MFT and f.indicator_type == IndicatorType.TIMESTAMP_MISMATCH_LARGE:
        delta = f.details.get("timestamp_deltas", {}).get("created_delta_days", "large")
        f.executive_summary_bullet = (
            f"Large timestamp mismatch in {fn or 'file'}; "
            f"SI/FN creation times differ by {delta} days."
        )
        return

    # EVTX — log cleared
    if f.module == Module.EVTX and f.indicator_type == IndicatorType.EVENTLOG_CLEARED:
        eid_time = f.details.get("event_time")
        user_sid = f.details.get("user_sid", "unknown SID")
        f.executive_summary_bullet = (
            f"Security log cleared (Event 1102) on {eid_time} by user {user_sid}."
        )
        return

    # EVTX — service stopped / tamper-style events
    if f.module == Module.EVTX and f.indicator_type == IndicatorType.EVENTLOG_SERVICE_STOPPED:
        eid = f.details.get("event_id", "service-stop")
        eid_time = f.details.get("event_time")
        f.executive_summary_bullet = (
            f"Event logging service tamper-type event (Event {eid}) at {eid_time}."
        )
        return

    # Anti-forensics
    if f.module == Module.ANTI_FORENSICS and f.indicator_type == IndicatorType.ANTIFORENSIC_TOOL:
        tool = f.details.get("program_name", fn or "tool")
        f.executive_summary_bullet = f"Detected known wiping/anti-forensics tool '{tool}'."
        return

    # Stego
    if f.module == Module.STEGO:
        if f.indicator_type == IndicatorType.STEGO_SUSPICIOUS_IMAGE:
            extra_kb = f.details.get("extra_data_bytes", 0) // 1024
            f.executive_summary_bullet = (
                f"Image {fn or 'image'} contains ~{extra_kb} KB of suspicious embedded data."
            )
            return
        if f.indicator_type == IndicatorType.STEGO_TEXT_PAYLOAD:
            size = f.details.get("payload_size_bytes", 0)
            f.executive_summary_bullet = (
                f"Hidden text payload extracted from {fn or 'image'} ({size} bytes)."
            )
            return
        if f.indicator_type == IndicatorType.STEGO_CODE_PAYLOAD:
            lang = f.details.get("language_guess", "code-like")
            f.executive_summary_bullet = (
                f"Hidden {lang} script extracted from {fn or 'image'} stored in metadata."
            )
            return

    # Carving
    if f.module == Module.CARVING and f.indicator_type == IndicatorType.CARVED_FILE:
        ftype = f.details.get("file_type", "file")
        size = f.details.get("size_bytes", 0)
        off = f.details.get("offset_start")
        off_s = f"0x{off:X}" if isinstance(off, int) else "unknown offset"
        f.executive_summary_bullet = (
            f"Recovered deleted {ftype} ({size} bytes) from unallocated space at offset {off_s}."
        )
        return

    # Recycle bin
    if f.module == Module.RECYCLE_BIN and f.indicator_type == IndicatorType.RECYCLE_DELETED_FILE:
        orig = f.details.get("original_path", "a file")
        sid = f.details.get("sid", "unknown SID")
        f.executive_summary_bullet = (
            f"Deleted file '{orig}' found in Recycle Bin for user {sid}."
        )
        return

    # VSS
    if f.module == Module.VSS and f.indicator_type == IndicatorType.SHADOW_COPY:
        root = f.details.get("vss_root", "System Volume Information")
        count = f.details.get("indicator_count")
        if count is not None:
            f.executive_summary_bullet = (
                f"Found {count} VSS-related artifacts in {root}."
            )
        else:
            f.executive_summary_bullet = (
                f"VSS-related artifacts detected in {root}."
            )
        return

    # Fallback
    f.executive_summary_bullet = f.evidence_summary or f"{f.module}: {f.indicator_type}"


def finalize_finding(f: Finding) -> Finding:
    """Convenience: score + generate summary, then return f."""
    score_finding(f)
    generate_executive_summary(f)
    return f
