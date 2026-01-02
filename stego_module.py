# stego_module.py
import os
import zlib
from pathlib import Path
from typing import Callable, Optional

from findings import (
    Finding,
    Module,
    Severity,
    IndicatorType,
    finalize_finding,
)
from stego_detection import StegoAnalyzer

# -------------------- ID helper --------------------

_counter = 0
def _next_id(prefix: str = "STG") -> str:
    global _counter
    _counter += 1
    return f"{prefix}-{_counter:06d}"


# -------------------- JPEG helpers --------------------

def _is_jpeg(data: bytes) -> bool:
    return data.startswith(b"\xFF\xD8") and b"\xFF\xD9" in data


def _jpeg_eof_index(data: bytes) -> Optional[int]:
    """Return index of JPEG EOF marker end (position *after* FFD9) or None."""
    idx = data.rfind(b"\xFF\xD9")
    if idx == -1:
        return None
    return idx + 2


# -------------------- PNG helpers --------------------

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

def _is_png(data: bytes) -> bool:
    return data.startswith(PNG_MAGIC)


def _png_iend_index(data: bytes) -> Optional[int]:
    """
    Return index just after the IEND chunk, or None if invalid.
    PNG structure: 8-byte signature, then repeated:
      length(4) | type(4) | data(length) | crc(4)
    """
    if not _is_png(data) or len(data) < 8 + 12:
        return None

    offset = 8
    data_len = len(data)
    iend_end = None

    while offset + 8 <= data_len:
        try:
            length = int.from_bytes(data[offset:offset + 4], "big", signed=False)
            ctype = data[offset + 4:offset + 8]
            chunk_total = 4 + 4 + length + 4  # len + type + data + crc
            if offset + chunk_total > data_len:
                break  # truncated / malformed
        except Exception:
            break

        if ctype == b"IEND":
            iend_end = offset + chunk_total
            break

        offset += chunk_total

    return iend_end


# -------------------- Trailer / payload helpers --------------------

def _is_mostly_printable(b: bytes, threshold: float = 0.90) -> bool:
    """Determine whether bytes resemble printable ASCII text."""
    if not b:
        return False
    printable = sum(1 for x in b if 32 <= x <= 126 or x in (9, 10, 13))
    ratio = printable / len(b)
    return ratio >= threshold


def _guess_language(text: str) -> str:
    """
    Very small, safe heuristics. Returns one of:
    - "powershell", "batch", "python", "javascript", "bash",
      "code-like", or "text".
    """
    t = text.lower()

    if "$env:" in t or "powershell" in t or "param(" in t:
        return "powershell"
    if "function " in t and "{" in t and "}" in t:
        return "javascript"
    if "#!" in t or " fi\n" in t or "elif " in t:
        return "bash"
    if "import " in t or "def " in t or "print(" in t:
        return "python"
    if "echo " in t or "cmd.exe" in t:
        return "batch"

    if any(sym in t for sym in ["{", "}", ";", "()", "==", "&&"]):
        return "code-like"

    return "text"


def _detect_trailer_format(extra: bytes) -> str:
    """
    Very simple classifier for trailer format:
    - "zip", "gzip", "zlib", or "raw"
    """
    if len(extra) >= 4 and extra[:4] == b"PK\x03\x04":
        return "zip"
    if len(extra) >= 2 and extra[:2] == b"\x1F\x8B":
        return "gzip"
    if len(extra) >= 2 and extra[0] == 0x78 and extra[1] in (0x01, 0x9C, 0xDA):
        return "zlib"
    return "raw"


def _try_decompress(extra: bytes, fmt: str) -> Optional[bytes]:
    """
    Best-effort zlib/gzip-style decompression.
    Never executes anything, only returns bytes or None.
    """
    try:
        if fmt == "zlib":
            return zlib.decompress(extra)
        if fmt == "gzip":
            # Very rough: zlib can sometimes handle gzip streams if header is normal;
            # if not, we just treat as opaque.
            return zlib.decompress(extra, wbits=16 + zlib.MAX_WBITS)
    except Exception:
        return None
    return None


def _handle_text_payload(
    image_path: Path,
    text_bytes: bytes,
    out_dir: Path,
    log_callback: Callable[[str], None],
    add_finding
):
    """
    Store printable text from stego trailer and emit TEXT/CODE findings.
    """
    try:
        txt = text_bytes.decode("utf-8", errors="ignore")
    except Exception:
        txt = text_bytes.decode("latin-1", errors="ignore")

    lang = _guess_language(txt)

    qdir = out_dir / "stego_quarantine"
    qdir.mkdir(exist_ok=True)
    txt_path = qdir / f"{image_path.name}.hidden.txt"
    with open(txt_path, "w", encoding="utf-8") as tf:
        tf.write(txt)

    payload_size = len(txt.encode("utf-8", errors="ignore"))
    log_callback(
        f"[i] Hidden text extracted from {image_path} ({payload_size} bytes, lang guess: {lang})."
    )

    # TEXT payload finding
    f_text = Finding(
        id=_next_id(),
        module=Module.STEGO,
        indicator_type=IndicatorType.STEGO_TEXT_PAYLOAD,
        severity=Severity.MEDIUM,
        resource_type="text",
        file_path=str(txt_path),
        evidence_summary="Hidden text extracted from image trailer.",
        details={
            "payload_size_bytes": payload_size,
            "language_guess": lang,
            "source_image": str(image_path),
        },
        tags=["stego", "textpayload"],
    )
    add_finding(finalize_finding(f_text))

    # CODE-like payload finding
    if lang != "text":
        f_code = Finding(
            id=_next_id(),
            module=Module.STEGO,
            indicator_type=IndicatorType.STEGO_CODE_PAYLOAD,
            severity=Severity.HIGH,
            resource_type="text_code",
            file_path=str(txt_path),
            evidence_summary=f"Hidden code-like payload detected ({lang}).",
            details={
                "language_guess": lang,
                "source_image": str(image_path),
            },
            tags=["stego", "code"],
        )
        add_finding(finalize_finding(f_code))


def _process_trailer(
    image_path: Path,
    extra: bytes,
    out_dir: Path,
    log_callback: Callable[[str], None],
    add_finding: Optional[Callable[[Finding], None]],
    image_format: str,
):
    """
    Common logic for JPEG/PNG trailer processing:
      - suspicious image finding
      - classify trailer format
      - optional decompression and text/code detection
      - save raw trailer
    """
    extra_len = len(extra)
    if extra_len < 512:
        return

    log_callback(
        f"[!] Stego triage: {image_path} has {extra_len} bytes after {image_format.upper()} end marker."
    )

    trailer_fmt = _detect_trailer_format(extra)
    trailer_info = {"trailer_format": trailer_fmt}

    # ---- Finding #1: Suspicious image ----
    if add_finding:
        f_img = Finding(
            id=_next_id(),
            module=Module.STEGO,
            indicator_type=IndicatorType.STEGO_SUSPICIOUS_IMAGE,
            severity=Severity.MEDIUM,
            resource_type="image",
            file_path=str(image_path),
            evidence_summary=(
                f"{image_format.upper()} image has {extra_len} bytes of non-image data after end marker."
            ),
            details={
                "stego_stage": "triage",
                "image_metadata": {
                    "format": image_format.lower(),
                    "size_bytes": None,   # optional; can be filled by caller
                    "has_data_after_eof": True,
                },
                "extra_data_bytes": extra_len,
                **trailer_info,
            },
            tags=["stego", "triage"],
        )
        add_finding(finalize_finding(f_img))

    # ---- Trailer classification and processing ----
    decompressed = None
    
    # 1. ZIP detection – safe extraction to quarantine
    if trailer_fmt == "zip":
        qdir = out_dir / "stego_quarantine"
        qdir.mkdir(exist_ok=True)

        zip_path = qdir / f"{image_path.name}.hidden.zip"
        try:
            with open(zip_path, "wb") as zf:
                zf.write(extra)
            log_callback(f"[i] ZIP archive detected in trailer, saved to: {zip_path}")
        except Exception:
            pass

        # Try reading names safely
        try:
            import zipfile
            with zipfile.ZipFile(zip_path, "r") as z:
                names = z.namelist()
                log_callback(f"[i] ZIP contains: {names}")

                # Check if ZIP contains code-like files
                suspicious_exts = {".exe", ".ps1", ".bat", ".py", ".js", ".vbs", ".cmd"}
                code_like = any(n.lower().endswith(tuple(suspicious_exts)) for n in names)

                if add_finding:
                    f_zip = Finding(
                        id=_next_id(),
                        module=Module.STEGO,
                        indicator_type=IndicatorType.STEGO_SUSPICIOUS_IMAGE,
                        severity=Severity.MEDIUM,
                        resource_type="zip",
                        file_path=str(zip_path),
                        evidence_summary="Hidden ZIP archive embedded inside image.",
                        details={
                            "zip_file": str(zip_path),
                            "num_entries": len(names),
                            "entries": names,
                            "contains_code_files": code_like,
                        },
                        tags=["stego", "zip"],
                    )
                    add_finding(finalize_finding(f_zip))

                    # Extra finding if code-like entries found
                    if code_like:
                        f_code = Finding(
                            id=_next_id(),
                            module=Module.STEGO,
                            indicator_type=IndicatorType.STEGO_CODE_PAYLOAD,
                            severity=Severity.HIGH,
                            resource_type="zip",
                            file_path=str(zip_path),
                            evidence_summary="ZIP trailer contains code-like files.",
                            details={
                                "entries": names,
                                "source_image": str(image_path),
                            },
                            tags=["stego", "zip-code"],
                        )
                        add_finding(finalize_finding(f_code))

        except Exception:
            pass

    # 2. zlib/gzip decompression
    elif trailer_fmt in ("zlib", "gzip"):
        decompressed = _try_decompress(extra, trailer_fmt)

    # use decompressed or raw for text detection
    candidate = decompressed if decompressed else extra

    # 3. Handle printable text
    if add_finding and _is_mostly_printable(candidate):
        _handle_text_payload(image_path, candidate, out_dir, log_callback, add_finding)

    # Save raw trailer to quarantine (always safe)
    try:
        qdir = out_dir / "stego_quarantine"
        qdir.mkdir(exist_ok=True)
        with open(qdir / f"{image_path.name}.trailer.bin", "wb") as qf:
            qf.write(extra)
    except Exception:
        pass


# -------------------- Per-file scanners --------------------

def _scan_jpeg_file(
    path: Path,
    data: bytes,
    out_dir: Path,
    log_callback: Callable[[str], None],
    add_finding: Optional[Callable[[Finding], None]],
) -> None:
    if not _is_jpeg(data):
        return
    eof_idx = _jpeg_eof_index(data)
    if eof_idx is None or eof_idx >= len(data):
        return
    extra = data[eof_idx:]
    _process_trailer(path, extra, out_dir, log_callback, add_finding, "jpeg")


def _scan_png_file(
    path: Path,
    data: bytes,
    out_dir: Path,
    log_callback: Callable[[str], None],
    add_finding: Optional[Callable[[Finding], None]],
) -> None:
    if not _is_png(data):
        return

    # 1) Parse chunk table and look for weird/large ancillary chunks
    offset = 8
    data_len = len(data)
    suspicious_ancillary = False

    # Typical critical + common ancillary chunk types
    known_ok = {
        b"IHDR", b"IDAT", b"IEND", b"PLTE",
        b"tEXt", b"iTXt", b"zTXt", b"bKGD",
        b"pHYs", b"tIME", b"gAMA", b"cHRM",
    }

    while offset + 8 <= data_len:
        try:
            length = int.from_bytes(data[offset:offset + 4], "big", signed=False)
            ctype = data[offset + 4:offset + 8]
            chunk_total = 4 + 4 + length + 4
            if offset + chunk_total > data_len:
                break
        except Exception:
            break

        # Unknown or unusually large ancillary chunk?
        if ctype not in known_ok and length > 1024:
            suspicious_ancillary = True

        if ctype == b"IEND":
            break

        offset += chunk_total

    if suspicious_ancillary and add_finding:
        # We treat this as a suspicious image even if no trailer is present.
        f_img = Finding(
            id=_next_id(),
            module=Module.STEGO,
            indicator_type=IndicatorType.STEGO_SUSPICIOUS_IMAGE,
            severity=Severity.MEDIUM,
            resource_type="image",
            file_path=str(path),
            evidence_summary="PNG contains large unknown ancillary chunk (possible stego carrier).",
            details={
                "stego_stage": "chunk_inspection",
                "image_metadata": {
                    "format": "png",
                    "size_bytes": len(data),
                    "suspicious_ancillary_chunk": True,
                },
            },
            tags=["stego", "png_chunk"],
        )
        add_finding(finalize_finding(f_img))

    # 2) Check for trailer after IEND and process like JPEG trailer
    iend_end = _png_iend_index(data)
    if iend_end is None or iend_end >= len(data):
        return

    extra = data[iend_end:]
    _process_trailer(path, extra, out_dir, log_callback, add_finding, "png")


# -------------------- Main scan entrypoint --------------------

def scan_images_for_stego(
    drive_letter: Optional[str],
    out_dir: str,
    log_callback: Callable[[str], None],
    add_finding: Optional[Callable[[Finding], None]] = None,
    max_files: int = 5000,
    folder_override: Optional[str] = None,
) -> None:
    """
    Advanced multi-stage steganography detection with confidence scoring.
    """
    # Determine root path
    if folder_override:
        root = Path(folder_override)
        if not root.exists():
            log_callback(f"[!] Stego scan: folder not found: {folder_override}")
            return
    elif drive_letter:
        root = Path(f"{drive_letter}:\\")
        if not root.exists():
            log_callback("[!] Stego scan: drive not found.")
            return
    else:
        log_callback("[!] Stego scan: no drive_letter or folder_override provided.")
        return

    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    
    log_callback("[=] Starting multi-stage steganography detection...")
    log_callback(f"[DEBUG] Scanning root: {root}")  # ADD THIS
    
    # Initialize analyzer
    analyzer = StegoAnalyzer(log_callback=log_callback)
    
    # Counters
    scanned = 0
    suspicious_count = 0
    confirmed_count = 0
    
    # **ADD THIS: Find all images first**
    image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif','.jfif'}
    all_images = [p for p in root.rglob('*') if p.suffix.lower() in image_extensions and p.is_file()]
    
    log_callback(f"[DEBUG] Found {len(all_images)} images in {root}")  # ADD THIS
    
    if len(all_images) == 0:
        log_callback("[!] No images found in the specified folder!")
        return
    
    # Process images
    for path in all_images:  # CHANGE THIS from root.rglob("*")
        if scanned >= max_files:
            break
        
        scanned += 1
        log_callback(f"[DEBUG] Processing image {scanned}/{len(all_images)}: {path.name}")  # ADD THIS
        
        try:
            # Read file data
            data = path.read_bytes()
            
            # Run multi-stage analysis
            score, severity, details = analyzer.analyze_image(path, data)
            
            log_callback(f"[DEBUG] Analysis complete: score={score}, severity={severity}")  # ADD THIS
            
            # Create finding based on severity
            if severity in ("MEDIUM", "HIGH", "CRITICAL"):
                suspicious_count += 1
                log_callback(f"[DEBUG] Creating finding for {path.name}")  # ADD THIS
                
                if severity in ("HIGH", "CRITICAL"):
                    confirmed_count += 1
                
                # Map severity
                if severity == "CRITICAL":
                    finding_severity = Severity.HIGH
                    confidence = "critical"
                elif severity == "HIGH":
                    finding_severity = Severity.HIGH
                    confidence = "high"
                elif severity == "MEDIUM":
                    finding_severity = Severity.MEDIUM
                    confidence = "medium"
                else:
                    finding_severity = Severity.LOW
                    confidence = "low"
                
                # Determine indicator type
                if details.get("metadata_scan", {}).get("confirmed_tool"):
                    indicator_type = IndicatorType.STEGO_CODE_PAYLOAD
                    summary = f"Confirmed steganography tool signature detected in {path.name}"
                elif score >= 20:
                    indicator_type = IndicatorType.STEGO_CODE_PAYLOAD
                    summary = f"Strong statistical evidence of steganography in {path.name} (score: {score})"
                elif details.get("lsb_analysis", {}).get("coordinated_embedding"):
                    indicator_type = IndicatorType.STEGO_SUSPICIOUS_IMAGE
                    summary = f"Coordinated LSB embedding pattern detected in {path.name}"
                elif details.get("entropy_analysis", {}).get("lsb_too_random"):
                    indicator_type = IndicatorType.STEGO_TEXT_PAYLOAD
                    summary = f"High-entropy LSB plane suggests hidden payload in {path.name}"
                else:
                    indicator_type = IndicatorType.STEGO_SUSPICIOUS_IMAGE
                    summary = f"Multiple steganography indicators detected in {path.name}"
                
                # Create finding
                if add_finding:
                    log_callback(f"[DEBUG] Calling add_finding() for {path.name}")  # ADD THIS
                    finding = Finding(
                        id=_next_id("STEGO"),
                        module=Module.STEGO,
                        indicator_type=indicator_type,
                        severity=finding_severity,
                        resource_type="image",
                        file_path=str(path),
                        evidence_summary=summary,
                        details={
                            "analysis_score": score,
                            "confidence": confidence,
                            **details
                        },
                        tags=["stego", "multi_stage_analysis", severity.lower()],
                    )
                    finding.confidence_level = confidence
                    add_finding(finalize_finding(finding))
                    log_callback(f"[DEBUG] Finding added successfully")  # ADD THIS
                else:
                    log_callback(f"[!] add_finding is None!")  # ADD THIS
                
                log_callback(f"[!] {severity}: {path.name} - Score: {score}")
            else:
                log_callback(f"[DEBUG] {path.name} marked as {severity} (not suspicious enough)")  # ADD THIS
            
        except Exception as e:
            log_callback(f"[!] Error analyzing {path.name}: {e}")
            import traceback
            log_callback(f"[!] Traceback: {traceback.format_exc()}")  # ADD THIS
            continue
    
    log_callback(f"[=] Stego scan complete:")
    log_callback(f"    - Scanned: {scanned} images")
    log_callback(f"    - Suspicious: {suspicious_count}")
    log_callback(f"    - High confidence: {confirmed_count}")
# Keep the _next_id helper function as-is
_counter = 0
def _next_id(prefix: str = "STG") -> str:
    global _counter
    _counter += 1
    return f"{prefix}-{_counter:06d}"


# You can DELETE or keep these old functions for reference:
# _scan_jpeg_file, _scan_png_file, _process_trailer, etc.
# They are no longer called by the main scan function.