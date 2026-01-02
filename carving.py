# carving.py - Enhanced with filename recovery attempts
import os
import hashlib
from pathlib import Path
from typing import Optional, Dict, Tuple

from findings import (
    Finding,
    Module,
    Severity,
    IndicatorType,
    finalize_finding
)

# File signatures
MAGICS = {
    "jpg": (b"\xff\xd8\xff", b"\xff\xd9"),
    "png": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    "exe": (b"MZ", None),
}

PREFETCH_MAGIC = b"SCCA"

BAT_SIGNATURES = [
    b"@echo off", b"@ECHO OFF", b"@Echo Off",
    b"REM ", b"rem ", b"call ", b"CALL ",
    b"set ", b"SET ",
]

PS1_SIGNATURES = [
    b"#Requires -Version", b"[CmdletBinding(",
    b"param(", b"$PSVersionTable",
    b"function ", b"Function ",
    b"Write-Host", b"Get-", b"Set-", b"New-",
]


def extract_filename_from_content(data: bytes, file_type: str) -> Optional[str]:
    """
    Try to extract original filename from file content.
    Works for some file types that embed metadata.
    """
    try:
        if file_type == "jpg":
            # Look for JPEG EXIF FileName tag
            if b"FileName" in data:
                idx = data.find(b"FileName")
                # Try to extract nearby ASCII string
                snippet = data[idx:idx+200]
                for i in range(len(snippet)-1):
                    if snippet[i:i+1].isalpha():
                        # Found start of potential filename
                        end = i
                        while end < len(snippet) and (snippet[end:end+1].isalnum() or snippet[end:end+1] in b"._-"):
                            end += 1
                        potential_name = snippet[i:end].decode('ascii', errors='ignore')
                        if len(potential_name) > 3 and '.' in potential_name:
                            return potential_name
        
        elif file_type == "png":
            # PNG iTXt chunks sometimes contain filenames
            if b"File name" in data or b"FileName" in data:
                for pattern in [b"File name", b"FileName"]:
                    idx = data.find(pattern)
                    if idx != -1:
                        snippet = data[idx:idx+150]
                        # Try to find null-terminated string
                        for i in range(len(snippet)):
                            if snippet[i:i+1] == b'\x00':
                                continue
                            if snippet[i:i+1].isalpha():
                                end = i
                                while end < len(snippet) and snippet[end:end+1] not in b'\x00\r\n':
                                    end += 1
                                potential_name = snippet[i:end].decode('utf-8', errors='ignore').strip()
                                if '.' in potential_name and len(potential_name) < 255:
                                    return potential_name
        
        elif file_type == "exe":
            # PE files - look for original filename in VERSION_INFO
            if b"OriginalFilename" in data:
                idx = data.find(b"OriginalFilename")
                snippet = data[idx+16:idx+200]  # Skip tag, look ahead
                # Look for null-terminated UTF-16 string
                potential_bytes = []
                for i in range(0, min(len(snippet), 100), 2):
                    if snippet[i] == 0 and snippet[i+1] == 0:
                        break
                    if snippet[i+1] == 0:  # UTF-16LE
                        potential_bytes.append(snippet[i])
                if potential_bytes:
                    potential_name = bytes(potential_bytes).decode('ascii', errors='ignore')
                    if '.' in potential_name and len(potential_name) > 3:
                        return potential_name
        
        elif file_type in ["bat", "ps1"]:
            # Script files - look for REM comments with filename
            first_lines = data[:500].decode('ascii', errors='ignore').split('\n')[:5]
            for line in first_lines:
                if 'REM' in line.upper() or '#' in line:
                    # Look for filename patterns
                    words = line.split()
                    for word in words:
                        if '.' in word and not word.startswith(('http', 'www')):
                            clean = word.strip('":;,()[]{}')
                            if len(clean) > 3 and len(clean) < 255:
                                return clean
    
    except Exception:
        pass
    
    return None


def calculate_file_hash(data: bytes) -> Tuple[str, str]:
    """Calculate MD5 and SHA1 hashes of file content."""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    return md5, sha1


def get_file_description(data: bytes, file_type: str) -> str:
    """
    Generate a human-readable description of the file content.
    """
    try:
        if file_type == "exe":
            # Try to extract version info or product name
            if b"ProductName" in data:
                idx = data.find(b"ProductName")
                snippet = data[idx+11:idx+150]
                name_bytes = []
                for i in range(0, min(len(snippet), 80), 2):
                    if snippet[i] == 0 and snippet[i+1] == 0:
                        break
                    if snippet[i+1] == 0:
                        name_bytes.append(snippet[i])
                if name_bytes:
                    product = bytes(name_bytes).decode('ascii', errors='ignore').strip()
                    if product and len(product) > 2:
                        return f"Executable: {product}"
            return "Windows PE Executable"
        
        elif file_type == "jpg":
            # Check for JFIF or EXIF
            if b"JFIF" in data[:20]:
                return "JPEG Image (JFIF)"
            elif b"Exif" in data[:100]:
                return "JPEG Image with EXIF metadata"
            return "JPEG Image"
        
        elif file_type == "png":
            return "PNG Image"
        
        elif file_type == "bat":
            # Try to find what the batch file does
            content = data[:1000].decode('ascii', errors='ignore').lower()
            if 'install' in content:
                return "Batch script (installer/setup)"
            elif 'backup' in content:
                return "Batch script (backup)"
            elif 'delete' in content or 'del ' in content:
                return "Batch script (cleanup/deletion)"
            return "Batch script"
        
        elif file_type == "ps1":
            content = data[:1000].decode('utf-8', errors='ignore')
            if 'function ' in content.lower():
                return "PowerShell script with functions"
            return "PowerShell script"
        
        elif file_type == "pf":
            # Prefetch files contain executable name
            try:
                # Prefetch file format: executable name at offset 0x10, UTF-16LE
                name_bytes = []
                for i in range(0x10, min(0x10 + 60, len(data)), 2):
                    if data[i] == 0 and data[i+1] == 0:
                        break
                    if data[i+1] == 0:
                        name_bytes.append(data[i])
                if name_bytes:
                    exe_name = bytes(name_bytes).decode('ascii', errors='ignore')
                    return f"Prefetch: {exe_name}"
            except:
                pass
            return "Windows Prefetch file"
    
    except Exception:
        pass
    
    return f"{file_type.upper()} file"


def carve(
    drive_letter: str,
    out_dir: str,
    max_bytes: int = 1024 * 1024 * 1024,
    log_callback=print,
    device_mode: bool = True,
    add_finding=None,
    stop_event=None,
):
    """
    Carve deleted files from drive with enhanced filename recovery.
    """
    os.makedirs(out_dir, exist_ok=True)
    for ext in ["jpg", "png", "exe", "ps1", "txt", "pf", "bat"]:
        os.makedirs(os.path.join(out_dir, ext), exist_ok=True)

    target = None
    prefix = f"{drive_letter}_device"
    
    if device_mode:
        target = f"\\\\.\\{drive_letter}:"
    else:
        target = None

    if target:
        try:
            with open(target, "rb", buffering=1024 * 1024) as f:
                log_callback(f"[i] Scanning raw device {target} (up to {max_bytes} bytes)...")
                scan_stream(f, out_dir, max_bytes, log_callback, add_finding, prefix, stop_event)
                return
        except Exception as e:
            log_callback(f"[!] Could not open raw device {target}: {e}")

    # Fallback mode
    root_path = Path(f"{drive_letter}:\\")
    log_callback(f"[i] Fallback scanning files under {root_path} (no unallocated data).")

    for p in root_path.rglob("*"):
        if stop_event and stop_event.is_set():
            log_callback("[!] Carving stopped by user.")
            return
            
        try:
            if p.is_file():
                safe_name = "".join(c for c in p.name if c.isalnum() or c in "._-")[:50]
                with open(p, "rb", buffering=512 * 1024) as f:
                    scan_stream(
                        f, out_dir, 50 * 1024 * 1024,
                        log_callback, add_finding, safe_name, stop_event
                    )
        except Exception:
            continue


def scan_stream(
    f,
    out_dir: str,
    max_bytes: int,
    log_callback=print,
    add_finding=None,
    prefix: str = "carve",
    stop_event=None,
):
    read = 0
    bufsize = 1024 * 1024
    window = b""

    idx = {
        "jpg": 0, "png": 0, "exe": 0,
        "pf": 0, "txt": 0, "bat": 0, "ps1": 0,
    }

    global_offset = 0

    while read < max_bytes:
        if stop_event and stop_event.is_set():
            log_callback("[!] Carving stopped by user.")
            return
            
        chunk = f.read(bufsize)
        if not chunk:
            break

        window += chunk
        read += len(chunk)

        def register_carved_file(ext: str, data: bytes, file_id: int, offset_start: Optional[int]):
            # Try to extract original filename from content
            original_name = extract_filename_from_content(data, ext)
            
            # Calculate hashes for correlation
            md5_hash, sha1_hash = calculate_file_hash(data)
            
            # Get file description
            description = get_file_description(data, ext)
            
            # Generate filename
            offset_hex = f"{offset_start:012X}" if isinstance(offset_start, int) else "unknown"
            
            if original_name:
                # Use recovered original name
                base_name = os.path.splitext(original_name)[0]
                outpath = os.path.join(out_dir, ext, f"{base_name}_recovered_at_{offset_hex}.{ext}")
                log_callback(f"[+] Carved {ext.upper()}: '{original_name}' (recovered name) at offset 0x{offset_hex}")
            else:
                # Use descriptive name
                outpath = os.path.join(out_dir, ext, f"{prefix}_{ext}_{file_id:04d}_at_{offset_hex}.{ext}")
                log_callback(f"[+] Carved {ext.upper()}: {description} at offset 0x{offset_hex} ({len(data)} bytes)")
            
            with open(outpath, "wb") as o:
                o.write(data)

            if add_finding:
                fobj = Finding(
                    id=f"CARVE-{ext.upper()}-{file_id:06d}",
                    module=Module.CARVING,
                    indicator_type=IndicatorType.CARVED_FILE,
                    severity=Severity.LOW,
                    resource_type="file_fragment",
                    file_path=outpath,
                    related_artifact=None,
                    evidence_summary=f"Recovered: {original_name or description}" if original_name else f"Recovered deleted {ext.upper()} file",
                    details={
                        "file_type": ext,
                        "size_bytes": len(data),
                        "offset_start": offset_start,
                        "offset_hex": offset_hex,
                        "source_prefix": prefix,
                        "recovered_filename": original_name,
                        "file_description": description,
                        "md5": md5_hash,
                        "sha1": sha1_hash,
                    },
                    tags=["carve", "unallocated"] + (["filename_recovered"] if original_name else []),
                )
                add_finding(finalize_finding(fobj))

        # -------------------- JPG --------------------
        start, end = MAGICS["jpg"]
        si = window.find(start)
        while si != -1:
            ei = window.find(end, si + len(start))
            if ei != -1:
                data = window[si:ei + len(end)]
                offset = global_offset + si
                register_carved_file("jpg", data, idx["jpg"], offset)
                idx["jpg"] += 1
                window = window[ei + len(end):]
                si = window.find(start)
            else:
                window = window[-1024 * 1024:]
                break

        # -------------------- PNG --------------------
        start, end = MAGICS["png"]
        si = window.find(start)
        while si != -1:
            ei = window.find(end, si + len(start))
            if ei != -1:
                data = window[si:ei + len(end)]
                offset = global_offset + si
                register_carved_file("png", data, idx["png"], offset)
                idx["png"] += 1
                window = window[ei + len(end):]
                si = window.find(start)
            else:
                window = window[-1024 * 1024:]
                break

        # -------------------- EXE --------------------
        si = window.find(MAGICS["exe"][0])
        while si != -1:
            endpos = min(si + 1024 * 1024, len(window))
            data = window[si:endpos]
            offset = global_offset + si
            register_carved_file("exe", data, idx["exe"], offset)
            idx["exe"] += 1
            window = window[endpos:]
            si = window.find(MAGICS["exe"][0])

        # -------------------- PREFETCH --------------------
        si = window.find(PREFETCH_MAGIC)
        while si != -1:
            endpos = min(si + 512 * 1024, len(window))
            data = window[si:endpos]
            offset = global_offset + si
            register_carved_file("pf", data, idx["pf"], offset)
            idx["pf"] += 1
            window = window[endpos:]
            si = window.find(PREFETCH_MAGIC)

        # -------------------- SCRIPTS --------------------
        for sig in PS1_SIGNATURES:
            si = window.find(sig)
            if si != -1:
                max_script_len = 50000
                endpos = min(si + max_script_len, len(window))
                data = window[si:endpos]
                
                ps_count = sum(1 for s in PS1_SIGNATURES if s in data)
                if ps_count >= 2:
                    offset = global_offset + si
                    register_carved_file("ps1", data, idx["ps1"], offset)
                    idx["ps1"] += 1
                    window = window[endpos:]
                    break
        
        for sig in BAT_SIGNATURES:
            si = window.find(sig)
            if si != -1:
                max_script_len = 10000
                endpos = min(si + max_script_len, len(window))
                data = window[si:endpos]
                
                bat_count = sum(1 for s in BAT_SIGNATURES if s in data)
                has_batch_chars = (
                    b"%" in data or b"goto " in data.lower() or
                    b"if " in data.lower() or b"for " in data.lower()
                )
                
                if bat_count >= 2 or (bat_count >= 1 and has_batch_chars):
                    offset = global_offset + si
                    register_carved_file("bat", data, idx["bat"], offset)
                    idx["bat"] += 1
                    window = window[endpos:]
                    break

        global_offset += len(chunk)
        
        if len(window) > 2 * 1024 * 1024:
            window = window[-2 * 1024 * 1024:]

    log_callback("[=] Carving pass complete.")