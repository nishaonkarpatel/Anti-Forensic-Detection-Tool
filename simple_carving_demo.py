# simple_carving_demo.py

import os
import sys
from pathlib import Path

# Setup path to import your modules
sys.path.insert(0, str(Path(__file__).parent))

from carving import scan_stream

# Track findings
findings = []

def log_msg(msg):
    """Simple logger."""
    print(msg)

def save_finding(finding):
    """Save finding to list."""
    findings.append(finding)
    print(f"    ✓ FOUND: {finding.evidence_summary}")

# ============================================================
# STEP 1: Create a demo "disk image" with embedded files
# ============================================================

def create_demo_disk():
    """
    Create a binary file that simulates a disk with deleted files.
    This is like what would be on unallocated disk space.
    """
    print("\n" + "="*70)
    print("STEP 1: Creating simulated disk image with 'deleted' files")
    print("="*70)
    
    # A minimal valid JPEG image (1x1 red pixel) - 164 bytes
    # This is what a real deleted JPEG would look like in raw disk data
    jpeg_data = bytes([
        # JPEG Start of Image + JFIF header
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
        0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00,
        # Quantization Table
        0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06,
        0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B,
        0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D,
        0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C,
        0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34,
        0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32,
        # Start of Frame
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00,
        0x01, 0x01, 0x01, 0x11, 0x00,
        # Start of Scan
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
        0x3F, 0x00, 0xD2, 0xCF, 0x20,
        # End of Image marker (this is what carver looks for!)
        0xFF, 0xD9
    ])
    
    # Some "deleted" text files
    text_file_1 = b"""This is a secret document that was deleted!
It contains important information that needs to be recovered.
The file was removed from the system but data remains on disk.
This is exactly what file carving can recover.
""" * 3  # Repeat to make it longer
    
    text_file_2 = b"""CONFIDENTIAL MEMO
Date: 2024-12-01
From: Admin
To: All Staff

This document was supposedly deleted but we can recover it!
File carving works by finding file signatures in raw disk data.
""" * 3
    
    # Create a "disk image" - mix of deleted files and garbage
    # This simulates what raw disk sectors look like
    disk_image = b""
    
    # Sector 0-100: Empty space (zeros)
    disk_image += b"\x00" * 5000
    
    # Sector 101-150: Random garbage (old data)
    disk_image += b"JUNKDATA" * 500
    
    # Sector 151: DELETED JPEG STARTS HERE
    disk_image += jpeg_data
    
    # More garbage
    disk_image += b"\xFF\xAA\x55" * 300
    
    # Sector 200: DELETED TEXT FILE 1
    disk_image += text_file_1
    
    # More garbage
    disk_image += b"\x00" * 2000
    
    # Sector 300: ANOTHER JPEG (simulate multiple deleted images)
    disk_image += jpeg_data
    
    # Garbage
    disk_image += b"\xDE\xAD\xBE\xEF" * 200
    
    # Sector 400: DELETED TEXT FILE 2
    disk_image += text_file_2
    
    # Final empty sectors
    disk_image += b"\x00" * 3000
    
    # Save the "disk image"
    os.makedirs("demo_output", exist_ok=True)
    disk_path = "demo_output/simulated_disk.bin"
    
    with open(disk_path, "wb") as f:
        f.write(disk_image)
    
    print(f"\n✓ Created simulated disk: {disk_path}")
    print(f"  Size: {len(disk_image):,} bytes")
    print(f"  Contains:")
    print(f"    - 2 deleted JPEG images ({len(jpeg_data)} bytes each)")
    print(f"    - 2 deleted text documents")
    print(f"    - Random 'garbage' data (simulating old/unallocated space)")
    print(f"\n  This file simulates what a real disk looks like with deleted files!")
    
    return disk_path

# ============================================================
# STEP 2: Run carving to recover the deleted files
# ============================================================

def run_carving(disk_path):
    """
    Scan the disk image and carve out deleted files.
    """
    print("\n" + "="*70)
    print("STEP 2: Running file carving to recover deleted files")
    print("="*70)
    print("\nCarving process started...\n")
    
    output_dir = "demo_output/recovered_files"
    
    # Open the disk image and scan it
    with open(disk_path, "rb") as disk:
        scan_stream(
            f=disk,
            out_dir=output_dir,
            max_bytes=100 * 1024 * 1024,  # Scan up to 100 MB
            log_callback=log_msg,
            add_finding=save_finding,
            prefix="recovered"
        )
    
    print("\n" + "="*70)
    print("STEP 3: Carving complete!")
    print("="*70)
    
    # Show what was recovered
    print(f"\n✓ Recovered files saved to: {output_dir}/")
    print(f"✓ Total files carved: {len(findings)}")
    
    if findings:
        print("\n📁 Recovered files:")
        for finding in findings:
            file_type = finding.details.get('file_type', 'unknown').upper()
            size = finding.details.get('size_bytes', 0)
            offset = finding.details.get('offset_start', 0)
            path = finding.file_path
            
            print(f"\n  {file_type} file:")
            print(f"    Location: {path}")
            print(f"    Size: {size:,} bytes")
            print(f"    Found at disk offset: 0x{offset:X} ({offset:,} bytes)")
    
    return output_dir

# ============================================================
# STEP 3: Verify the recovered files
# ============================================================

def verify_recovered_files(output_dir):
    """
    Check what we recovered and verify it worked.
    """
    print("\n" + "="*70)
    print("STEP 4: Verification - What did we recover?")
    print("="*70)
    
    # Check JPG files
    jpg_dir = Path(output_dir) / "jpg"
    if jpg_dir.exists():
        jpg_files = list(jpg_dir.glob("*.jpg"))
        print(f"\n✓ Recovered {len(jpg_files)} JPEG image(s):")
        for jpg in jpg_files:
            size = jpg.stat().st_size
            print(f"  - {jpg.name} ({size} bytes)")
            print(f"    You can open this file in any image viewer!")
    
    # Check TXT files
    txt_dir = Path(output_dir) / "txt"
    if txt_dir.exists():
        txt_files = list(txt_dir.glob("*.txt"))
        print(f"\n✓ Recovered {len(txt_files)} text document(s):")
        for txt in txt_files:
            size = txt.stat().st_size
            print(f"  - {txt.name} ({size} bytes)")
            
            # Show preview of recovered text
            try:
                with open(txt, 'r', encoding='utf-8', errors='ignore') as f:
                    preview = f.read(100).replace('\n', ' ')
                    if len(preview) > 80:
                        preview = preview[:77] + "..."
                    print(f"    Preview: \"{preview}\"")
            except:
                pass
    
    print("\n" + "="*70)
    print("DEMO COMPLETE!")
    print("="*70)
    print("\n✓ File carving successfully recovered deleted files from disk image!")
    print(f"✓ All recovered files are in: {output_dir}/")
    print("\nYou can now:")
    print("  1. Open the recovered JPG files in an image viewer")
    print("  2. Read the recovered TXT files in a text editor")
    print("  3. Examine the simulated disk image: demo_output/simulated_disk.bin")

# ============================================================
# MAIN EXECUTION
# ============================================================

def main():
    """
    Run the complete carving demonstration.
    """
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "AFDT FILE CARVING DEMONSTRATION" + " "*22 + "║")
    print("╚" + "="*68 + "╝")
    print("\nThis demo will:")
    print("  1. Create a simulated disk image with 'deleted' files")
    print("  2. Run file carving to recover the deleted files")
    print("  3. Show you what was recovered")
    print("\nNo real images needed - everything is created automatically!")
    
    input("\nPress ENTER to start the demo...")
    
    # Step 1: Create the disk image
    disk_path = create_demo_disk()
    
    # Step 2: Run carving
    output_dir = run_carving(disk_path)
    
    # Step 3: Verify results
    verify_recovered_files(output_dir)
    
    print("\n")

if __name__ == "__main__":
    main()