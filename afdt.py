#afdt.py
import os
import threading
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from analysis import (
    check_event_log_tamper,
    find_log_deletions,
    count_events_by_date_range,
    run_mftecmd_and_detect_timestomp,
    inspect_recycle_bin,
    check_vss_presence,
    detect_anti_forensic_apps,
    # folder-mode helpers:
    check_event_log_tamper_folder,
    find_log_deletions_folder,
    count_events_by_date_range_folder,
    inspect_recycle_bin_folder,
)

from carving import carve
from findings import Finding
from reporting import (
    generate_html_report,
    export_to_csv,
    export_to_json,
    export_to_markdown,
)
from stego_module import scan_images_for_stego
from dashboard import DashboardWindow


APP_NAME = "AFDT – Anti Forensic Detection Tool"
LOG_DIR = "logs"
TOOLS_DIR = "tools"
SIG_PATH = os.path.join("signatures", "anti_forensics.json")


class Logger:
    def __init__(self, textbox: scrolledtext.ScrolledText):
        self.textbox = textbox
        ts = datetime.datetime.now().strftime("%Y-%m-%dT%H_%M_%S")
        os.makedirs(LOG_DIR, exist_ok=True)
        self.temp_path = os.path.join(LOG_DIR, "afdt_temp.log")
        self.final_path = os.path.join(LOG_DIR, f"afdt_{ts}.log")
        # reset temp
        open(self.temp_path, "w", encoding="utf-8").close()

    def log(self, msg: str):
        line = msg if msg.endswith("\n") else msg + "\n"
        try:
            self.textbox.insert(tk.END, line)
            self.textbox.see(tk.END)
            with open(self.temp_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            # GUI might be gone, or file error – ignore for now
            pass

    def finalize(self):
        try:
            with open(self.temp_path, "r", encoding="utf-8") as src, open(
                self.final_path, "w", encoding="utf-8"
            ) as dst:
                dst.write(src.read())
        except Exception:
            pass


# ============================================================
# STANDALONE HELPER FUNCTIONS (moved outside class)
# ============================================================

def scan_folder_for_timestomp(folder_path, log_callback=print, add_finding=None):
    """
    Scan folder for timestamp inconsistencies (modified < created).
    """
    import os
    import datetime
    from findings import Finding, Module, Severity, IndicatorType, finalize_finding

    log_callback("[i] (folder mode) Running basic timestomp heuristic...")

    suspicious_count = 0
    try:
        for root, dirs, files in os.walk(folder_path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    stats = os.stat(fp)
                    created = datetime.datetime.fromtimestamp(stats.st_ctime)
                    modified = datetime.datetime.fromtimestamp(stats.st_mtime)

                    if modified < created:
                        suspicious_count += 1
                        log_callback(f"[!] (folder mode) Suspicious timestamp: {fp}")
                        
                        if add_finding:
                            finding = Finding(
                                id=f"TIMESTOMP-{suspicious_count:06d}",
                                module=Module.MFT,
                                indicator_type=IndicatorType.TIMESTAMP_MISMATCH_LARGE,
                                severity=Severity.MEDIUM,
                                resource_type="file",
                                file_path=fp,
                                related_artifact=None,
                                evidence_summary=f"File modified time is earlier than created time",
                                details={
                                    "created_time": created.isoformat(),
                                    "modified_time": modified.isoformat(),
                                    "delta_seconds": (created - modified).total_seconds(),
                                    "reason": "Modified timestamp predates creation timestamp"
                                },
                                tags=["timestomp", "suspicious_timestamp"],
                            )
                            add_finding(finalize_finding(finding))
                            
                except Exception as e:
                    log_callback(f"[!] Could not read timestamps for {fp}: {e}")

        log_callback(f"[+] (folder mode) Timestomp scan completed. Found {suspicious_count} suspicious files.")
    except Exception as e:
        log_callback(f"[!] Error in timestomp scan: {e}")


def scan_for_suspicious_files(folder_path, log_callback=print, add_finding=None):
    """
    Scan for suspicious files: double extensions, embedded payloads, very large files.
    """
    import os
    from findings import Finding, Module, Severity, IndicatorType, finalize_finding

    log_callback("[i] (folder mode) Scanning for suspicious files...")

    suspect_ext_patterns = [
        (".jpg.exe", "Image masquerading as EXE"),
        (".png.exe", "Image masquerading as EXE"),
        (".txt.exe", "TXT masquerading as EXE"),
        (".pdf.exe", "PDF masquerading as EXE"),
        (".doc.exe", "DOC masquerading as EXE"),
    ]

    suspicious_count = 0
    try:
        for root, dirs, files in os.walk(folder_path):
            for f in files:
                fp = os.path.join(root, f)

                # 1) double-extension check
                lower = f.lower()
                for pattern, reason in suspect_ext_patterns:
                    if lower.endswith(pattern):
                        suspicious_count += 1
                        log_callback(f"[!] Suspicious file: {fp} – {reason}")
                        
                        if add_finding:
                            finding = Finding(
                                id=f"SUSPICIOUS-{suspicious_count:06d}",
                                module=Module.ANTI_FORENSICS,
                                indicator_type=IndicatorType.ANTIFORENSIC_TOOL,
                                severity=Severity.HIGH,
                                resource_type="file",
                                file_path=fp,
                                related_artifact=None,
                                evidence_summary=reason,
                                details={
                                    "filename": f,
                                    "pattern_matched": pattern,
                                    "reason": reason
                                },
                                tags=["suspicious_extension", "masquerading"],
                            )
                            add_finding(finalize_finding(finding))

                # 2) check for ASCII payload at end (like stego image)
                try:
                    with open(fp, "rb") as fh:
                        data = fh.read()

                        # scan last 200 bytes for plaintext ASCII
                        if len(data) > 200:
                            tail = data[-200:]
                            # Count printable ASCII characters
                            printable_count = sum(1 for b in tail if 32 <= b <= 126)
                            
                            if printable_count > 150:  # >75% printable
                                suspicious_count += 1
                                text_tail = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in tail[-50:])
                                log_callback(f"[!] Stego-like ASCII data found in {fp} | tail preview: {text_tail}")
                                
                                if add_finding:
                                    finding = Finding(
                                        id=f"STEGO-ASCII-{suspicious_count:06d}",
                                        module=Module.STEGO,
                                        indicator_type=IndicatorType.STEGO_TEXT_PAYLOAD,
                                        severity=Severity.MEDIUM,
                                        resource_type="file",
                                        file_path=fp,
                                        related_artifact=None,
                                        evidence_summary="File contains suspicious ASCII data at end",
                                        details={
                                            "tail_preview": text_tail,
                                            "printable_ratio": printable_count / len(tail)
                                        },
                                        tags=["stego", "embedded_data"],
                                    )
                                    add_finding(finalize_finding(finding))
                except:
                    pass

                # 3) huge file heuristic
                try:
                    size_mb = os.path.getsize(fp) / (1024 * 1024)
                    if size_mb > 200:
                        log_callback(f"[!] Very large file (>{size_mb:.1f}MB): {fp}")
                        
                        if add_finding:
                            finding = Finding(
                                id=f"LARGE-FILE-{suspicious_count:06d}",
                                module=Module.ANTI_FORENSICS,
                                indicator_type=IndicatorType.ANTIFORENSIC_TOOL,
                                severity=Severity.LOW,
                                resource_type="file",
                                file_path=fp,
                                related_artifact=None,
                                evidence_summary=f"Very large file detected ({size_mb:.1f} MB)",
                                details={
                                    "size_mb": size_mb,
                                    "size_bytes": os.path.getsize(fp)
                                },
                                tags=["large_file"],
                            )
                            add_finding(finalize_finding(finding))
                except:
                    pass

        log_callback(f"[+] (folder mode) Suspicious file scan completed. Found {suspicious_count} issues.")
    except Exception as e:
        log_callback(f"[!] Error during suspicious file scan: {e}")


# ============================================================
# MAIN APPLICATION CLASS
# ============================================================

class AFDTApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(APP_NAME)
        root.geometry("980x640")

        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None

        # In-memory collection of structured findings
        self.findings: list[Finding] = []

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Inputs
        row = 0
        ttk.Label(frm, text="Start Date (YYYY-MM-DD HH:MM:SS):").grid(
            column=0, row=row, sticky="w"
        )
        self.start_var = tk.StringVar(value="2024-01-01 00:00:00")
        ttk.Entry(frm, textvariable=self.start_var, width=26).grid(
            column=1, row=row, sticky="w"
        )

        ttk.Label(frm, text="End Date (YYYY-MM-DD HH:MM:SS):").grid(
            column=2, row=row, sticky="w", padx=(20, 0)
        )
        self.end_var = tk.StringVar(
            value=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        ttk.Entry(frm, textvariable=self.end_var, width=26).grid(
            column=3, row=row, sticky="w"
        )

        row += 1
        ttk.Label(
            frm,
            text='Target (Drive letter like "E" OR full folder path):',
        ).grid(column=0, row=row, sticky="w", pady=(8, 0))

        # keep name drive_var for backward compatibility, but now it may hold a folder path
        self.drive_var = tk.StringVar(value="E")
        ttk.Entry(frm, textvariable=self.drive_var, width=40).grid(
            column=1, row=row, sticky="w", pady=(8, 0)
        )

        ttk.Label(frm, text="Tools Dir:").grid(
            column=2, row=row, sticky="w", padx=(20, 0), pady=(8, 0)
        )
        self.tools_var = tk.StringVar(value=TOOLS_DIR)
        ttk.Entry(frm, textvariable=self.tools_var, width=30).grid(
            column=3, row=row, sticky="w", pady=(8, 0)
        )

        # Action buttons
        row += 1
        btn_start = ttk.Button(frm, text="Start Analysis", command=self.on_start)
        btn_start.grid(column=0, row=row, pady=10, sticky="w")

        btn_carve = ttk.Button(frm, text="Carving", command=self.on_carve)
        btn_carve.grid(column=1, row=row, pady=10, sticky="w")

        btn_stop = ttk.Button(frm, text="Stop", command=self.on_stop)
        btn_stop.grid(column=2, row=row, pady=10, sticky="w")

        btn_about = ttk.Button(frm, text="About", command=self.on_about)
        btn_about.grid(column=3, row=row, pady=10, sticky="w")

        row += 1
        btn_dashboard = ttk.Button(frm, text="View Dashboard", command=self.on_dashboard)
        btn_dashboard.grid(column=0, row=row, pady=10, sticky="w")

        btn_report = ttk.Button(frm, text="Export Report", command=self.on_export_report)
        btn_report.grid(column=1, row=row, pady=10, sticky="w")

        # Log text area
        row += 1
        self.text = scrolledtext.ScrolledText(frm, wrap=tk.WORD, height=25)
        self.text.grid(column=0, row=row, columnspan=4, sticky="nsew", pady=(10, 0))

        frm.rowconfigure(row, weight=1)
        frm.columnconfigure(3, weight=1)

        self.logger = Logger(self.text)

    # ------------------------------------------------------------------
    # Findings hook
    # ------------------------------------------------------------------
    def add_finding(self, finding: Finding):
        """
        Called by analysis modules to register a structured finding.
        """
        self.findings.append(finding)
        # Also log a short line so user sees something in real time
        self.logger.log(
            f"[F] {finding.executive_summary_bullet or finding.evidence_summary}"
        )

    # ------------------------------------------------------------------
    # GUI actions
    # ------------------------------------------------------------------
    def parse_dates(self) -> tuple[datetime.datetime, datetime.datetime]:
        s = datetime.datetime.strptime(self.start_var.get(), "%Y-%m-%d %H:%M:%S")
        e = datetime.datetime.strptime(self.end_var.get(), "%Y-%m-%d %H:%M:%S")
        return s, e

    def on_start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("AFDT", "An operation is already running.")
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._run_analysis, daemon=True)
        self.worker.start()

    def on_carve(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("AFDT", "An operation is already running.")
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._run_carving, daemon=True)
        self.worker.start()

    def on_stop(self):
        self.stop_event.set()
        self.logger.log(
            "[i] Stop requested. Current operation will halt ASAP and logs will be finalized."
        )

    def on_about(self):
        messagebox.showinfo(
            "About AFDT",
            "AFDT – Anti Forensic Detection Tool\nVersion 0.1.0\nAuthor: You\n© 2025",
        )

    def on_dashboard(self):
        """Show interactive dashboard with findings analysis"""
        if not self.findings:
            messagebox.showinfo("Dashboard", "No findings available. Run an analysis first.")
            return
        
        try:
            case_meta = {
                "Case Name": "AFDT Analysis",
                "Target": self.drive_var.get(),
                "Start Date": self.start_var.get(),
                "End Date": self.end_var.get(),
                "Total Findings": len(self.findings),
                "Analysis Date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            DashboardWindow(self.root, self.findings, case_meta)
        except Exception as e:
            messagebox.showerror("Dashboard Error", f"Failed to open dashboard:\n{e}")

    def on_export_report(self):
        """Export findings to multiple formats with format selection"""
        if not self.findings:
            messagebox.showinfo("Export Report", "No findings to export. Run an analysis first.")
            return
        
        # Create export dialog
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Report")
        export_window.geometry("500x400")
        export_window.transient(self.root)
        export_window.grab_set()
        
        # Main container
        main_frame = ttk.Frame(export_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Select Export Format:", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Format selection with radio buttons
        format_var = tk.StringVar(value="html")
        
        formats = [
            ("HTML Report (Recommended)", "html", "Full featured HTML report with styling"),
            ("CSV Spreadsheet", "csv", "Import into Excel or other tools"),
            ("JSON Data", "json", "Machine-readable format"),
            ("Markdown Document", "md", "Plain text with formatting"),
        ]
        
        # Radio buttons frame
        radio_frame = ttk.Frame(main_frame)
        radio_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        for label, value, description in formats:
            frame_opt = ttk.Frame(radio_frame)
            frame_opt.pack(fill=tk.X, pady=8)
            
            rb = ttk.Radiobutton(frame_opt, text=label, variable=format_var, value=value)
            rb.pack(anchor=tk.W)
            
            ttk.Label(frame_opt, text=f"  {description}", foreground="#666", 
                    font=("Arial", 9)).pack(anchor=tk.W, padx=20)
        
        # Separator
        ttk.Separator(main_frame, orient="horizontal").pack(fill=tk.X, pady=10)
        
        # Button frame at the bottom
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        # Export button function
        def do_export():
            format_choice = format_var.get()
            export_window.destroy()
            self._export_report_format(format_choice)
        
        # Buttons
        ttk.Button(button_frame, text="Export", command=do_export, width=12).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=export_window.destroy, width=12).pack(side=tk.RIGHT)

    def _export_report_format(self, format_type: str):
        """Export report in the specified format"""
        try:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = f"afdt_report_{timestamp}"
            
            case_meta = {
                "Case Name": "AFDT Analysis",
                "Target": self.drive_var.get(),
                "Start Date": self.start_var.get(),
                "End Date": self.end_var.get(),
                "Total Findings": len(self.findings),
                "Analysis Date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            
            if format_type == "html":
                report_path = os.path.join(LOG_DIR, f"{base_name}.html")
                generate_html_report(self.findings, report_path, case_meta)
            elif format_type == "csv":
                report_path = os.path.join(LOG_DIR, f"{base_name}.csv")
                export_to_csv(self.findings, report_path)
            elif format_type == "json":
                report_path = os.path.join(LOG_DIR, f"{base_name}.json")
                export_to_json(self.findings, report_path)
            elif format_type == "md":
                report_path = os.path.join(LOG_DIR, f"{base_name}.md")
                export_to_markdown(self.findings, report_path, case_meta)
            else:
                messagebox.showerror("Error", f"Unknown format: {format_type}")
                return
            
            # Show success message with option to open file
            result = messagebox.askyesno(
                "Export Complete",
                f"Report exported successfully to:\n{report_path}\n\nOpen file location?",
                icon="info"
            )
            
            if result:
                import subprocess
                import platform
                
                # Open file explorer at the location
                if platform.system() == "Windows":
                    subprocess.run(["explorer", "/select,", os.path.abspath(report_path)])
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["open", "-R", report_path])
                else:  # Linux
                    subprocess.run(["xdg-open", os.path.dirname(report_path)])
                    
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")

    def _finalize(self):
        """Finalize logs and cleanup"""
        self.logger.finalize()
        self.logger.log("[=] Analysis complete. Logs finalized.")

    def _run_carving(self):
        """Run file carving operation"""
        target = self.drive_var.get().strip()
        if not target:
            self.logger.log("[!] No target provided.")
            return

        if len(target) == 1 and target.isalpha():
            drv = target.upper()
            self.logger.log(f"[i] Starting carving on drive {drv}:")
            carve(
                drive_letter=drv,
                out_dir="carved_output",
                max_bytes=1024 * 1024 * 1024,  # 1GB
                log_callback=self.logger.log,
                device_mode=True,
                add_finding=self.add_finding,
                stop_event=self.stop_event,  # ADDED: Pass stop_event
            )
        else:
            self.logger.log("[!] Carving requires a drive letter (e.g., 'E').")
        
        self._finalize()

    # ------------------------------------------------------------------
    # Core analysis pipeline (drive mode + folder mode)
    # ------------------------------------------------------------------
    def _run_analysis(self):
        self.findings.clear()

        target = self.drive_var.get().strip()
        if not target:
            self.logger.log("[!] No target provided.")
            return

        # -----------------------------------------
        # Determine mode (drive vs folder)
        # -----------------------------------------
        if len(target) == 1 and target.isalpha():
            drv = target.upper()
            root_path = Path(f"{drv}:\\")
            if not root_path.exists():
                self.logger.log("[!] Drive does not exist or is not accessible.")
                return
            mode = "drive"
            root = root_path
        else:
            root_path = Path(target)
            if not root_path.exists():
                self.logger.log(f"[!] Folder does not exist: {root_path}")
                return
            mode = "folder"
            root = root_path

        # -----------------------------------------
        # Parse dates
        # -----------------------------------------
        try:
            start, end = self.parse_dates()
        except Exception as e:
            self.logger.log(f"[!] Invalid date(s): {e}")
            return

        # ============================================================
        # DRIVE MODE
        # ============================================================
        if mode == "drive":
            self.logger.log(f"[=] Starting analysis for {drv}: from {start} to {end}")

            self.logger.log("[i] Checking EVTX tamper indicators...")
            check_event_log_tamper(drv, log_callback=self.logger.log, add_finding=self.add_finding)
            if self.stop_event.is_set(): return self._finalize()

            self.logger.log("[i] Checking for log deletions (Security 1102)...")
            find_log_deletions(drv, log_callback=self.logger.log, add_finding=self.add_finding)
            if self.stop_event.is_set(): return self._finalize()

            self.logger.log("[i] Counting events by date range...")
            count_events_by_date_range(drv, start, end, log_callback=self.logger.log)
            if self.stop_event.is_set(): return self._finalize()

            self.logger.log("[i] Running MFT timestomp analysis (MFTECmd)...")
            run_mftecmd_and_detect_timestomp(
                drv, self.tools_var.get(), LOG_DIR, log_callback=self.logger.log, add_finding=self.add_finding
            )
            if self.stop_event.is_set(): return self._finalize()

            self.logger.log("[i] Inspecting Recycle Bin...")
            inspect_recycle_bin(drv, log_callback=self.logger.log, add_finding=self.add_finding)
            if self.stop_event.is_set(): return self._finalize()

            self.logger.log("[i] Checking Volume Shadow Copy artifacts (heuristic)...")
            check_vss_presence(drv, log_callback=self.logger.log, add_finding=self.add_finding)
            if self.stop_event.is_set(): return self._finalize()

            self.logger.log("[i] Scanning for anti-forensic apps (signatures)...")
            detect_anti_forensic_apps(drv, SIG_PATH, log_callback=self.logger.log, add_finding=self.add_finding)

            return self._finalize()

        # ============================================================
        # FOLDER MODE
        # ============================================================
        else:
            self.logger.log(f"[=] Starting analysis in FOLDER MODE on {root} from {start} to {end}")

            # EVTX tamper
            self.logger.log("[i] (folder mode) Checking EVTX tamper indicators...")
            check_event_log_tamper_folder(str(root), log_callback=self.logger.log, add_finding=self.add_finding)
            if self.stop_event.is_set(): return self._finalize()

            # EVTX deletions
            self.logger.log("[i] (folder mode) Checking for log deletions (Security 1102)...")
            find_log_deletions_folder(str(root), log_callback=self.logger.log, add_finding=self.add_finding)
            if self.stop_event.is_set(): return self._finalize()

            # Event counts
            self.logger.log("[i] (folder mode) Counting events by date range...")
            count_events_by_date_range_folder(str(root), start, end, log_callback=self.logger.log)
            if self.stop_event.is_set(): return self._finalize()

            # Recycle Bin
            self.logger.log("[i] (folder mode) Inspecting Recycle Bin...")
            inspect_recycle_bin_folder(str(root), log_callback=self.logger.log)
            if self.stop_event.is_set(): return self._finalize()

            # -------------------------------------------------------
            # STEGO SCAN
            # -------------------------------------------------------
            self.logger.log("[i] (folder mode) Running steganography scan...")
            self.logger.log(f"[DEBUG] Stego scan target folder: {root}")
            self.logger.log(f"[DEBUG] Output dir: C:\\stego_output")
            try:
                scan_images_for_stego(
                    drive_letter=None,
                    out_dir="stego_out",
                    log_callback=self.logger.log,
                    add_finding=self.add_finding,
                    max_files=5000,
                    folder_override=str(root),
                )
                self.logger.log("[DEBUG] Stego scan completed")
            except Exception as e:
                self.logger.log(f"[!] Stego scan failed: {e}")
                import traceback
                self.logger.log(f"[!] Traceback: {traceback.format_exc()}")
            if self.stop_event.is_set(): return self._finalize()

            # -------------------------------------------------------
            # TIMESTOMP DETECTION
            # -------------------------------------------------------
            self.logger.log("[i] (folder mode) Checking for timestamp inconsistencies...")
            try:
                scan_folder_for_timestomp(str(root), log_callback=self.logger.log, add_finding=self.add_finding)
            except Exception as e:
                self.logger.log(f"[!] Timestamp scan failed: {e}")
            if self.stop_event.is_set(): return self._finalize()

            # -------------------------------------------------------
            # SUSPICIOUS FILES
            # -------------------------------------------------------
            self.logger.log("[i] (folder mode) Scanning for suspicious files...")
            try:
                scan_for_suspicious_files(str(root), log_callback=self.logger.log, add_finding=self.add_finding)
            except Exception as e:
                self.logger.log(f"[!] Suspicious file scan failed: {e}")
            if self.stop_event.is_set(): return self._finalize()

            return self._finalize()

#---------------------------------------------------------------------------------------------------
def main():
    root = tk.Tk()
    app = AFDTApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()