# dashboard.py - Redesigned with modern table-based interface
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import List, Dict, Any
from collections import Counter
import datetime

from findings import Finding, Severity, Module


class DashboardWindow:
    """Modern dashboard with table-based interface matching specification."""
    
    def __init__(self, parent: tk.Tk, findings: List[Finding], case_meta: Dict[str, Any]):
        self.findings = findings
        self.case_meta = case_meta
        
        # Create main window
        self.window = tk.Toplevel(parent)
        self.window.title("TraceHunter Dashboard")
        self.window.geometry("1400x900")
        
        # Create main container with split view
        # Use tk.PanedWindow instead of ttk.PanedWindow for better sash control
        self.main_paned = tk.PanedWindow(
            self.window, 
            orient=tk.HORIZONTAL,
            sashwidth=8,
            sashrelief=tk.RAISED,
            bg='#d0d0d0'
        )
        self.main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left side: findings table
        self.left_frame = ttk.Frame(self.main_paned)
        self.main_paned.add(self.left_frame, width=900)
        
        # Right side: detail panel (initially hidden)
        self.right_frame = ttk.Frame(self.main_paned)
        self.detail_visible = False
        
        self._create_header()
        self._create_filter_bar()
        self._create_findings_table()
        self._create_status_bar()
        
    def _setup_sash_highlighting(self):
        """Setup visual feedback for sash dragging."""
        # The sash becomes draggable automatically with PanedWindow
        # Add visual cursor change hint
        self.main_paned.bind('<Enter>', lambda e: self._update_cursor_on_sash(e))
        self.main_paned.bind('<Motion>', lambda e: self._update_cursor_on_sash(e))
        self.main_paned.bind('<Leave>', lambda e: self.main_paned.config(cursor=""))
    
    def _update_cursor_on_sash(self, event):
        """Change cursor when hovering over sash."""
        # Check if mouse is near sash (within 10 pixels)
        try:
            sash_coord = self.main_paned.sash_coord(0)
            if abs(event.x - sash_coord[0]) < 10:
                self.main_paned.config(cursor="sb_h_double_arrow")
            else:
                self.main_paned.config(cursor="")
        except:
            # Sash doesn't exist yet (detail panel not shown)
            pass
    
    def _create_header(self):
        """Create header with case information."""
        header = ttk.Frame(self.left_frame)
        header.pack(fill=tk.X, padx=10, pady=5)
        
        # Title
        title = ttk.Label(header, text="🔍 Findings Analysis", 
                         font=("Arial", 16, "bold"))
        title.pack(anchor=tk.W)
        
        # Case info row
        info_text = f"Case: {self.case_meta.get('Case Name', 'N/A')} | Target: {self.case_meta.get('Target', 'N/A')} | Total Findings: {len(self.findings)}"
        info_label = ttk.Label(header, text=info_text, font=("Arial", 9))
        info_label.pack(anchor=tk.W, pady=(2, 0))
        
    def _create_filter_bar(self):
        """Create filter controls."""
        filter_frame = ttk.Frame(self.left_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Filter by severity
        ttk.Label(filter_frame, text="Severity:").pack(side=tk.LEFT, padx=(0, 5))
        self.severity_filter = ttk.Combobox(
            filter_frame, 
            values=["All", "HIGH", "MEDIUM", "LOW"],
            state="readonly", 
            width=10
        )
        self.severity_filter.set("All")
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        
        # Filter by module
        ttk.Label(filter_frame, text="Module:").pack(side=tk.LEFT, padx=(10, 5))
        modules = ["All"] + sorted(list(set(f.module.upper() for f in self.findings)))
        self.module_filter = ttk.Combobox(
            filter_frame,
            values=modules,
            state="readonly",
            width=15
        )
        self.module_filter.set("All")
        self.module_filter.pack(side=tk.LEFT, padx=5)
        
        # Apply button
        ttk.Button(filter_frame, text="Apply", command=self._apply_filters).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear", command=self._clear_filters).pack(side=tk.LEFT)
        
        # Search box
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<Return>', lambda e: self._apply_filters())
        
    def _create_findings_table(self):
        """Create main findings table."""
        table_frame = ttk.Frame(self.left_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal")
        
        # Create treeview with columns matching the specification
        self.tree = ttk.Treeview(
            table_frame,
            columns=("sev", "module", "indicator", "resource", "summary", "time"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Configure columns
        self.tree.heading("sev", text="Sev")
        self.tree.heading("module", text="Module")
        self.tree.heading("indicator", text="Indicator")
        self.tree.heading("resource", text="Resource")
        self.tree.heading("summary", text="Summary")
        self.tree.heading("time", text="Time")
        
        self.tree.column("sev", width=50, anchor="center")
        self.tree.column("module", width=100)
        self.tree.column("indicator", width=200)
        self.tree.column("resource", width=150)
        self.tree.column("summary", width=400)
        self.tree.column("time", width=150)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        
        # Bind click event
        self.tree.bind("<ButtonRelease-1>", self._on_row_click)
        
        # Configure severity colors
        self.tree.tag_configure("HIGH", foreground="#d32f2f")
        self.tree.tag_configure("MEDIUM", foreground="#f57c00")
        self.tree.tag_configure("LOW", foreground="#388e3c")
        
        # Populate table
        self._populate_table()
        
    def _populate_table(self, filtered_findings=None):
        """Populate the findings table."""
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        findings = filtered_findings if filtered_findings is not None else self.findings
        
        # Sort by priority score (descending)
        sorted_findings = sorted(findings, key=lambda f: f.priority_score, reverse=True)
        
        for f in sorted_findings:
            # Severity indicator (using color)
            sev_display = "●" if f.severity == "high" else ("◐" if f.severity == "medium" else "○")
            
            # Module name
            module = f.module.upper()
            
            # Indicator (humanized from indicator_type)
            indicator = self._humanize_indicator(f.indicator_type)
            
            # Resource (last part of path)
            resource = self._extract_filename(f.file_path)
            
            # Summary (truncated)
            summary = f.evidence_summary
            if len(summary) > 80:
                summary = summary[:77] + "..."
            
            # Time
            time_str = f.created_at.strftime("%Y-%m-%d %H:%M:%S") if f.created_at else ""
            
            self.tree.insert(
                "", 
                "end",
                values=(sev_display, module, indicator, resource, summary, time_str),
                tags=(f.severity.upper(),)
            )
            
            # Store finding reference
            self.tree.item(self.tree.get_children()[-1], tags=(f.severity.upper(), f.id))
    
    def _humanize_indicator(self, indicator_type: str) -> str:
        """Convert indicator_type to human-readable format."""
        mappings = {
            "timestamp_mismatch_large_delta": "Timestamp mismatch (large delta)",
            "eventlog_cleared": "Eventlog cleared",
            "eventlog_service_stopped": "Eventlog service stopped",
            "stego_suspicious_image": "Stego: suspicious image",
            "stego_text_payload_detected": "Stego: text payload",
            "stego_code_like_payload_detected": "Stego: code-like payload",
            "anti_forensic_tool_detected": "Anti-forensic tool",
            "deleted_file_record": "Deleted file record",
            "recovered_deleted_file": "Recovered deleted file",
            "shadow_copy_present": "Shadow copy present"
        }
        return mappings.get(indicator_type, indicator_type)
    
    def _extract_filename(self, path: str) -> str:
        """Extract filename from path."""
        if not path:
            return ""
        return path.replace("\\", "/").split("/")[-1]
    
    def _on_row_click(self, event):
        """Handle row click to show detail panel."""
        selection = self.tree.selection()
        if not selection:
            return
        
        # Get finding ID from tags
        tags = self.tree.item(selection[0], "tags")
        finding_id = tags[1] if len(tags) > 1 else None
        
        if finding_id:
            finding = next((f for f in self.findings if f.id == finding_id), None)
            if finding:
                self._show_detail_panel(finding)
    
    def _show_detail_panel(self, finding: Finding):
        """Show detail panel for selected finding."""
        # Add right panel if not visible
        if not self.detail_visible:
            # Add panel with weight for resizing
            self.main_paned.add(self.right_frame, width=500)
            self.detail_visible = True
            
            # Set initial sash position (60% left, 40% right)
            self.window.update_idletasks()
            total_width = self.main_paned.winfo_width()
            self.main_paned.sash_place(0, int(total_width * 0.6), 0)
        
        # Clear previous content
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Add resize hint at top of detail panel
        hint_frame = ttk.Frame(self.right_frame, relief="raised", borderwidth=1)
        hint_frame.pack(fill=tk.X)
        ttk.Label(hint_frame, text="◀ ▶ Drag to resize", 
                 font=("Arial", 8), foreground="#999").pack(pady=2)
        
        # Create detail view based on module type
        if finding.module == Module.STEGO:
            self._create_stego_detail_view(finding)
        elif finding.module == Module.MFT:
            self._create_mft_detail_view(finding)
        elif finding.module == Module.EVTX:
            self._create_evtx_detail_view(finding)
        elif finding.module == Module.CARVING:
            self._create_carving_detail_view(finding)
        else:
            self._create_generic_detail_view(finding)
    
    def _create_detail_header(self, parent, finding: Finding):
        """Create common header for detail views."""
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, padx=10, pady=10)
        
        # Close button
        ttk.Button(header, text="✕ Close", command=self._hide_detail_panel).pack(side=tk.RIGHT)
        
        # Finding ID and title
        title_text = f"{finding.id}"
        ttk.Label(header, text=title_text, font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        # Module and severity
        info_frame = ttk.Frame(header)
        info_frame.pack(fill=tk.X, pady=5)
        
        # Module badge
        module_label = ttk.Label(info_frame, text=finding.module.upper(), 
                                background="#667eea", foreground="white",
                                font=("Arial", 9, "bold"), padding=5)
        module_label.pack(side=tk.LEFT, padx=(0, 5))
        
        # Severity badge
        sev_colors = {"high": "#d32f2f", "medium": "#f57c00", "low": "#388e3c"}
        sev_label = ttk.Label(info_frame, text=finding.severity.upper(),
                             background=sev_colors.get(finding.severity, "#666"),
                             foreground="white",
                             font=("Arial", 9, "bold"), padding=5)
        sev_label.pack(side=tk.LEFT, padx=5)
        
        # Indicator type
        ttk.Label(info_frame, text=self._humanize_indicator(finding.indicator_type),
                 font=("Arial", 9)).pack(side=tk.LEFT, padx=10)
        
        ttk.Separator(header, orient="horizontal").pack(fill=tk.X, pady=10)
    
    def _create_section(self, parent, title: str) -> ttk.Frame:
        """Create a section with title."""
        section = ttk.LabelFrame(parent, text=title, padding=10)
        section.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        return section
    
    def _add_info_row(self, parent, label: str, value: str):
        """Add an info row to a section."""
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text=f"{label}:", font=("Arial", 9, "bold"), width=20).pack(side=tk.LEFT)
        ttk.Label(row, text=str(value), font=("Arial", 9)).pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def _create_stego_detail_view(self, finding: Finding):
        """Create Stego-specific detail view."""
        # Scrollable container
        canvas = tk.Canvas(self.right_frame)
        scrollbar = ttk.Scrollbar(self.right_frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Header
        self._create_detail_header(scrollable, finding)
        
        # Section 1: Common info
        common = self._create_section(scrollable, "Common Information")
        self._add_info_row(common, "Resource Type", finding.resource_type)
        self._add_info_row(common, "File Path", finding.file_path)
        if finding.related_artifact:
            self._add_info_row(common, "Related Artifact", finding.related_artifact)
        self._add_info_row(common, "Created At", finding.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        
        # Section 2: Image Metadata
        if "image_metadata" in finding.details or "dimensions" in finding.details:
            metadata = self._create_section(scrollable, "1. Image Metadata")
            
            img_meta = finding.details.get("image_metadata", {})
            dims = finding.details.get("dimensions", {})
            
            if "format" in img_meta:
                self._add_info_row(metadata, "Format", img_meta["format"])
            if dims:
                self._add_info_row(metadata, "Dimensions", f"{dims.get('width')}x{dims.get('height')}")
            if "size_bytes" in img_meta:
                size_mb = img_meta["size_bytes"] / (1024 * 1024)
                self._add_info_row(metadata, "Size", f"{size_mb:.2f} MB")
            
            eof = img_meta.get("has_data_after_eof", False)
            self._add_info_row(metadata, "Has data after EOF", "Yes" if eof else "No")
            
            unusual_meta = finding.details.get("metadata_scan", {}).get("large_metadata", False)
            self._add_info_row(metadata, "Unusual metadata", "Yes" if unusual_meta else "No")
        
        # Section 3: Stego Signals
        stego_signals = self._create_section(scrollable, "2. Stego Signals")
        
        signals_list = tk.Text(stego_signals, height=6, wrap=tk.WORD, font=("Arial", 9))
        signals_list.pack(fill=tk.BOTH, expand=True)
        
        # Collect signals
        signals = []
        
        if "extra_data_bytes" in finding.details:
            extra = finding.details["extra_data_bytes"]
            signals.append(f"• Extra data after EOF: {extra} bytes")
        
        if finding.details.get("metadata_scan", {}).get("large_metadata"):
            signals.append("• Suspicious EXIF UserComment with large ASCII text")
        
        if finding.details.get("entropy_analysis", {}).get("high_lsb_entropy"):
            signals.append("• High entropy in LSB plane (randomized data)")
        
        if finding.details.get("lsb_analysis", {}).get("coordinated_embedding"):
            signals.append("• Coordinated LSB embedding pattern across channels")
        
        if not signals:
            signals.append("• Multiple statistical anomalies detected")
        
        for signal in signals:
            signals_list.insert(tk.END, signal + "\n")
        
        signals_list.config(state=tk.DISABLED)
        
        # Section 4: Payloads
        if "language_guess" in finding.details or "payload_size_bytes" in finding.details:
            payload = self._create_section(scrollable, "3. Payloads (if any)")
            
            lang = finding.details.get("language_guess", "unknown")
            size = finding.details.get("payload_size_bytes", 0)
            
            self._add_info_row(payload, "Source", "Appended data / metadata / LSB")
            self._add_info_row(payload, "Size", f"{size} bytes")
            self._add_info_row(payload, "Looks like code?", f"Language guess: {lang}")
            
            # Warning banner
            warning = ttk.Frame(payload)
            warning.pack(fill=tk.X, pady=10)
            warning_label = ttk.Label(
                warning,
                text="⚠️ Extracted content is untrusted. It has NOT been executed.\nDo not run it directly; analyse in sandbox if needed.",
                background="#fff3cd",
                foreground="#856404",
                font=("Arial", 9),
                padding=10,
                wraplength=400
            )
            warning_label.pack(fill=tk.X)
            
            # Buttons
            btn_frame = ttk.Frame(payload)
            btn_frame.pack(fill=tk.X, pady=5)
            ttk.Button(btn_frame, text="View as text (safe)", 
                      command=lambda: self._view_payload_text(finding)).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="View as hex",
                      command=lambda: self._view_payload_hex(finding)).pack(side=tk.LEFT)
    
    def _create_mft_detail_view(self, finding: Finding):
        """Create MFT-specific detail view."""
        canvas = tk.Canvas(self.right_frame)
        scrollbar = ttk.Scrollbar(self.right_frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._create_detail_header(scrollable, finding)
        
        # Common info
        common = self._create_section(scrollable, "Common Information")
        self._add_info_row(common, "File Path", finding.file_path)
        self._add_info_row(common, "MFT Record", finding.details.get("mft_record_id", "N/A"))
        self._add_info_row(common, "Created At", finding.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        
        # MFT Timestamps block
        timestamps = self._create_section(scrollable, "MFT Timestamps")
        
        # Create table
        table_frame = ttk.Frame(timestamps)
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Headers
        headers = ["Source", "Created", "Modified", "Accessed"]
        for col, header in enumerate(headers):
            ttk.Label(table_frame, text=header, font=("Arial", 9, "bold"),
                     background="#f0f0f0", padding=5).grid(row=0, column=col, sticky="ew")
        
        # StandardInfo row
        si = finding.details.get("standard_info", {})
        ttk.Label(table_frame, text="StandardInfo", padding=5).grid(row=1, column=0, sticky="w")
        ttk.Label(table_frame, text=si.get("created", "..."), padding=5).grid(row=1, column=1, sticky="w")
        ttk.Label(table_frame, text=si.get("modified", "..."), padding=5).grid(row=1, column=2, sticky="w")
        ttk.Label(table_frame, text=si.get("accessed", "..."), padding=5).grid(row=1, column=3, sticky="w")
        
        # FileName row
        fn = finding.details.get("file_name_attr", {})
        ttk.Label(table_frame, text="FileName", padding=5).grid(row=2, column=0, sticky="w")
        ttk.Label(table_frame, text=fn.get("created", "..."), padding=5).grid(row=2, column=1, sticky="w")
        ttk.Label(table_frame, text=fn.get("modified", "..."), padding=5).grid(row=2, column=2, sticky="w")
        ttk.Label(table_frame, text=fn.get("accessed", "..."), padding=5).grid(row=2, column=3, sticky="w")
        
        # Delta row
        delta_days = finding.details.get("timestamp_deltas", {}).get("created_delta_days")
        if delta_days:
            ttk.Label(table_frame, text="Δ (days)", font=("Arial", 9, "bold"), padding=5).grid(row=3, column=0, sticky="w")
            ttk.Label(table_frame, text=f"+{delta_days}", foreground="#d32f2f", 
                     font=("Arial", 9, "bold"), padding=5).grid(row=3, column=1, sticky="w")
        
        # Suspicious fields
        susp_fields = finding.details.get("suspicious_fields", [])
        if susp_fields:
            susp = self._create_section(scrollable, "Analysis")
            self._add_info_row(susp, "Suspicious fields", ", ".join(susp_fields))
            self._add_info_row(susp, "Reason", finding.details.get("reason", ""))
    
    def _create_evtx_detail_view(self, finding: Finding):
        """Create EVTX-specific detail view."""
        canvas = tk.Canvas(self.right_frame)
        scrollbar = ttk.Scrollbar(self.right_frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._create_detail_header(scrollable, finding)
        
        # Common info
        common = self._create_section(scrollable, "Common Information")
        self._add_info_row(common, "File Path", finding.file_path)
        self._add_info_row(common, "Related Artifact", finding.related_artifact or "N/A")
        self._add_info_row(common, "Created At", finding.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        
        # Event info
        event = self._create_section(scrollable, "Event Information")
        self._add_info_row(event, "Log name", finding.details.get("log_name", "N/A"))
        self._add_info_row(event, "Event ID", finding.details.get("event_id", "N/A"))
        self._add_info_row(event, "Record ID", finding.details.get("record_id", "N/A"))
        self._add_info_row(event, "Time created", finding.details.get("event_time", "N/A"))
        
        # User/SID
        user = self._create_section(scrollable, "User / SID")
        self._add_info_row(user, "User SID", finding.details.get("user_sid", "N/A"))
    
    def _create_carving_detail_view(self, finding: Finding):
        """Create Carving-specific detail view."""
        canvas = tk.Canvas(self.right_frame)
        scrollbar = ttk.Scrollbar(self.right_frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._create_detail_header(scrollable, finding)
        
        # Common info
        common = self._create_section(scrollable, "Carved File Information")
        
        offset = finding.details.get("offset_start")
        offset_str = f"0x{offset:X}" if isinstance(offset, int) else "unknown"
        
        self._add_info_row(common, "Source", "\\\\.\\ I: , offsets")
        self._add_info_row(common, "Carved path", finding.file_path)
        self._add_info_row(common, "File type", finding.details.get("file_type", "N/A"))
        self._add_info_row(common, "Size", f"{finding.details.get('size_bytes', 0)} bytes")
        self._add_info_row(common, "Offset", offset_str)
    
    def _create_generic_detail_view(self, finding: Finding):
        """Create generic detail view for other modules."""
        canvas = tk.Canvas(self.right_frame)
        scrollbar = ttk.Scrollbar(self.right_frame, orient="vertical", command=canvas.yview)
        scrollable = ttk.Frame(canvas)
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._create_detail_header(scrollable, finding)
        
        # Common info
        common = self._create_section(scrollable, "Information")
        self._add_info_row(common, "Resource Type", finding.resource_type)
        self._add_info_row(common, "File Path", finding.file_path)
        if finding.related_artifact:
            self._add_info_row(common, "Related Artifact", finding.related_artifact)
        self._add_info_row(common, "Created At", finding.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        
        # Summary
        summary = self._create_section(scrollable, "Evidence Summary")
        text = tk.Text(summary, height=4, wrap=tk.WORD, font=("Arial", 9))
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, finding.evidence_summary)
        text.config(state=tk.DISABLED)
        
        # Details
        if finding.details:
            details = self._create_section(scrollable, "Technical Details")
            for key, value in finding.details.items():
                self._add_info_row(details, key, value)
    
    def _hide_detail_panel(self):
        """Hide the detail panel."""
        if self.detail_visible:
            self.main_paned.remove(self.right_frame)
            self.detail_visible = False
    
    def _view_payload_text(self, finding: Finding):
        """Show payload as text in read-only viewer."""
        viewer = tk.Toplevel(self.window)
        viewer.title("Payload Viewer (Read-Only)")
        viewer.geometry("800x600")
        
        text = scrolledtext.ScrolledText(viewer, wrap=tk.WORD, font=("Consolas", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Try to read payload
        payload_text = "Payload content not available"
        if finding.file_path:
            try:
                with open(finding.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    payload_text = f.read()
            except:
                payload_text = "Could not read payload file"
        
        text.insert(tk.END, payload_text)
        text.config(state=tk.DISABLED)
    
    def _view_payload_hex(self, finding: Finding):
        """Show payload as hex dump."""
        viewer = tk.Toplevel(self.window)
        viewer.title("Payload Hex Viewer")
        viewer.geometry("900x600")
        
        text = scrolledtext.ScrolledText(viewer, wrap=tk.NONE, font=("Consolas", 9))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Try to read payload
        if finding.file_path:
            try:
                with open(finding.file_path, 'rb') as f:
                    data = f.read(4096)  # First 4KB
                
                # Create hex dump
                hex_dump = self._create_hex_dump(data)
                text.insert(tk.END, hex_dump)
            except:
                text.insert(tk.END, "Could not read payload file")
        
        text.config(state=tk.DISABLED)
    
    def _create_hex_dump(self, data: bytes) -> str:
        """Create hex dump string from bytes."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f'{i:08X}  {hex_part:<48}  {ascii_part}')
        return '\n'.join(lines)
    
    def _create_status_bar(self):
        """Create status bar at bottom."""
        status = ttk.Frame(self.left_frame)
        status.pack(fill=tk.X, padx=10, pady=5)
        
        # Severity counts
        counts = self._count_by_severity()
        status_text = f"HIGH: {counts.get('high', 0)} | MEDIUM: {counts.get('medium', 0)} | LOW: {counts.get('low', 0)} | Total: {len(self.findings)}"
        
        ttk.Label(status, text=status_text, font=("Arial", 9)).pack(side=tk.LEFT)
        
        # Export button
        ttk.Button(status, text="Export Report", command=self._export_report).pack(side=tk.RIGHT, padx=5)
    
    def _apply_filters(self):
        """Apply filters to table."""
        severity = self.severity_filter.get()
        module = self.module_filter.get()
        search = self.search_var.get().lower()
        
        filtered = self.findings
        
        if severity != "All":
            filtered = [f for f in filtered if f.severity.upper() == severity]
        
        if module != "All":
            filtered = [f for f in filtered if f.module.upper() == module]
        
        if search:
            filtered = [f for f in filtered if 
                       search in f.evidence_summary.lower() or
                       search in f.file_path.lower() or
                       search in f.id.lower()]
        
        self._populate_table(filtered)
    
    def _clear_filters(self):
        """Clear all filters."""
        self.severity_filter.set("All")
        self.module_filter.set("All")
        self.search_var.set("")
        self._populate_table()
    
    def _export_report(self):
        """Export current view to report."""
        messagebox.showinfo("Export", "Use the main 'Export Report' button in the main window")
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        return Counter(f.severity for f in self.findings)