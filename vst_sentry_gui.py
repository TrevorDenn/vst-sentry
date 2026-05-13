"""
VST-Sentry GUI v2.5 — Tkinter Desktop Application
=====================================================

A drag-and-drop security scanner for VST / DLL plugin files. Provides
real-time analysis logging, a green/yellow/red status indicator, and
automatic safe-file installation to a user-configured DAW plugin folder.

Features:
    - Drag-and-drop zone (tkinterdnd2) with click-to-browse fallback
    - Threaded analysis so the GUI never freezes
    - Live scrolling analysis log with timestamps + severity icons
    - Colour-coded status indicator: Green/Yellow/Red/Grey
    - Menu bar with keyboard shortcuts (Ctrl+O, Ctrl+E, Ctrl+F, F5, etc.)
    - Tooltips on all interactive elements
    - Right-click context menu on the analysis log
    - Ctrl+F search-in-log with match highlighting
    - Persistent scan history panel with JSON storage
    - Batch folder scanning (scan all DLLs/VSTs in a directory)
    - Re-scan last file (F5)
    - Recent files menu (last 10 scanned files)
    - Animated progress bar during analysis
    - Auto-detect common DAW plugin folder paths
    - First-run welcome dialog
    - Configuration dialog for plugin folder + VirusTotal API key
    - Auto-copy Safe plugins to the configured folder
    - Full text report display for Suspicious / High Risk verdicts
    - Export report to text, JSON, or HTML
    - Summary dashboard cards after analysis
    - Quarantine folder for suspicious/high-risk files
    - Button hover effects
    - Window title updates during analysis
    - Copy SHA-256 to clipboard with visual feedback
    - Enhanced drag-and-drop visual feedback
    - Compare two scans side-by-side from history
    - Notification sound on scan completion
    - Scan duration tracking in history entries
    - Log-line severity icons (success/warning/error)
    - Statistics footer with lifetime scan counts
    - Keyboard shortcut cheat sheet (F1)
    - Session scan counter
    - Rich file-info tooltips on scan history cards
    - Auto-update check stub (Help > Check for Updates)
    - Multi-file drag-and-drop (queues as batch scan)
    - Scan progress step percentage in status bar
    - Export report as PDF (plain-text layout)
    - Drag-and-drop folder support (recursive plugin discovery)

Usage:
    python vst_sentry_gui.py

Author:  VST-Sentry Project
License: MIT
"""

from __future__ import annotations

import configparser
import glob as _glob_mod
import json
import os
import shutil
import sys
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
from typing import Any

# ---------------------------------------------------------------------------
# Ensure project root is on the path so we can import analyzer
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer import AnalysisResult, analyze_file, generate_report  # noqa: E402

# ---------------------------------------------------------------------------
# Optional: tkinterdnd2 for native drag-and-drop support
# ---------------------------------------------------------------------------
_HAS_DND = False
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore
    _HAS_DND = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Application Constants
# ---------------------------------------------------------------------------
APP_TITLE = "VST-Sentry"
APP_VERSION = "2.5.0"
QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vst_sentry.ini")
HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.json")
VALID_EXTENSIONS = {".dll", ".vst3", ".vst", ".exe"}
WINDOW_MIN_W = 960
WINDOW_MIN_H = 720
MAX_RECENT_FILES = 10
MAX_HISTORY_ENTRIES = 100
ENABLE_SOUND = True  # System bell on scan completion
GITHUB_RELEASES_URL = "https://github.com/vst-sentry/vst-sentry/releases/latest"
UPDATE_CHECK_TIMEOUT = 5  # seconds

# Common VST plugin folder paths (for auto-detect)
_COMMON_PLUGIN_PATHS = [
    # Windows — VST2
    os.path.expandvars(r"%ProgramFiles%\VSTPlugins"),
    os.path.expandvars(r"%ProgramFiles%\Steinberg\VSTPlugins"),
    os.path.expandvars(r"%ProgramFiles%\Common Files\VST2"),
    os.path.expandvars(r"%ProgramFiles(x86)%\VSTPlugins"),
    os.path.expandvars(r"%ProgramFiles(x86)%\Steinberg\VSTPlugins"),
    # Windows — VST3
    os.path.expandvars(r"%CommonProgramFiles%\VST3"),
    os.path.expandvars(r"%ProgramFiles%\Common Files\VST3"),
    # Windows — Ableton
    os.path.expandvars(r"%ProgramData%\Ableton\Live 11 Suite\Resources\VST Plug-Ins"),
    os.path.expandvars(r"%ProgramData%\Ableton\Live 12 Suite\Resources\VST Plug-Ins"),
    # macOS
    os.path.expanduser("~/Library/Audio/Plug-Ins/VST"),
    os.path.expanduser("~/Library/Audio/Plug-Ins/VST3"),
    "/Library/Audio/Plug-Ins/VST",
    "/Library/Audio/Plug-Ins/VST3",
    # Linux
    os.path.expanduser("~/.vst"),
    os.path.expanduser("~/.vst3"),
    "/usr/lib/vst",
    "/usr/lib/vst3",
    "/usr/local/lib/vst",
    "/usr/local/lib/vst3",
]

# Colour palette — dark theme inspired by DAW interfaces
_COLOURS = {
    "bg_dark":      "#1a1a2e",
    "bg_mid":       "#16213e",
    "bg_light":     "#0f3460",
    "bg_card":      "#1e2a47",
    "bg_input":     "#0d1b2a",
    "fg":           "#e0e0e0",
    "fg_dim":       "#8892a4",
    "fg_bright":    "#ffffff",
    "accent":       "#4fc3f7",
    "green":        "#00e676",
    "yellow":       "#ffd740",
    "red":          "#ff5252",
    "orange":       "#ff9100",
    "grey":         "#78909c",
    "border":       "#2c3e6b",
    "drop_zone_bg": "#0d2137",
    "drop_hover":   "#1a3a5c",
    "drop_active":  "#264a6e",  # border pulse during drag-over
    "log_bg":       "#0d1b2a",
    "button_bg":    "#1b3a5c",
    "button_fg":    "#e0e0e0",
    "button_hover": "#245a8c",
    "search_bg":    "#162a4a",
    "search_match": "#ffab40",
    "history_bg":   "#111a2e",
    "history_sel":  "#1b3a5c",
    "progress_bg":  "#0d1b2a",
    "progress_fg":  "#4fc3f7",
    "clipboard":    "#00e676",  # flash colour for "Copied!" feedback
}

# Status-to-colour mapping
_STATUS_COLOURS = {
    "Safe":       _COLOURS["green"],
    "Suspicious": _COLOURS["yellow"],
    "High Risk":  _COLOURS["red"],
    "Error":      _COLOURS["grey"],
    "Ready":      _COLOURS["grey"],
    "Analyzing":  _COLOURS["accent"],
}

# Verdict-to-status message mapping
_VERDICT_MESSAGES = {
    "Safe":       "Secure \u2014 Installed",
    "Suspicious": "WARNING \u2014 Suspicious indicators detected",
    "High Risk":  "BLOCKED \u2014 High-risk indicators detected",
    "Error":      "Error during analysis",
}


# ---------------------------------------------------------------------------
# Hover Effect Utility
# ---------------------------------------------------------------------------
def _apply_hover(widget: tk.Widget, hover_bg: str, normal_bg: str) -> None:
    """Bind enter/leave events to change the background on hover."""
    widget.bind("<Enter>", lambda e: widget.configure(bg=hover_bg), add="+")
    widget.bind("<Leave>", lambda e: widget.configure(bg=normal_bg), add="+")


def _bind_click_recursive(widget: tk.Misc, sequence: str, callback) -> None:
    """
    Bind *callback* on *widget* and every descendant.

    Tkinter delivers events to the deepest widget under the cursor; parent
    bindings do not run for clicks on child Labels.
    """
    widget.bind(sequence, callback)
    for child in widget.winfo_children():
        _bind_click_recursive(child, sequence, callback)


# Log-line severity icon prefixes (Unicode)
_LOG_ICONS: dict[str, str] = {
    "success": "\u2714 ",   # ✔
    "warning": "\u26a0 ",   # ⚠
    "error":   "\u26d4 ",   # ⛔
    # info, accent, header — no prefix
}


# ---------------------------------------------------------------------------
# ToolTip Widget
# ---------------------------------------------------------------------------
class ToolTip:
    """
    Lightweight tooltip that appears when hovering over a widget.

    Usage:
        ToolTip(some_button, "Click to analyze a file")
    """

    _DELAY_MS = 500     # Hover delay before showing
    _DURATION_MS = 0    # 0 = stays until mouse leaves

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self._widget = widget
        self._text = text
        self._tip_window: tk.Toplevel | None = None
        self._after_id: str | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._cancel, add="+")
        widget.bind("<ButtonPress>", self._cancel, add="+")

    @property
    def text(self) -> str:
        """Current tooltip text."""
        return self._text

    @text.setter
    def text(self, value: str) -> None:
        """Update the tooltip text."""
        self._text = value

    def _schedule(self, _event: tk.Event | None = None) -> None:
        """Schedule the tooltip to appear after a delay."""
        self._cancel()
        self._after_id = self._widget.after(self._DELAY_MS, self._show)

    def _cancel(self, _event: tk.Event | None = None) -> None:
        """Cancel the scheduled tooltip and hide any visible one."""
        if self._after_id:
            self._widget.after_cancel(self._after_id)
            self._after_id = None
        self._hide()

    def _show(self) -> None:
        """Display the tooltip near the widget."""
        if self._tip_window or not self._text:
            return
        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._tip_window = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.configure(bg="#2a2a3e")
        label = tk.Label(
            tw,
            text=self._text,
            font=("Segoe UI", 9),
            fg="#e0e0e0",
            bg="#2a2a3e",
            padx=8,
            pady=4,
            wraplength=280,
            justify=tk.LEFT,
        )
        label.pack()

    def _hide(self) -> None:
        """Destroy the tooltip window."""
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None


# ---------------------------------------------------------------------------
# Scan History — persistent JSON storage
# ---------------------------------------------------------------------------
@dataclass
class ScanHistoryEntry:
    """One record in the scan history."""
    file_name: str
    file_path: str
    verdict: str
    risk_score: int
    scan_date: str          # ISO-8601
    flagged_count: int = 0
    vt_detections: str = ""
    sha256: str = ""
    elapsed_seconds: float = 0.0  # Scan duration in seconds
    file_size: int = 0            # File size in bytes


class ScanHistory:
    """Manages a list of scan results persisted to a JSON file."""

    def __init__(self, path: str = HISTORY_FILE) -> None:
        """Load existing history from *path*."""
        self._path = path
        self._entries: list[ScanHistoryEntry] = []
        self._load()

    # -- Persistence --

    def _load(self) -> None:
        """Read history from disk."""
        if not os.path.isfile(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._entries = [ScanHistoryEntry(**e) for e in data]
        except Exception:
            self._entries = []

    def _save(self) -> None:
        """Write history to disk."""
        try:
            data = [asdict(e) for e in self._entries]
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception:
            pass  # Non-fatal — history is a nice-to-have

    # -- Public API --

    def add(self, entry: ScanHistoryEntry) -> None:
        """Append a scan record and trim to MAX_HISTORY_ENTRIES."""
        self._entries.insert(0, entry)
        self._entries = self._entries[:MAX_HISTORY_ENTRIES]
        self._save()

    def clear(self) -> None:
        """Delete all history entries."""
        self._entries.clear()
        self._save()

    @property
    def entries(self) -> list[ScanHistoryEntry]:
        """Read-only access to history entries (newest first)."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Configuration Manager
# ---------------------------------------------------------------------------
class Config:
    """Persistent configuration backed by an INI file."""

    _SECTION = "VST-Sentry"

    def __init__(self, path: str = CONFIG_FILE) -> None:
        """Load config from *path*, creating defaults if the file is missing."""
        self._path = path
        self._parser = configparser.ConfigParser()
        self._load()

    def _load(self) -> None:
        """Read config file; create defaults if missing."""
        if os.path.isfile(self._path):
            self._parser.read(self._path, encoding="utf-8")
        if not self._parser.has_section(self._SECTION):
            self._parser.add_section(self._SECTION)
            self._parser.set(self._SECTION, "plugin_folder", "")
            self._parser.set(self._SECTION, "vt_api_key", "")
            self._parser.set(self._SECTION, "first_run", "true")
            self._parser.set(self._SECTION, "recent_files", "")
            self._save()
        # Ensure newer keys exist for older config files
        for key, default in [
            ("vt_api_key", ""),
            ("first_run", "false"),
            ("recent_files", ""),
        ]:
            if not self._parser.has_option(self._SECTION, key):
                self._parser.set(self._SECTION, key, default)
                self._save()

    def _save(self) -> None:
        """Write current state to disk."""
        with open(self._path, "w", encoding="utf-8") as fh:
            self._parser.write(fh)

    # -- Properties --

    @property
    def plugin_folder(self) -> str:
        """Configured DAW plugin folder path (may be empty)."""
        return self._parser.get(self._SECTION, "plugin_folder", fallback="")

    @plugin_folder.setter
    def plugin_folder(self, value: str) -> None:
        """Persist a new plugin folder path."""
        self._parser.set(self._SECTION, "plugin_folder", value)
        self._save()

    @property
    def vt_api_key(self) -> str:
        """Stored VirusTotal API key (may be empty)."""
        return self._parser.get(self._SECTION, "vt_api_key", fallback="")

    @vt_api_key.setter
    def vt_api_key(self, value: str) -> None:
        """Persist a new VirusTotal API key."""
        self._parser.set(self._SECTION, "vt_api_key", value)
        self._save()

    @property
    def is_first_run(self) -> bool:
        """True on the very first application launch."""
        return self._parser.get(self._SECTION, "first_run", fallback="true").lower() == "true"

    @is_first_run.setter
    def is_first_run(self, value: bool) -> None:
        self._parser.set(self._SECTION, "first_run", str(value).lower())
        self._save()

    @property
    def recent_files(self) -> list[str]:
        """List of recently scanned file paths (newest first)."""
        raw = self._parser.get(self._SECTION, "recent_files", fallback="")
        if not raw.strip():
            return []
        return [p for p in raw.split("|") if p.strip()]

    @recent_files.setter
    def recent_files(self, paths: list[str]) -> None:
        self._parser.set(self._SECTION, "recent_files", "|".join(paths[:MAX_RECENT_FILES]))
        self._save()


# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------
class VSTSentryApp:
    """Main application window."""

    def __init__(self) -> None:
        """Build the main window, toolbar, drop zone, analysis log, and status bar."""
        self._config = Config()
        self._history = ScanHistory()
        self._current_result: AnalysisResult | None = None
        self._analysis_thread: threading.Thread | None = None
        self._is_analysing = False
        self._last_file_path: str | None = None
        self._batch_queue: list[str] = []
        self._batch_results: list[AnalysisResult] = []
        self._is_batch = False

        # Search state
        self._search_visible = False
        self._search_matches: list[str] = []
        self._search_index = 0

        # Progress animation state
        self._progress_after_id: str | None = None
        self._progress_value = 0.0
        self._pulse_after_id: str | None = None
        self._progress_step = 0        # Current analysis step (1-8)
        self._progress_total_steps = 8  # Total pipeline steps

        # Elapsed-time timer state
        self._elapsed_after_id: str | None = None
        self._analysis_start_time: float = 0.0

        # ----- Root window ---------------------------------------------------
        if _HAS_DND:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()

        self.root.title(f"{APP_TITLE}  v{APP_VERSION}")
        self.root.configure(bg=_COLOURS["bg_dark"])
        self.root.minsize(WINDOW_MIN_W, WINDOW_MIN_H)
        self.root.geometry(f"{WINDOW_MIN_W}x{WINDOW_MIN_H}")

        # Centre window on screen
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - WINDOW_MIN_W) // 2
        y = (sh - WINDOW_MIN_H) // 2
        self.root.geometry(f"+{x}+{y}")

        # Try to set window icon (non-fatal if missing)
        try:
            icon_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "icon.ico"
            )
            if os.path.isfile(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        # ----- Build UI widgets ----------------------------------------------
        self._build_menu_bar()
        self._build_header()
        self._build_drop_zone()
        self._build_status_bar()
        self._build_summary_cards()  # dashboard cards (hidden initially)
        self._build_main_area()      # log + history pane
        self._build_button_bar()
        self._build_stats_footer()   # lifetime statistics bar

        # Session scan counter
        self._session_scan_count = 0

        # ----- Keyboard Shortcuts --------------------------------------------
        self.root.bind("<Control-o>", lambda e: self._on_browse_click())
        self.root.bind("<Control-O>", lambda e: self._on_browse_click())
        self.root.bind("<Control-e>", lambda e: self._export_report())
        self.root.bind("<Control-E>", lambda e: self._export_report())
        self.root.bind("<Control-f>", lambda e: self._toggle_search())
        self.root.bind("<Control-F>", lambda e: self._toggle_search())
        self.root.bind("<Control-l>", lambda e: self._clear_log())
        self.root.bind("<Control-L>", lambda e: self._clear_log())
        self.root.bind("<F5>", lambda e: self._rescan_last())
        self.root.bind("<F1>", lambda e: self._show_shortcut_cheat_sheet())
        self.root.bind("<Control-h>", lambda e: self._toggle_history_panel())
        self.root.bind("<Control-H>", lambda e: self._toggle_history_panel())
        self.root.bind("<Escape>", lambda e: self._close_search())

        # ----- Initial state -------------------------------------------------
        self._set_status("Ready", "Drop a .dll, .vst3, or installer .exe to begin analysis")

        # ----- First-run welcome ---------------------------------------------
        if self._config.is_first_run:
            self.root.after(300, self._show_welcome)

    # =====================================================================
    # Menu Bar
    # =====================================================================

    def _build_menu_bar(self) -> None:
        """Standard menu bar: File, Edit, View, Help."""
        menubar = tk.Menu(self.root, bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
                          activebackground=_COLOURS["button_hover"],
                          activeforeground=_COLOURS["fg_bright"],
                          relief=tk.FLAT, borderwidth=0)

        # -- File --
        file_menu = tk.Menu(menubar, tearoff=0,
                            bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
                            activebackground=_COLOURS["button_hover"],
                            activeforeground=_COLOURS["fg_bright"])
        file_menu.add_command(label="Open File...          Ctrl+O",
                              command=self._on_browse_click)
        file_menu.add_command(label="Scan Folder...",
                              command=self._scan_folder)
        file_menu.add_command(label="Re-scan Last File     F5",
                              command=self._rescan_last)
        file_menu.add_separator()

        # Recent files submenu
        self._recent_menu = tk.Menu(file_menu, tearoff=0,
                                    bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
                                    activebackground=_COLOURS["button_hover"],
                                    activeforeground=_COLOURS["fg_bright"])
        file_menu.add_cascade(label="Recent Files", menu=self._recent_menu)
        self._rebuild_recent_menu()

        file_menu.add_separator()
        file_menu.add_command(label="Export Report...      Ctrl+E",
                              command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Settings...",
                              command=self._open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit",
                              command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # -- Edit --
        edit_menu = tk.Menu(menubar, tearoff=0,
                            bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
                            activebackground=_COLOURS["button_hover"],
                            activeforeground=_COLOURS["fg_bright"])
        edit_menu.add_command(label="Copy                  Ctrl+C",
                              command=self._copy_log_selection)
        edit_menu.add_command(label="Select All            Ctrl+A",
                              command=self._select_all_log)
        edit_menu.add_separator()
        edit_menu.add_command(label="Find...               Ctrl+F",
                              command=self._toggle_search)
        edit_menu.add_separator()
        edit_menu.add_command(label="Copy SHA-256",
                              command=self._copy_sha256)
        edit_menu.add_separator()
        edit_menu.add_command(label="Clear Log             Ctrl+L",
                              command=self._clear_log)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        # -- View --
        view_menu = tk.Menu(menubar, tearoff=0,
                            bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
                            activebackground=_COLOURS["button_hover"],
                            activeforeground=_COLOURS["fg_bright"])
        view_menu.add_command(label="Toggle History        Ctrl+H",
                              command=self._toggle_history_panel)
        view_menu.add_command(label="Clear History",
                              command=self._clear_history)
        view_menu.add_separator()
        view_menu.add_command(label="Compare Scans...",
                              command=self._compare_scans)
        menubar.add_cascade(label="View", menu=view_menu)

        # -- Help --
        help_menu = tk.Menu(menubar, tearoff=0,
                            bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
                            activebackground=_COLOURS["button_hover"],
                            activeforeground=_COLOURS["fg_bright"])
        help_menu.add_command(label="Keyboard Shortcuts    F1",
                              command=self._show_shortcut_cheat_sheet)
        help_menu.add_separator()
        help_menu.add_command(label="Check for Updates...",
                              command=self._check_for_updates)
        help_menu.add_separator()
        help_menu.add_command(label="VirusTotal Website",
                              command=lambda: webbrowser.open("https://www.virustotal.com"))
        help_menu.add_command(label="MITRE ATT&CK Website",
                              command=lambda: webbrowser.open("https://attack.mitre.org"))
        help_menu.add_separator()
        help_menu.add_command(label="About VST-Sentry",
                              command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    # =====================================================================
    # UI Construction
    # =====================================================================

    def _build_header(self) -> None:
        """Top bar with app title and config gear button."""
        header = tk.Frame(self.root, bg=_COLOURS["bg_mid"], height=52)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # Shield + Title
        title_lbl = tk.Label(
            header,
            text="\u25c8  VST-Sentry",
            font=("Segoe UI", 16, "bold"),
            fg=_COLOURS["accent"],
            bg=_COLOURS["bg_mid"],
            padx=16,
        )
        title_lbl.pack(side=tk.LEFT)

        version_lbl = tk.Label(
            header,
            text=f"v{APP_VERSION}",
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"],
            bg=_COLOURS["bg_mid"],
        )
        version_lbl.pack(side=tk.LEFT, pady=(6, 0))

        # Config gear button
        gear_btn = tk.Button(
            header,
            text="\u2699  Settings",
            font=("Segoe UI", 10),
            fg=_COLOURS["button_fg"],
            bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            activeforeground=_COLOURS["fg_bright"],
            bd=0,
            padx=14,
            pady=4,
            cursor="hand2",
            command=self._open_settings,
        )
        gear_btn.pack(side=tk.RIGHT, padx=16, pady=10)
        ToolTip(gear_btn, "Open settings (plugin folder, VT API key)")

    def _build_drop_zone(self) -> None:
        """Central drag-and-drop zone with click-to-browse fallback."""
        container = tk.Frame(self.root, bg=_COLOURS["bg_dark"], padx=20, pady=12)
        container.pack(fill=tk.X, side=tk.TOP)

        self._drop_frame = tk.Frame(
            container,
            bg=_COLOURS["drop_zone_bg"],
            highlightbackground=_COLOURS["border"],
            highlightthickness=2,
            cursor="hand2",
        )
        self._drop_frame.pack(fill=tk.X, ipady=24)

        # Icon + instructions
        self._drop_icon_lbl = tk.Label(
            self._drop_frame,
            text="\u21e9",
            font=("Segoe UI", 32),
            fg=_COLOURS["accent"],
            bg=_COLOURS["drop_zone_bg"],
        )
        self._drop_icon_lbl.pack(pady=(8, 0))

        primary_text = (
            "Drop files or folders here" if _HAS_DND
            else "Click to select a .dll, .vst3, or .exe file"
        )
        self._drop_primary_lbl = tk.Label(
            self._drop_frame,
            text=primary_text,
            font=("Segoe UI", 13, "bold"),
            fg=_COLOURS["fg"],
            bg=_COLOURS["drop_zone_bg"],
        )
        self._drop_primary_lbl.pack()

        secondary_text = (
            ".dll / .vst3 / .vst / .exe  \u00b7  folders auto-scanned recursively  \u00b7  Ctrl+O"
            if _HAS_DND
            else "Supports .dll, .vst3, .vst, and .exe files  \u00b7  Ctrl+O"
        )
        self._drop_secondary_lbl = tk.Label(
            self._drop_frame,
            text=secondary_text,
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"],
            bg=_COLOURS["drop_zone_bg"],
        )
        self._drop_secondary_lbl.pack(pady=(0, 6))

        # Bind click-to-browse on all children
        for widget in (
            self._drop_frame,
            self._drop_icon_lbl,
            self._drop_primary_lbl,
            self._drop_secondary_lbl,
        ):
            widget.bind("<Button-1>", self._on_browse_click)

        # Tooltip
        ToolTip(
            self._drop_frame,
            "Drop plugin files or a VstPlugins folder here, or click to browse",
        )

        # Bind native drag-and-drop if available
        if _HAS_DND:
            self._drop_frame.drop_target_register(DND_FILES)
            self._drop_frame.dnd_bind("<<DropEnter>>", self._on_drop_enter)
            self._drop_frame.dnd_bind("<<DropLeave>>", self._on_drop_leave)
            self._drop_frame.dnd_bind("<<Drop>>", self._on_drop)

    def _build_status_bar(self) -> None:
        """Colour-coded status indicator with verdict label and progress bar."""
        container = tk.Frame(self.root, bg=_COLOURS["bg_dark"], padx=20, pady=4)
        container.pack(fill=tk.X, side=tk.TOP)

        self._status_frame = tk.Frame(
            container,
            bg=_COLOURS["bg_card"],
            highlightbackground=_COLOURS["border"],
            highlightthickness=1,
        )
        self._status_frame.pack(fill=tk.X, ipady=6)

        # Top row: status dot + label
        top_row = tk.Frame(self._status_frame, bg=_COLOURS["bg_card"])
        top_row.pack(fill=tk.X, padx=8, pady=(4, 0))

        # Status indicator dot (canvas circle)
        self._status_canvas = tk.Canvas(
            top_row, width=22, height=22,
            bg=_COLOURS["bg_card"], highlightthickness=0,
        )
        self._status_canvas.pack(side=tk.LEFT, padx=(8, 8))
        self._status_dot = self._status_canvas.create_oval(
            3, 3, 19, 19, fill=_COLOURS["grey"], outline=""
        )
        self._glow_dot = self._status_canvas.create_oval(
            0, 0, 22, 22, outline=_COLOURS["grey"], width=1
        )

        # Status text
        self._status_label = tk.Label(
            top_row, text="Status: Ready",
            font=("Segoe UI", 12, "bold"),
            fg=_COLOURS["fg"], bg=_COLOURS["bg_card"],
        )
        self._status_label.pack(side=tk.LEFT)

        # Elapsed time label (right-aligned)
        self._elapsed_label = tk.Label(
            top_row, text="",
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_card"],
        )
        self._elapsed_label.pack(side=tk.RIGHT, padx=(0, 8))

        # Status detail (right-aligned)
        self._status_detail = tk.Label(
            top_row, text="",
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_card"],
            anchor=tk.E,
        )
        self._status_detail.pack(side=tk.RIGHT, padx=(0, 16))

        # Progress bar (canvas-based for custom styling)
        self._progress_canvas = tk.Canvas(
            self._status_frame, height=4,
            bg=_COLOURS["progress_bg"], highlightthickness=0,
        )
        self._progress_canvas.pack(fill=tk.X, padx=16, pady=(4, 4))
        self._progress_bar = self._progress_canvas.create_rectangle(
            0, 0, 0, 4, fill=_COLOURS["progress_fg"], outline=""
        )

    def _build_summary_cards(self) -> None:
        """Build the summary dashboard cards row (hidden until first scan)."""
        self._summary_frame = tk.Frame(self.root, bg=_COLOURS["bg_dark"], padx=20, pady=2)
        # Don't pack yet — shown after first successful analysis

        self._summary_cards: dict[str, dict[str, tk.Label]] = {}
        card_defs = [
            ("verdict", "VERDICT", "--"),
            ("score", "RISK SCORE", "0"),
            ("imports", "FLAGGED APIs", "0"),
            ("vt", "VIRUSTOTAL", "N/A"),
            ("entropy", "ENTROPY", "--"),
        ]

        for key, title, default_value in card_defs:
            card = tk.Frame(
                self._summary_frame,
                bg=_COLOURS["bg_card"],
                highlightbackground=_COLOURS["border"],
                highlightthickness=1,
                padx=12, pady=8,
            )
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

            title_lbl = tk.Label(
                card, text=title,
                font=("Segoe UI", 8, "bold"),
                fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_card"],
            )
            title_lbl.pack(anchor=tk.W)

            value_lbl = tk.Label(
                card, text=default_value,
                font=("Segoe UI", 16, "bold"),
                fg=_COLOURS["fg_bright"], bg=_COLOURS["bg_card"],
            )
            value_lbl.pack(anchor=tk.W)

            detail_lbl = tk.Label(
                card, text="",
                font=("Segoe UI", 8),
                fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_card"],
            )
            detail_lbl.pack(anchor=tk.W)

            self._summary_cards[key] = {
                "frame": card, "title": title_lbl,
                "value": value_lbl, "detail": detail_lbl,
            }

    def _update_summary_cards(self, result: AnalysisResult) -> None:
        """Populate the summary dashboard with analysis results."""
        # Show the frame if hidden
        if not self._summary_frame.winfo_ismapped():
            self._summary_frame.pack(
                fill=tk.X, side=tk.TOP,
                before=self._main_container,
            )

        verdict = result.verdict
        verdict_colour = {
            "Safe": _COLOURS["green"],
            "Suspicious": _COLOURS["yellow"],
            "High Risk": _COLOURS["red"],
        }.get(verdict, _COLOURS["grey"])

        # Verdict card
        vc = self._summary_cards["verdict"]
        vc["value"].configure(text=verdict.upper(), fg=verdict_colour)
        vc["detail"].configure(text=result.file_name)

        # Score card
        sc = self._summary_cards["score"]
        sc["value"].configure(text=str(result.risk_score), fg=verdict_colour)
        if result.risk_score == 0:
            sc["detail"].configure(text="No risk indicators")
        elif result.risk_score <= 4:
            sc["detail"].configure(text="Within safe range")
        elif result.risk_score <= 19:
            sc["detail"].configure(text="Requires investigation")
        else:
            sc["detail"].configure(text="High risk threshold exceeded")

        # Imports card
        ic = self._summary_cards["imports"]
        count = result.flagged_count
        ic["value"].configure(
            text=str(count),
            fg=_COLOURS["red"] if count > 0 else _COLOURS["green"],
        )
        total = result.total_imports
        ic["detail"].configure(text=f"of {total} total imports")

        # VT card
        vtc = self._summary_cards["vt"]
        vt_data = result.vt_lookup
        if vt_data and vt_data.get("found"):
            ratio = vt_data.get("detection_ratio", "N/A")
            mal = vt_data.get("malicious", 0)
            vtc["value"].configure(
                text=ratio,
                fg=_COLOURS["green"] if mal == 0 else _COLOURS["red"],
            )
            vtc["detail"].configure(
                text="Clean" if mal == 0 else f"{mal} engine(s) flagged"
            )
        elif vt_data and vt_data.get("queried"):
            vtc["value"].configure(text="N/F", fg=_COLOURS["fg_dim"])
            vtc["detail"].configure(text="Not found in database")
        else:
            vtc["value"].configure(text="--", fg=_COLOURS["fg_dim"])
            vtc["detail"].configure(text="No API key configured")

        # Entropy card
        ec = self._summary_cards["entropy"]
        ea = result.entropy_analysis
        if ea:
            ent_val = ea.get("file_entropy", 0)
            packed = ea.get("is_likely_packed", False)
            ec["value"].configure(
                text=f"{ent_val:.2f}",
                fg=_COLOURS["red"] if packed else _COLOURS["green"],
            )
            ec["detail"].configure(
                text="Likely packed/encrypted" if packed else "Normal range"
            )
        else:
            ec["value"].configure(text="--", fg=_COLOURS["fg_dim"])
            ec["detail"].configure(text="")

    def _build_main_area(self) -> None:
        """Build the central area: log (left) + history panel (right)."""
        self._main_container = tk.Frame(self.root, bg=_COLOURS["bg_dark"])
        self._main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=4)

        # Use a PanedWindow so the user can resize the split
        self._paned = tk.PanedWindow(
            self._main_container, orient=tk.HORIZONTAL,
            bg=_COLOURS["border"], sashwidth=4, sashpad=0,
        )
        self._paned.pack(fill=tk.BOTH, expand=True)

        # --- Left side: Search bar + Analysis Log ---
        log_container = tk.Frame(self._paned, bg=_COLOURS["bg_dark"])

        # Search bar (hidden by default)
        self._search_frame = tk.Frame(log_container, bg=_COLOURS["search_bg"])
        # Don't pack yet — toggled with Ctrl+F

        search_lbl = tk.Label(
            self._search_frame, text="\u2315 Find:",
            font=("Segoe UI", 9, "bold"),
            fg=_COLOURS["fg"], bg=_COLOURS["search_bg"],
        )
        search_lbl.pack(side=tk.LEFT, padx=(8, 4), pady=4)

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._on_search_changed())
        self._search_entry = tk.Entry(
            self._search_frame,
            textvariable=self._search_var,
            font=("Consolas", 10),
            bg=_COLOURS["bg_input"], fg=_COLOURS["fg"],
            insertbackground=_COLOURS["fg"],
            relief=tk.FLAT, width=30,
        )
        self._search_entry.pack(side=tk.LEFT, padx=2, pady=4, ipady=2)
        self._search_entry.bind("<Return>", lambda e: self._find_next())
        self._search_entry.bind("<Escape>", lambda e: self._close_search())

        self._search_count_lbl = tk.Label(
            self._search_frame, text="",
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["search_bg"],
        )
        self._search_count_lbl.pack(side=tk.LEFT, padx=4)

        search_next_btn = tk.Button(
            self._search_frame, text="\u25bc Next",
            font=("Segoe UI", 8), fg=_COLOURS["button_fg"],
            bg=_COLOURS["button_bg"], bd=0, padx=6, pady=1,
            cursor="hand2", command=self._find_next,
        )
        search_next_btn.pack(side=tk.LEFT, padx=2)

        search_prev_btn = tk.Button(
            self._search_frame, text="\u25b2 Prev",
            font=("Segoe UI", 8), fg=_COLOURS["button_fg"],
            bg=_COLOURS["button_bg"], bd=0, padx=6, pady=1,
            cursor="hand2", command=self._find_prev,
        )
        search_prev_btn.pack(side=tk.LEFT, padx=2)

        search_close_btn = tk.Button(
            self._search_frame, text="\u2715",
            font=("Segoe UI", 9), fg=_COLOURS["fg_dim"],
            bg=_COLOURS["search_bg"], bd=0, padx=6,
            cursor="hand2", command=self._close_search,
        )
        search_close_btn.pack(side=tk.RIGHT, padx=4)

        # Log header
        log_header = tk.Label(
            log_container, text="Analysis Log",
            font=("Segoe UI", 10, "bold"),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_dark"],
            anchor=tk.W,
        )
        log_header.pack(fill=tk.X, pady=(0, 4))

        # Log text widget
        self._log_text = scrolledtext.ScrolledText(
            log_container,
            font=("Consolas", 10),
            bg=_COLOURS["log_bg"], fg=_COLOURS["fg"],
            insertbackground=_COLOURS["fg"],
            selectbackground=_COLOURS["bg_light"],
            wrap=tk.WORD, state=tk.DISABLED,
            relief=tk.FLAT, borderwidth=0,
            padx=12, pady=8,
        )
        self._log_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for coloured log lines
        self._log_text.tag_configure("timestamp", foreground=_COLOURS["fg_dim"])
        self._log_text.tag_configure("info", foreground=_COLOURS["fg"])
        self._log_text.tag_configure("success", foreground=_COLOURS["green"])
        self._log_text.tag_configure("warning", foreground=_COLOURS["yellow"])
        self._log_text.tag_configure("error", foreground=_COLOURS["red"])
        self._log_text.tag_configure("accent", foreground=_COLOURS["accent"])
        self._log_text.tag_configure(
            "header", foreground=_COLOURS["fg_bright"],
            font=("Consolas", 10, "bold"),
        )
        self._log_text.tag_configure(
            "search_highlight",
            background=_COLOURS["search_match"],
            foreground="#000000",
        )

        # Right-click context menu
        self._context_menu = tk.Menu(
            self._log_text, tearoff=0,
            bg=_COLOURS["bg_mid"], fg=_COLOURS["fg"],
            activebackground=_COLOURS["button_hover"],
            activeforeground=_COLOURS["fg_bright"],
        )
        self._context_menu.add_command(label="Copy", command=self._copy_log_selection)
        self._context_menu.add_command(label="Select All", command=self._select_all_log)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="Find...", command=self._toggle_search)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="Clear Log", command=self._clear_log)
        self._log_text.bind("<Button-3>", self._on_right_click)
        # macOS right-click
        self._log_text.bind("<Button-2>", self._on_right_click)

        self._paned.add(log_container, stretch="always")

        # --- Right side: Scan History Panel ---
        self._history_frame = tk.Frame(self._paned, bg=_COLOURS["history_bg"])
        self._build_history_panel()
        self._paned.add(self._history_frame, stretch="never", width=260)

    def _build_history_panel(self) -> None:
        """Populate the scan history sidebar."""
        frame = self._history_frame

        header_frame = tk.Frame(frame, bg=_COLOURS["history_bg"])
        header_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

        tk.Label(
            header_frame, text="\u23f3  Scan History",
            font=("Segoe UI", 10, "bold"),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["history_bg"],
        ).pack(side=tk.LEFT)

        clear_hist_btn = tk.Button(
            header_frame, text="\u2715",
            font=("Segoe UI", 9), fg=_COLOURS["fg_dim"],
            bg=_COLOURS["history_bg"], bd=0,
            cursor="hand2", command=self._clear_history,
        )
        clear_hist_btn.pack(side=tk.RIGHT)
        ToolTip(clear_hist_btn, "Clear scan history")

        # Scrollable history list
        self._history_canvas = tk.Canvas(
            frame, bg=_COLOURS["history_bg"], highlightthickness=0,
        )
        self._history_scrollbar = tk.Scrollbar(
            frame, orient=tk.VERTICAL, command=self._history_canvas.yview,
        )
        self._history_inner = tk.Frame(self._history_canvas, bg=_COLOURS["history_bg"])

        self._history_inner.bind("<Configure>", lambda e: self._history_canvas.configure(
            scrollregion=self._history_canvas.bbox("all")
        ))
        self._history_canvas.create_window((0, 0), window=self._history_inner, anchor="nw")
        self._history_canvas.configure(yscrollcommand=self._history_scrollbar.set)

        self._history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._history_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        # Populate with existing entries
        self._refresh_history_list()

    def _refresh_history_list(self) -> None:
        """Rebuild the history list widgets from the ScanHistory data."""
        for child in self._history_inner.winfo_children():
            child.destroy()

        if not self._history.entries:
            tk.Label(
                self._history_inner,
                text="No scans yet.\nDrop a file to get started.",
                font=("Segoe UI", 9),
                fg=_COLOURS["fg_dim"], bg=_COLOURS["history_bg"],
                justify=tk.CENTER, wraplength=220,
            ).pack(pady=40)
            return

        for i, entry in enumerate(self._history.entries):
            self._create_history_card(entry, i)

    def _create_history_card(self, entry: ScanHistoryEntry, index: int) -> None:
        """Create a single scan history card widget."""
        verdict_colours = {
            "Safe": _COLOURS["green"],
            "Suspicious": _COLOURS["yellow"],
            "High Risk": _COLOURS["red"],
        }
        verdict_colour = verdict_colours.get(entry.verdict, _COLOURS["grey"])

        card = tk.Frame(
            self._history_inner,
            bg=_COLOURS["bg_card"],
            highlightbackground=_COLOURS["border"],
            highlightthickness=1,
            cursor="hand2",
        )
        card.pack(fill=tk.X, padx=4, pady=2)

        # Verdict indicator bar (left edge)
        indicator = tk.Frame(card, bg=verdict_colour, width=4)
        indicator.pack(side=tk.LEFT, fill=tk.Y)

        # Content
        content = tk.Frame(card, bg=_COLOURS["bg_card"])
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Filename (truncated)
        name = entry.file_name
        if len(name) > 28:
            name = name[:25] + "..."
        tk.Label(
            content, text=name,
            font=("Consolas", 9, "bold"),
            fg=_COLOURS["fg"], bg=_COLOURS["bg_card"],
            anchor=tk.W,
        ).pack(fill=tk.X)

        # Verdict + score
        detail_text = f"{entry.verdict}  \u00b7  Score: {entry.risk_score}"
        if entry.flagged_count:
            detail_text += f"  \u00b7  {entry.flagged_count} flags"
        tk.Label(
            content, text=detail_text,
            font=("Segoe UI", 8),
            fg=verdict_colour, bg=_COLOURS["bg_card"],
            anchor=tk.W,
        ).pack(fill=tk.X)

        # Date
        try:
            dt = datetime.fromisoformat(entry.scan_date)
            date_str = dt.strftime("%b %d, %Y  %H:%M")
        except Exception:
            date_str = entry.scan_date
        tk.Label(
            content, text=date_str,
            font=("Segoe UI", 7),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_card"],
            anchor=tk.W,
        ).pack(fill=tk.X)

        # Click to re-scan (entire card subtree — labels sit above the frames)
        def _rescan(path: str = entry.file_path) -> None:
            if os.path.isfile(path):
                self._start_analysis(path)
            else:
                messagebox.showerror("File Not Found",
                                     f"The file no longer exists:\n{path}")

        _bind_click_recursive(card, "<Button-1>", lambda _e: _rescan())

        # Rich file-info tooltip
        tip_lines = [f"Path: {entry.file_path}"]
        if entry.file_size:
            tip_lines.append(f"Size: {entry.file_size:,} bytes")
        if entry.sha256:
            tip_lines.append(f"SHA-256: {entry.sha256[:32]}...")
        if entry.vt_detections:
            tip_lines.append(f"VT: {entry.vt_detections}")
        if entry.elapsed_seconds > 0:
            tip_lines.append(f"Duration: {entry.elapsed_seconds:.1f}s")
        tip_lines.append("Click to re-scan")
        ToolTip(card, "\n".join(tip_lines))

    def _build_button_bar(self) -> None:
        """Bottom button row: Analyze, Scan Folder, Re-scan, Clear Log, Export."""
        container = tk.Frame(self.root, bg=_COLOURS["bg_dark"], padx=20, pady=12)
        container.pack(fill=tk.X, side=tk.BOTTOM)

        btn_style = {
            "font": ("Segoe UI", 10, "bold"),
            "fg": _COLOURS["button_fg"],
            "bg": _COLOURS["button_bg"],
            "activebackground": _COLOURS["button_hover"],
            "activeforeground": _COLOURS["fg_bright"],
            "bd": 0,
            "padx": 14,
            "pady": 7,
            "cursor": "hand2",
        }

        self._analyse_btn = tk.Button(
            container, text="\u25b6  Analyze File",
            command=self._on_browse_click, **btn_style,
        )
        self._analyse_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self._analyse_btn, "Open a file to analyze (Ctrl+O)")

        self._scan_folder_btn = tk.Button(
            container, text="\U0001f4c1  Scan Folder",
            command=self._scan_folder, **btn_style,
        )
        self._scan_folder_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self._scan_folder_btn, "Scan all DLL/VST files in a folder")

        self._rescan_btn = tk.Button(
            container, text="\u21bb  Re-scan",
            command=self._rescan_last, state=tk.DISABLED, **btn_style,
        )
        self._rescan_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self._rescan_btn, "Re-analyze the last scanned file (F5)")

        self._clear_btn = tk.Button(
            container, text="\u2715  Clear Log",
            command=self._clear_log, **btn_style,
        )
        self._clear_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self._clear_btn, "Clear the analysis log (Ctrl+L)")

        self._export_btn = tk.Button(
            container, text="\u2913  Export Report",
            command=self._export_report, state=tk.DISABLED, **btn_style,
        )
        self._export_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self._export_btn, "Save analysis report to file (Ctrl+E)")

        self._copy_sha_btn = tk.Button(
            container, text="\u2398  Copy SHA-256",
            command=self._copy_sha256, state=tk.DISABLED, **btn_style,
        )
        self._copy_sha_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self._copy_sha_btn, "Copy the file's SHA-256 hash to clipboard")

        # Apply hover effects to all buttons
        for btn in (self._analyse_btn, self._scan_folder_btn,
                    self._rescan_btn, self._clear_btn, self._export_btn,
                    self._copy_sha_btn):
            _apply_hover(btn, _COLOURS["button_hover"], _COLOURS["button_bg"])

        # Plugin folder indicator (right side)
        folder = self._config.plugin_folder
        folder_display = self._truncate_path(folder) if folder else "Not configured"
        self._folder_label = tk.Label(
            container,
            text=f"\U0001f4c1 Plugin folder: {folder_display}",
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"],
            bg=_COLOURS["bg_dark"],
            anchor=tk.E,
        )
        self._folder_label.pack(side=tk.RIGHT)

    # =====================================================================
    # Event Handlers
    # =====================================================================

    def _on_browse_click(self, event: tk.Event | None = None) -> None:
        """Open file dialog to select a plugin file."""
        if self._is_analysing:
            return

        file_path = filedialog.askopenfilename(
            title="Select VST Plugin or DLL",
            filetypes=[
                ("VST / DLL / EXE files", "*.dll *.vst3 *.vst *.exe"),
                ("DLL files", "*.dll"),
                ("VST3 files", "*.vst3"),
                ("Installer EXE files", "*.exe"),
                ("All files", "*.*"),
            ],
        )
        if file_path:
            self._start_analysis(file_path)

    def _on_drop_enter(self, event: Any) -> None:
        """Highlight drop zone when a file is dragged over it."""
        hover = _COLOURS["drop_hover"]
        self._drop_frame.configure(
            bg=hover,
            highlightbackground=_COLOURS["drop_active"],
        )
        self._drop_icon_lbl.configure(text="\u2b07", bg=hover)  # solid arrow
        self._drop_primary_lbl.configure(
            text="Release to scan files / folder", bg=hover,
        )
        self._drop_secondary_lbl.configure(bg=hover)
        return event.action

    def _on_drop_leave(self, event: Any) -> None:
        """Restore drop zone appearance when the drag leaves."""
        bg = _COLOURS["drop_zone_bg"]
        self._drop_frame.configure(
            bg=bg,
            highlightbackground=_COLOURS["border"],
        )
        primary_text = (
            "Drop files or folders here" if _HAS_DND
            else "Click to select a .dll, .vst3, or .exe file"
        )
        self._drop_icon_lbl.configure(text="\u21e9", bg=bg)
        self._drop_primary_lbl.configure(text=primary_text, bg=bg)
        self._drop_secondary_lbl.configure(bg=bg)

    @staticmethod
    def _collect_plugins_from_dir(folder: str) -> list[str]:
        """Recursively discover all DLL/VST/VST3/EXE files in *folder*.

        Returns a de-duplicated, sorted list of absolute paths.
        """
        found: list[str] = []
        for ext in VALID_EXTENSIONS:
            found.extend(
                _glob_mod.glob(os.path.join(folder, f"*{ext}"))
            )
            found.extend(
                _glob_mod.glob(
                    os.path.join(folder, "**", f"*{ext}"),
                    recursive=True,
                )
            )
        return sorted(set(found))

    @staticmethod
    def _parse_drop_paths(raw: str) -> list[str]:
        """Parse the raw drop-event string into a list of filesystem paths.

        Windows may wrap paths containing spaces in braces, e.g.
        ``{C:\\Program Files\\my plugin.dll}``.
        """
        raw = raw.strip()
        parsed: list[str] = []
        i = 0
        while i < len(raw):
            if raw[i] == "{":
                j = raw.index("}", i)
                parsed.append(raw[i + 1:j])
                i = j + 1
            elif raw[i] in (" ", "\t", "\n", "\r"):
                i += 1
            else:
                j = i
                while j < len(raw) and raw[j] not in (" ", "\t", "\n", "\r"):
                    j += 1
                parsed.append(raw[i:j])
                i = j
        return parsed

    def _on_drop(self, event: Any) -> None:
        """Handle file(s) or folder(s) dropped onto the drop zone.

        - Regular files are filtered to valid extensions.
        - Directories are recursively scanned for plugin files.
        - Multiple results are queued as a batch scan.
        """
        self._on_drop_leave(event)  # Reset hover highlight

        if self._is_analysing:
            self._log("Analysis already in progress \u2014 please wait.", "warning")
            return

        parsed_paths = self._parse_drop_paths(event.data)

        # Separate directories from files and expand directories
        valid: list[str] = []
        dir_count = 0
        for p in parsed_paths:
            if os.path.isdir(p):
                dir_count += 1
                discovered = self._collect_plugins_from_dir(p)
                if discovered:
                    self._log(
                        f"\U0001f4c2 Folder: {p} \u2014 "
                        f"{len(discovered)} plugin(s) found",
                        "info",
                    )
                    valid.extend(discovered)
                else:
                    self._log(
                        f"\U0001f4c2 Folder: {p} \u2014 "
                        f"no supported files found",
                        "warning",
                    )
            else:
                ext = os.path.splitext(p)[1].lower()
                if ext in VALID_EXTENSIONS:
                    valid.append(p)
                else:
                    self._log(
                        f"Skipped unsupported file type '{ext}': "
                        f"{os.path.basename(p)}",
                        "warning",
                    )

        # De-duplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for fp in valid:
            norm = os.path.normpath(fp)
            if norm not in seen:
                seen.add(norm)
                unique.append(fp)
        valid = unique

        if not valid:
            self._log(
                "No supported files found. Expected .dll, .vst3, .vst, or .exe (installer).",
                "error",
            )
            return

        if len(valid) == 1:
            self._start_analysis(valid[0])
        else:
            # Multiple files — start a batch scan
            label = (
                f"{len(valid)} plugins from {dir_count} folder(s)"
                if dir_count
                else f"{len(valid)} dropped files"
            )
            self._is_batch = True
            self._batch_queue = valid[1:]
            self._batch_results = []
            self._clear_log()
            self._log(f"{'=' * 60}", "accent")
            self._log(f"  BATCH SCAN \u2014 {label}", "header")
            self._log(f"{'=' * 60}", "accent")
            self._log("", "info")
            self._start_analysis(valid[0])

    def _on_right_click(self, event: tk.Event) -> None:
        """Show context menu on the analysis log."""
        try:
            self._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._context_menu.grab_release()

    # =====================================================================
    # Analysis Pipeline (threaded)
    # =====================================================================

    def _start_analysis(self, file_path: str) -> None:
        """Kick off analysis in a background thread."""
        if self._is_analysing:
            return

        self._is_analysing = True
        self._current_result = None
        self._last_file_path = file_path
        self._export_btn.configure(state=tk.DISABLED)
        self._rescan_btn.configure(state=tk.DISABLED)
        self._copy_sha_btn.configure(state=tk.DISABLED)

        # Track in recent files
        self._add_recent_file(file_path)

        # Update UI to show we're working
        self._set_status("Analyzing", f"Scanning {os.path.basename(file_path)}...")
        self.root.title(f"{APP_TITLE} \u2014 Analyzing {os.path.basename(file_path)}...")
        if not self._is_batch:
            self._clear_log()
        self._progress_step = 0
        self._start_progress_animation()
        self._start_elapsed_timer()

        file_name = os.path.basename(file_path)
        self._log(f"{'=' * 60}", "accent")
        self._log(f"  VST-Sentry Analysis \u2014 {file_name}", "header")
        self._log(f"{'=' * 60}", "accent")
        self._log(f"File: {file_path}", "info")
        size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
        self._log(f"Size: {size:,} bytes", "info")
        self._log("", "info")

        # Launch background thread
        self._analysis_thread = threading.Thread(
            target=self._run_analysis, args=(file_path,), daemon=True
        )
        self._analysis_thread.start()

    def _run_analysis(self, file_path: str) -> None:
        """Execute the analysis engine (runs in background thread)."""
        try:
            self._set_progress_step(1)
            self._log_ts("[1/8]  Validating PE structure...", "info")
            time.sleep(0.15)  # Brief pause so the user can read the log

            self._set_progress_step(2)
            self._log_ts("[2/8]  Computing file hashes (MD5, SHA-256)...", "info")
            time.sleep(0.1)

            self._set_progress_step(3)
            self._log_ts("[3/8]  Parsing Import Address Table (IAT)...", "info")
            time.sleep(0.1)

            self._set_progress_step(4)
            self._log_ts("[4/8]  Cross-referencing against Red Flag API database...", "info")
            time.sleep(0.1)

            self._set_progress_step(5)
            self._log_ts("[5/8]  Running entropy / packing heuristics...", "info")
            time.sleep(0.1)

            self._set_progress_step(6)
            self._log_ts("[6/8]  Checking digital signature...", "info")
            time.sleep(0.1)

            self._set_progress_step(7)
            vt_key = self._config.vt_api_key
            if vt_key:
                self._log_ts("[7/8]  Querying VirusTotal by SHA-256 hash...", "accent")
            else:
                self._log_ts("[7/8]  VirusTotal lookup skipped (no API key)", "info")
            time.sleep(0.1)

            # ---- Run the actual analyzer engine ----
            result = analyze_file(
                file_path,
                include_all_imports=True,
                vt_api_key=vt_key,
            )

            self._set_progress_step(8)
            # Log behaviour step based on what actually happened
            beh = result.vt_behaviours
            if beh.get("queried") and beh.get("found"):
                self._log_ts(
                    "[8/8]  Sandbox behaviour data retrieved from VirusTotal",
                    "accent",
                )
            elif beh.get("queried") and beh.get("error"):
                self._log_ts(
                    f"[8/8]  Sandbox behaviour lookup failed: {beh['error']}",
                    "warning",
                )
            elif beh.get("queried"):
                self._log_ts(
                    "[8/8]  No sandbox behaviour data available", "info"
                )
            else:
                self._log_ts(
                    "[8/8]  Sandbox behaviour lookup skipped (not applicable)",
                    "info",
                )
            time.sleep(0.1)

            # Store result for export
            self._current_result = result

            # Post results to the GUI thread
            self.root.after(0, self._display_results, result)

        except FileNotFoundError:
            self.root.after(0, self._analysis_error, "File not found.")
        except PermissionError:
            self.root.after(0, self._analysis_error, "Permission denied \u2014 cannot read file.")
        except Exception as exc:
            self.root.after(0, self._analysis_error, f"Unexpected error: {exc}")

    def _display_results(self, result: AnalysisResult) -> None:
        """Render analysis results in the log and update status (GUI thread)."""
        self._is_analysing = False
        self._stop_progress_animation()
        self._stop_elapsed_timer()
        self._export_btn.configure(state=tk.NORMAL)
        self._rescan_btn.configure(state=tk.NORMAL)
        self._copy_sha_btn.configure(state=tk.NORMAL)

        # Play notification sound
        if ENABLE_SOUND:
            try:
                self.root.bell()
            except Exception:
                pass

        self._log("", "info")
        self._log(f"{'-' * 60}", "accent")
        self._log("  RESULTS", "header")
        self._log(f"{'-' * 60}", "accent")
        self._log("", "info")

        # -- File metadata --
        self._log(f"  PE Type:        {result.pe_type}", "info")
        self._log(f"  Architecture:   {result.architecture}", "info")
        self._log(f"  Compiled:       {result.compile_timestamp}", "info")
        self._log(f"  MD5:            {result.md5}", "info")
        self._log(f"  SHA-256:        {result.sha256}", "info")
        self._log(f"  Total Imports:  {result.total_imports}", "info")
        self._log("", "info")

        # -- Signature info --
        sig = result.signature
        if sig.get("has_signature"):
            sig_status = "SIGNED"
            if sig.get("is_valid"):
                sig_status += " (Valid)"
            signer = sig.get("signer", "Unknown")
            self._log(f"  Signature:      {sig_status} \u2014 {signer}", "success")
        else:
            self._log("  Signature:      UNSIGNED", "warning")
        self._log("", "info")

        # -- Entropy analysis --
        ea = result.entropy_analysis
        if ea:
            self._log(f"  File Entropy:   {ea.get('file_entropy', 0):.4f} bits/byte", "info")
            packed_str = "YES" if ea.get("is_likely_packed") else "No"
            tag = "warning" if ea.get("is_likely_packed") else "info"
            self._log(f"  Likely Packed:  {packed_str}", tag)

            rwx_count = ea.get("rwx_sections", 0)
            if rwx_count > 0:
                self._log(f"  RWX Sections:   {rwx_count}  \u26a0 Suspicious", "warning")

            packer_count = ea.get("packer_sections", 0)
            if packer_count > 0:
                self._log(f"  Packer Names:   {packer_count} known packer section(s)", "warning")

            entropy_score = ea.get("total_entropy_score", 0)
            if entropy_score > 0:
                self._log(f"  Entropy Score:  +{entropy_score} pts", "warning")

            # Per-section detail
            sections = ea.get("sections", [])
            if sections:
                self._log("", "info")
                self._log("  Section Entropy Detail:", "accent")
                for sec in sections:
                    name = sec.get("name", "???")
                    ent = sec.get("entropy", 0)
                    alerts = sec.get("alerts", [])
                    alert_str = f"  [{', '.join(alerts)}]" if alerts else ""
                    tag = "warning" if alerts else "info"
                    self._log(f"    {name:<12} {ent:.4f} bits/byte{alert_str}", tag)

        self._log("", "info")

        # -- VirusTotal lookup --
        vt = result.vt_lookup
        if vt and vt.get("queried"):
            self._log("  VirusTotal Lookup:", "accent")
            if vt.get("error"):
                self._log(f"    Error: {vt['error']}", "warning")
            elif vt.get("found"):
                mal = vt.get("malicious", 0)
                ratio = vt.get("detection_ratio", "N/A")

                if mal == 0:
                    self._log(f"    Detection:    {ratio}  \u2714 Clean", "success")
                elif mal <= 4:
                    self._log(f"    Detection:    {ratio}  \u26a0 Low detections", "warning")
                else:
                    self._log(f"    Detection:    {ratio}  \u26d4 MALICIOUS", "error")

                threat_label = vt.get("threat_label", "")
                if threat_label:
                    self._log(f"    Threat Label: {threat_label}", "error")

                threat_names = vt.get("threat_names", [])
                if threat_names:
                    self._log(f"    Names:        {', '.join(threat_names)}", "warning")

                score_adj = vt.get("score_contribution", 0)
                if score_adj > 0:
                    self._log(f"    Score Impact: +{score_adj} pts", "warning")
                elif score_adj < 0:
                    self._log(f"    Score Impact: {score_adj} pts (verified clean)", "success")

                permalink = vt.get("permalink", "")
                if permalink:
                    self._log(f"    Report:       {permalink}", "info")
            else:
                self._log("    Hash not found in VirusTotal database", "info")
            self._log("", "info")

        # -- Sandbox behaviour data (High Risk + VT match only) --
        beh = result.vt_behaviours
        if beh and beh.get("queried") and beh.get("found"):
            self._log("  Sandbox Behaviour (VirusTotal):", "accent")
            self._log("", "info")

            # Network activity
            dns = beh.get("dns_lookups", [])
            ip_traffic = beh.get("ip_traffic", [])
            http = beh.get("http_conversations", [])
            if dns or ip_traffic or http:
                self._log("    Network Activity:", "error")
                for entry in dns:
                    hostname = entry.get("hostname", "")
                    resolved = entry.get("resolved_ips", [])
                    ips = ", ".join(resolved) if resolved else "unresolved"
                    self._log(f"      DNS  {hostname} \u2192 {ips}", "warning")
                for entry in ip_traffic:
                    dest_ip = entry.get("destination_ip", "")
                    dest_port = entry.get("destination_port", 0)
                    proto = entry.get("protocol", "TCP")
                    self._log(
                        f"      IP   {dest_ip}:{dest_port} ({proto})", "warning"
                    )
                for entry in http:
                    url = entry.get("url", "")
                    method = entry.get("method", "GET")
                    status = entry.get("status_code", 0)
                    self._log(
                        f"      HTTP {method} {url} [{status}]", "warning"
                    )
                self._log("", "info")

            # File-system activity
            dropped = beh.get("files_dropped", [])
            written = beh.get("files_written", [])
            if dropped or written:
                self._log("    File-System Activity:", "error")
                for entry in dropped:
                    path = entry.get("path", "")
                    sha = entry.get("sha256", "")
                    sha_str = f"  ({sha[:16]}...)" if sha else ""
                    self._log(f"      DROPPED {path}{sha_str}", "warning")
                for path in written:
                    self._log(f"      WRITTEN {path}", "warning")
                self._log("", "info")

            # Process activity
            cmds = beh.get("command_executions", [])
            procs = beh.get("processes_created", [])
            if cmds or procs:
                self._log("    Process Activity:", "error")
                for cmd in cmds:
                    self._log(f"      CMD  {cmd}", "warning")
                for proc in procs:
                    self._log(f"      PROC {proc}", "warning")
                self._log("", "info")

            # Persistence
            reg = beh.get("registry_keys_set", [])
            mutex = beh.get("mutexes_created", [])
            svc = beh.get("services_created", [])
            if reg or mutex or svc:
                self._log("    Persistence / System Modification:", "error")
                for entry in reg:
                    key = entry.get("key", "")
                    val = entry.get("value", "")
                    self._log(f"      REG     {key} = {val}", "warning")
                for m in mutex:
                    self._log(f"      MUTEX   {m}", "warning")
                for s in svc:
                    self._log(f"      SERVICE {s}", "warning")
                self._log("", "info")

            # Tags
            tags = beh.get("tags", [])
            if tags:
                self._log(f"    Tags: {', '.join(tags)}", "info")
                self._log("", "info")

            # MITRE ATT&CK Techniques
            mitre_techs = beh.get("mitre_attack_techniques", [])
            if mitre_techs:
                self._log("    MITRE ATT&CK Mapping:", "accent")
                _sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
                sorted_techs = sorted(
                    mitre_techs,
                    key=lambda t: (
                        _sev_order.get(t.get("severity", "UNKNOWN"), 4),
                        t.get("id", ""),
                    ),
                )
                for tech in sorted_techs:
                    tid = tech.get("id", "?")
                    sev = tech.get("severity", "?")
                    name = tech.get("name", "")
                    tactic = tech.get("tactic", "")
                    desc = tech.get("description", "")

                    sev_tag = {
                        "HIGH": "error",
                        "MEDIUM": "warning",
                        "LOW": "info",
                        "INFO": "info",
                    }.get(sev, "info")

                    name_str = f" {name}" if name else ""
                    tactic_str = f" [{tactic}]" if tactic else ""
                    self._log(
                        f"      [{sev:<6s}] {tid}{name_str}{tactic_str}",
                        sev_tag,
                    )
                    if desc:
                        self._log(
                            f"               {desc}", "info"
                        )
                self._log("", "info")

        elif beh and beh.get("queried") and beh.get("error"):
            self._log(
                f"  Sandbox Behaviour: {beh['error']}", "warning"
            )
            self._log("", "info")

        # -- Flagged imports --
        if result.flagged_imports:
            self._log(f"  Flagged Imports: {result.flagged_count}", "error")
            self._log("", "info")
            for imp in result.flagged_imports:
                weight = imp.get("weight", 0)
                tag = "error" if weight >= 7 else "warning"
                self._log(
                    f"    [{imp.get('category', '?')}] "
                    f"{imp.get('dll', '?')}!{imp.get('function', '?')} "
                    f"({weight} pts) \u2014 {imp.get('description', '')}",
                    tag,
                )
        else:
            self._log("  Flagged Imports: 0  \u2714", "success")

        self._log("", "info")

        # -- Warnings --
        if result.warnings:
            for w in result.warnings:
                self._log(f"  \u26a0 {w}", "warning")
            self._log("", "info")

        # -- Categories hit --
        if result.categories_hit:
            self._log("  Categories Hit:", "accent")
            for cat, pts in sorted(
                result.categories_hit.items(), key=lambda x: x[1], reverse=True
            ):
                self._log(f"    {cat}: {pts} pts", "warning")
            self._log("", "info")

        # -- Final verdict --
        self._log(f"{'=' * 60}", "accent")
        verdict = result.verdict
        score = result.risk_score
        verdict_tag = {
            "Safe": "success",
            "Suspicious": "warning",
            "High Risk": "error",
        }.get(verdict, "info")

        self._log(
            f"  VERDICT:  {verdict.upper()}  |  Risk Score: {score}",
            verdict_tag,
        )
        self._log(f"{'=' * 60}", "accent")
        self._log("", "info")

        # -- Update status indicator --
        status_msg = _VERDICT_MESSAGES.get(verdict, verdict)
        self._set_status(verdict, status_msg)

        # -- Update summary dashboard --
        self._update_summary_cards(result)

        # -- Record in history --
        vt_det = ""
        vt_data = result.vt_lookup
        if vt_data and vt_data.get("found"):
            vt_det = vt_data.get("detection_ratio", "")
        # Calculate elapsed scan time (must use monotonic — matches _start_elapsed_timer)
        elapsed = (
            time.monotonic() - self._analysis_start_time
            if self._analysis_start_time > 0 else 0.0
        )
        # Compute file size for history record
        try:
            file_size = os.path.getsize(result.file_path)
        except OSError:
            file_size = 0
        self._history.add(ScanHistoryEntry(
            file_name=result.file_name,
            file_path=result.file_path,
            verdict=verdict,
            risk_score=score,
            scan_date=datetime.now().isoformat(),
            flagged_count=result.flagged_count,
            vt_detections=vt_det,
            sha256=result.sha256,
            elapsed_seconds=round(elapsed, 2),
            file_size=file_size,
        ))
        self._refresh_history_list()

        # -- Update statistics footer --
        self._session_scan_count += 1
        self._update_stats_footer()

        # -- Post-verdict action: install or block --
        self._handle_verdict(result)

        # -- Batch continuation --
        if self._is_batch and self._batch_queue:
            self._batch_results.append(result)
            next_file = self._batch_queue.pop(0)
            self._log("", "info")
            self.root.after(200, self._start_analysis, next_file)
        elif self._is_batch:
            self._batch_results.append(result)
            self._finish_batch()

    def _handle_verdict(self, result: AnalysisResult) -> None:
        """
        Take action based on the verdict.

        Safe       -> auto-copy to configured plugin folder.
        Suspicious -> warn, display full text report, do NOT copy.
        High Risk  -> block, display full text report, do NOT copy.
        """
        verdict = result.verdict

        if verdict == "Safe":
            plugin_folder = self._config.plugin_folder
            if plugin_folder and os.path.isdir(plugin_folder):
                try:
                    dest = os.path.join(plugin_folder, result.file_name)
                    shutil.copy2(result.file_path, dest)
                    self._log(
                        f"\u2714  Copied to plugin folder: {dest}", "success"
                    )
                    self._set_status("Safe", "Secure \u2014 Installed")
                except Exception as exc:
                    self._log(
                        f"\u2718  Failed to copy to plugin folder: {exc}", "error"
                    )
            elif plugin_folder:
                self._log(
                    f"\u26a0  Plugin folder does not exist: {plugin_folder}",
                    "warning",
                )
                self._log(
                    "   Open Settings to configure a valid folder.", "info"
                )
            else:
                self._log(
                    "\u26a0  No plugin folder configured \u2014 open Settings to set one.",
                    "warning",
                )
                self._log(
                    "   File is Safe but was not auto-installed.", "info"
                )

        elif verdict in ("Suspicious", "High Risk"):
            self._log("", "info")
            self._log(
                "\u26d4  File was NOT copied to the plugin folder.", "error"
            )

            # Offer quarantine
            self._quarantine_file(result)

            self._log("", "info")

            # Display the full text report
            report = generate_report(result)
            self._log("  DETAILED REPORT:", "header")
            self._log("", "info")
            for line in report.splitlines():
                self._log(f"  {line}", "info")

    def _analysis_error(self, message: str) -> None:
        """Handle an analysis error (GUI thread)."""
        self._is_analysing = False
        self._stop_progress_animation()
        self._stop_elapsed_timer()
        self._rescan_btn.configure(state=tk.NORMAL if self._last_file_path else tk.DISABLED)
        self._log(f"\u2718  {message}", "error")
        self._set_status("Error", message)

    # =====================================================================
    # Quarantine
    # =====================================================================

    def _quarantine_file(self, result: AnalysisResult) -> None:
        """Move a suspicious/high-risk file to the quarantine folder."""
        src = result.file_path
        if not os.path.isfile(src):
            return

        answer = messagebox.askyesno(
            "Quarantine File",
            f"The file \u201c{result.file_name}\u201d was flagged as {result.verdict}.\n\n"
            f"Move it to the quarantine folder?\n"
            f"  {QUARANTINE_DIR}",
        )
        if not answer:
            self._log("  File was left in its original location.", "info")
            return

        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            # Add timestamp to avoid collisions
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            q_name = f"{ts}_{result.file_name}"
            dest = os.path.join(QUARANTINE_DIR, q_name)
            shutil.move(src, dest)
            self._log(
                f"\u2714  Quarantined: {dest}", "warning"
            )
        except Exception as exc:
            self._log(
                f"\u2718  Quarantine failed: {exc}", "error"
            )

    # =====================================================================
    # Batch Folder Scanning
    # =====================================================================

    def _scan_folder(self) -> None:
        """Scan all supported files in a user-selected directory."""
        if self._is_analysing:
            self._log("Analysis already in progress \u2014 please wait.", "warning")
            return

        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return

        # Recursively discover all plugin files
        files = self._collect_plugins_from_dir(folder)

        if not files:
            messagebox.showinfo(
                "No Files Found",
                f"No .dll, .vst3, .vst, or .exe files found in:\n{folder}"
            )
            return

        # Confirm batch scan
        count = len(files)
        if not messagebox.askyesno(
            "Batch Scan",
            f"Found {count} plugin file{'s' if count != 1 else ''} in:\n{folder}\n\n"
            f"Scan all {count} file{'s' if count != 1 else ''}?",
        ):
            return

        self._is_batch = True
        self._batch_queue = files[1:]  # Queue all except the first
        self._batch_results = []
        self._clear_log()

        self._log(f"{'=' * 60}", "accent")
        self._log(f"  BATCH SCAN \u2014 {count} files in {folder}", "header")
        self._log(f"{'=' * 60}", "accent")
        self._log("", "info")

        # Start the first file
        self._start_analysis(files[0])

    def _finish_batch(self) -> None:
        """Display batch scan summary after all files processed."""
        self._is_batch = False
        results = self._batch_results
        self._batch_results = []

        safe = sum(1 for r in results if r.verdict == "Safe")
        suspicious = sum(1 for r in results if r.verdict == "Suspicious")
        high_risk = sum(1 for r in results if r.verdict == "High Risk")

        self._log("", "info")
        self._log(f"{'=' * 60}", "accent")
        self._log("  BATCH SCAN COMPLETE", "header")
        self._log(f"{'=' * 60}", "accent")
        self._log(f"  Total files scanned:  {len(results)}", "info")
        if safe:
            self._log(f"  Safe:                 {safe}", "success")
        if suspicious:
            self._log(f"  Suspicious:           {suspicious}", "warning")
        if high_risk:
            self._log(f"  High Risk:            {high_risk}", "error")
        self._log(f"{'=' * 60}", "accent")

        # Update status
        if high_risk:
            self._set_status("High Risk", f"Batch: {high_risk} high-risk file(s) detected")
        elif suspicious:
            self._set_status("Suspicious", f"Batch: {suspicious} suspicious file(s) detected")
        else:
            self._set_status("Safe", f"Batch: all {len(results)} files are safe")

    # =====================================================================
    # Re-scan & Recent Files
    # =====================================================================

    def _rescan_last(self) -> None:
        """Re-analyze the most recently scanned file."""
        if self._is_analysing:
            return
        if self._last_file_path and os.path.isfile(self._last_file_path):
            self._start_analysis(self._last_file_path)
        elif self._last_file_path:
            self._log(
                f"\u2718  File no longer exists: {self._last_file_path}", "error"
            )
        else:
            self._log("\u26a0  No previous scan to repeat. Open a file first.", "warning")

    def _add_recent_file(self, file_path: str) -> None:
        """Add a file to the recent files list."""
        recent = self._config.recent_files
        # Remove if already present (move to front)
        recent = [p for p in recent if p != file_path]
        recent.insert(0, file_path)
        self._config.recent_files = recent[:MAX_RECENT_FILES]
        self._rebuild_recent_menu()

    def _rebuild_recent_menu(self) -> None:
        """Rebuild the File > Recent Files submenu."""
        self._recent_menu.delete(0, tk.END)
        recent = self._config.recent_files
        if not recent:
            self._recent_menu.add_command(label="(no recent files)", state=tk.DISABLED)
            return
        for path in recent:
            name = os.path.basename(path)
            self._recent_menu.add_command(
                label=f"{name}   ({self._truncate_path(path, 50)})",
                command=lambda p=path: self._open_recent(p),
            )
        self._recent_menu.add_separator()
        self._recent_menu.add_command(label="Clear Recent Files",
                                      command=self._clear_recent)

    def _open_recent(self, file_path: str) -> None:
        """Open and scan a file from the recent list."""
        if self._is_analysing:
            return
        if os.path.isfile(file_path):
            self._start_analysis(file_path)
        else:
            messagebox.showerror(
                "File Not Found",
                f"The file no longer exists:\n{file_path}"
            )

    def _clear_recent(self) -> None:
        """Clear the recent files list."""
        self._config.recent_files = []
        self._rebuild_recent_menu()

    # =====================================================================
    # Search in Log
    # =====================================================================

    def _toggle_search(self) -> None:
        """Show or hide the search bar."""
        if self._search_visible:
            self._close_search()
        else:
            self._search_frame.pack(fill=tk.X, before=self._log_text, pady=(0, 4))
            self._search_visible = True
            self._search_entry.focus_set()
            self._search_entry.select_range(0, tk.END)

    def _close_search(self) -> None:
        """Hide the search bar and clear highlights."""
        if not self._search_visible:
            return
        self._search_frame.pack_forget()
        self._search_visible = False
        self._clear_search_highlights()
        self._search_var.set("")

    def _on_search_changed(self) -> None:
        """Re-run the search when the query changes."""
        self._clear_search_highlights()
        query = self._search_var.get().strip()
        if not query:
            self._search_count_lbl.configure(text="")
            self._search_matches = []
            self._search_index = 0
            return

        # Find all matches in the log
        self._log_text.configure(state=tk.NORMAL)
        start = "1.0"
        positions = []
        while True:
            pos = self._log_text.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self._log_text.tag_add("search_highlight", pos, end)
            positions.append(pos)
            start = end
        self._log_text.configure(state=tk.DISABLED)

        self._search_matches = positions
        self._search_index = 0
        count = len(positions)
        self._search_count_lbl.configure(
            text=f"{count} match{'es' if count != 1 else ''}" if count else "No matches"
        )

        # Jump to first match
        if positions:
            self._log_text.see(positions[0])

    def _find_next(self) -> None:
        """Jump to the next search match."""
        if not self._search_matches:
            return
        self._search_index = (self._search_index + 1) % len(self._search_matches)
        self._log_text.see(self._search_matches[self._search_index])

    def _find_prev(self) -> None:
        """Jump to the previous search match."""
        if not self._search_matches:
            return
        self._search_index = (self._search_index - 1) % len(self._search_matches)
        self._log_text.see(self._search_matches[self._search_index])

    def _clear_search_highlights(self) -> None:
        """Remove all search highlight tags."""
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.tag_remove("search_highlight", "1.0", tk.END)
        self._log_text.configure(state=tk.DISABLED)

    # =====================================================================
    # Clipboard & Log Utilities
    # =====================================================================

    def _copy_log_selection(self) -> None:
        """Copy the selected text from the log to the clipboard."""
        try:
            selection = self._log_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selection)
        except tk.TclError:
            # Nothing selected — copy entire log
            content = self._log_text.get("1.0", tk.END).strip()
            if content:
                self.root.clipboard_clear()
                self.root.clipboard_append(content)

    def _select_all_log(self) -> None:
        """Select all text in the analysis log."""
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.tag_add(tk.SEL, "1.0", tk.END)
        self._log_text.configure(state=tk.DISABLED)

    # =====================================================================
    # History Panel
    # =====================================================================

    def _toggle_history_panel(self) -> None:
        """Show or hide the scan history sidebar."""
        try:
            self._paned.paneconfig(self._history_frame)
            # Panel is visible — hide it
            self._paned.forget(self._history_frame)
        except tk.TclError:
            # Panel is hidden — show it
            self._paned.add(self._history_frame, stretch="never", width=260)

    def _clear_history(self) -> None:
        """Clear all scan history."""
        if messagebox.askyesno("Clear History", "Delete all scan history?"):
            self._history.clear()
            self._refresh_history_list()

    # =====================================================================
    # Progress Animation
    # =====================================================================

    def _start_progress_animation(self) -> None:
        """Start the indeterminate progress bar animation."""
        self._progress_value = 0.0
        self._animate_progress()
        self._start_pulse_animation()

    def _animate_progress(self) -> None:
        """Animate the progress bar (indeterminate sliding pattern)."""
        canvas = self._progress_canvas
        canvas.update_idletasks()
        total_w = canvas.winfo_width()
        if total_w <= 1:
            total_w = 400

        # Sliding window effect
        self._progress_value = (self._progress_value + 0.015) % 1.0
        pos = self._progress_value
        bar_w = int(total_w * 0.3)
        x1 = int((total_w + bar_w) * pos - bar_w)
        x2 = x1 + bar_w

        canvas.coords(self._progress_bar, max(0, x1), 0, min(total_w, x2), 4)
        self._progress_after_id = canvas.after(30, self._animate_progress)

    def _stop_progress_animation(self) -> None:
        """Stop the progress bar and fill it completely (done state)."""
        if self._progress_after_id:
            self._progress_canvas.after_cancel(self._progress_after_id)
            self._progress_after_id = None
        self._stop_pulse_animation()

        # Show full bar briefly, then fade out
        canvas = self._progress_canvas
        canvas.update_idletasks()
        total_w = canvas.winfo_width() or 400
        canvas.coords(self._progress_bar, 0, 0, total_w, 4)
        canvas.after(1500, lambda: canvas.coords(self._progress_bar, 0, 0, 0, 4))

    # =====================================================================
    # Status Dot Pulse Animation
    # =====================================================================

    def _start_pulse_animation(self) -> None:
        """Pulse the status dot glow ring during analysis."""
        self._pulse_step = 0
        self._pulse_dot()

    def _pulse_dot(self) -> None:
        """Animate the glow ring expanding/contracting."""
        self._pulse_step = (self._pulse_step + 1) % 40
        # Oscillate width between 1 and 3
        phase = abs(self._pulse_step - 20) / 20.0  # 0..1..0
        width = 1 + 2 * (1 - phase)
        self._status_canvas.itemconfig(self._glow_dot, width=width)
        self._pulse_after_id = self._status_canvas.after(50, self._pulse_dot)

    def _stop_pulse_animation(self) -> None:
        """Stop the status dot pulse."""
        if self._pulse_after_id:
            self._status_canvas.after_cancel(self._pulse_after_id)
            self._pulse_after_id = None
        self._status_canvas.itemconfig(self._glow_dot, width=1)

    # =====================================================================
    # Elapsed Time Timer
    # =====================================================================

    def _start_elapsed_timer(self) -> None:
        """Start the elapsed time counter."""
        self._analysis_start_time = time.monotonic()
        self._update_elapsed()

    def _update_elapsed(self) -> None:
        """Update the elapsed time label every 100ms, including step %."""
        elapsed = time.monotonic() - self._analysis_start_time
        if elapsed < 60:
            time_text = f"{elapsed:.1f}s"
        else:
            m, s = divmod(int(elapsed), 60)
            time_text = f"{m}m {s}s"
        # Append progress percentage if a step has been reported
        if self._progress_step > 0:
            pct = int(
                (self._progress_step / self._progress_total_steps) * 100
            )
            self._elapsed_label.configure(
                text=f"\u23f1 {time_text}  \u00b7  {pct}%"
            )
        else:
            self._elapsed_label.configure(text=f"\u23f1 {time_text}")
        self._elapsed_after_id = self.root.after(100, self._update_elapsed)

    def _set_progress_step(self, step: int) -> None:
        """Update the current analysis step counter (thread-safe)."""
        self._progress_step = step

    def _stop_elapsed_timer(self) -> None:
        """Freeze the elapsed time display."""
        if self._elapsed_after_id:
            self.root.after_cancel(self._elapsed_after_id)
            self._elapsed_after_id = None

    # =====================================================================
    # Settings Dialog
    # =====================================================================

    def _open_settings(self) -> None:
        """Open a modal dialog for application settings."""
        dialog = tk.Toplevel(self.root)
        dialog.title("VST-Sentry Settings")
        dialog.configure(bg=_COLOURS["bg_dark"])
        dialog.geometry("560x420")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Centre on parent
        dialog.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() - 560) // 2
        py = self.root.winfo_y() + (self.root.winfo_height() - 420) // 2
        dialog.geometry(f"+{px}+{py}")

        # --- Plugin folder ---
        tk.Label(
            dialog,
            text="DAW VST Plugin Folder",
            font=("Segoe UI", 11, "bold"),
            fg=_COLOURS["fg"],
            bg=_COLOURS["bg_dark"],
        ).pack(anchor=tk.W, padx=20, pady=(20, 4))

        tk.Label(
            dialog,
            text=(
                "Safe plugins will be automatically copied to this folder.\n"
                "Click 'Auto-Detect' to find common plugin directories."
            ),
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"],
            bg=_COLOURS["bg_dark"],
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=20)

        folder_frame = tk.Frame(dialog, bg=_COLOURS["bg_dark"])
        folder_frame.pack(fill=tk.X, padx=20, pady=(8, 0))

        folder_var = tk.StringVar(value=self._config.plugin_folder)
        folder_entry = tk.Entry(
            folder_frame,
            textvariable=folder_var,
            font=("Consolas", 10),
            bg=_COLOURS["log_bg"],
            fg=_COLOURS["fg"],
            insertbackground=_COLOURS["fg"],
            relief=tk.FLAT,
        )
        folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)

        def browse_folder() -> None:
            """Open a directory chooser for the plugin folder."""
            path = filedialog.askdirectory(
                title="Select VST Plugin Folder",
                initialdir=folder_var.get() or None,
            )
            if path:
                folder_var.set(path)

        tk.Button(
            folder_frame, text="Browse...",
            font=("Segoe UI", 9),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=10, pady=4, cursor="hand2",
            command=browse_folder,
        ).pack(side=tk.RIGHT, padx=(4, 0))

        def auto_detect() -> None:
            """Find and offer common plugin folder paths."""
            found = [p for p in _COMMON_PLUGIN_PATHS if os.path.isdir(p)]
            if not found:
                messagebox.showinfo(
                    "Auto-Detect",
                    "No common VST plugin folders were found on this system.\n"
                    "Use 'Browse' to select your folder manually.",
                    parent=dialog,
                )
                return
            # Show a selection dialog
            sel_dialog = tk.Toplevel(dialog)
            sel_dialog.title("Detected Plugin Folders")
            sel_dialog.configure(bg=_COLOURS["bg_dark"])
            sel_dialog.geometry("480x300")
            sel_dialog.transient(dialog)
            sel_dialog.grab_set()

            tk.Label(
                sel_dialog,
                text="Select a plugin folder:",
                font=("Segoe UI", 10, "bold"),
                fg=_COLOURS["fg"], bg=_COLOURS["bg_dark"],
            ).pack(anchor=tk.W, padx=12, pady=(12, 6))

            listbox = tk.Listbox(
                sel_dialog,
                font=("Consolas", 9),
                bg=_COLOURS["log_bg"], fg=_COLOURS["fg"],
                selectbackground=_COLOURS["button_hover"],
                selectforeground=_COLOURS["fg_bright"],
                relief=tk.FLAT, borderwidth=0, height=10,
            )
            for p in found:
                listbox.insert(tk.END, p)
            listbox.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

            def select_path() -> None:
                sel = listbox.curselection()
                if sel:
                    folder_var.set(found[sel[0]])
                    sel_dialog.destroy()

            tk.Button(
                sel_dialog, text="Select",
                font=("Segoe UI", 10, "bold"),
                fg=_COLOURS["fg_bright"], bg=_COLOURS["green"],
                activebackground="#00c853", bd=0,
                padx=16, pady=6, cursor="hand2",
                command=select_path,
            ).pack(pady=8)

        tk.Button(
            folder_frame, text="Auto-Detect",
            font=("Segoe UI", 9),
            fg=_COLOURS["accent"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=10, pady=4, cursor="hand2",
            command=auto_detect,
        ).pack(side=tk.RIGHT, padx=(4, 0))

        # --- VirusTotal API Key ---
        tk.Label(
            dialog,
            text="VirusTotal API Key",
            font=("Segoe UI", 11, "bold"),
            fg=_COLOURS["fg"],
            bg=_COLOURS["bg_dark"],
        ).pack(anchor=tk.W, padx=20, pady=(16, 4))

        tk.Label(
            dialog,
            text=(
                "Optional. Enables hash lookup against 70+ AV engines.\n"
                "Get a free key at: https://www.virustotal.com/gui/join"
            ),
            font=("Segoe UI", 9),
            fg=_COLOURS["fg_dim"],
            bg=_COLOURS["bg_dark"],
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=20)

        vt_frame = tk.Frame(dialog, bg=_COLOURS["bg_dark"])
        vt_frame.pack(fill=tk.X, padx=20, pady=(8, 0))

        vt_var = tk.StringVar(value=self._config.vt_api_key)
        vt_entry = tk.Entry(
            vt_frame,
            textvariable=vt_var,
            font=("Consolas", 10),
            bg=_COLOURS["log_bg"],
            fg=_COLOURS["fg"],
            insertbackground=_COLOURS["fg"],
            relief=tk.FLAT,
            show="\u2022",
        )
        vt_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)

        _vt_visible = tk.BooleanVar(value=False)

        def toggle_vt_visibility() -> None:
            """Toggle between masked and plain-text display of the API key."""
            if _vt_visible.get():
                vt_entry.configure(show="")
            else:
                vt_entry.configure(show="\u2022")
            _vt_visible.set(not _vt_visible.get())

        tk.Button(
            vt_frame, text="Show",
            font=("Segoe UI", 9),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=12, pady=4, cursor="hand2",
            command=toggle_vt_visibility,
        ).pack(side=tk.RIGHT, padx=(8, 0))

        # --- Save / Cancel ---
        btn_frame = tk.Frame(dialog, bg=_COLOURS["bg_dark"])
        btn_frame.pack(fill=tk.X, padx=20, pady=20)

        def save_and_close() -> None:
            """Persist settings and dismiss the configuration dialog."""
            self._config.plugin_folder = folder_var.get().strip()
            self._config.vt_api_key = vt_var.get().strip()
            folder_display = (
                self._truncate_path(self._config.plugin_folder)
                if self._config.plugin_folder
                else "Not configured"
            )
            self._folder_label.configure(
                text=f"\U0001f4c1 Plugin folder: {folder_display}"
            )
            vt_status = "configured" if self._config.vt_api_key else "not set"
            self._log(
                f"Settings saved \u2014 plugin folder: {self._config.plugin_folder or '(none)'}"
                f" | VT API key: {vt_status}",
                "info",
            )
            dialog.destroy()

        tk.Button(
            btn_frame, text="Save",
            font=("Segoe UI", 10, "bold"),
            fg=_COLOURS["fg_bright"], bg=_COLOURS["green"],
            activebackground="#00c853", bd=0,
            padx=20, pady=6, cursor="hand2",
            command=save_and_close,
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_frame, text="Cancel",
            font=("Segoe UI", 10),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=20, pady=6, cursor="hand2",
            command=dialog.destroy,
        ).pack(side=tk.LEFT)

    # =====================================================================
    # Welcome Dialog (first-run)
    # =====================================================================

    def _show_welcome(self) -> None:
        """Display a welcome dialog on first launch."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Welcome to VST-Sentry")
        dialog.configure(bg=_COLOURS["bg_dark"])
        dialog.geometry("500x440")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Centre on parent
        dialog.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() - 500) // 2
        py = self.root.winfo_y() + (self.root.winfo_height() - 440) // 2
        dialog.geometry(f"+{px}+{py}")

        # Shield icon
        tk.Label(
            dialog, text="\u25c8",
            font=("Segoe UI", 48),
            fg=_COLOURS["accent"], bg=_COLOURS["bg_dark"],
        ).pack(pady=(24, 0))

        tk.Label(
            dialog, text="Welcome to VST-Sentry",
            font=("Segoe UI", 18, "bold"),
            fg=_COLOURS["fg_bright"], bg=_COLOURS["bg_dark"],
        ).pack(pady=(0, 4))

        tk.Label(
            dialog, text=f"v{APP_VERSION}",
            font=("Segoe UI", 10),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_dark"],
        ).pack()

        desc_text = (
            "VST-Sentry scans VST and DLL plugin files for security threats\n"
            "before they reach your DAW. It detects:\n\n"
            "\u2022  Suspicious Windows API imports (process injection, keylogging)\n"
            "\u2022  Packed or encrypted DLL sections (common in trojans)\n"
            "\u2022  Unsigned binaries with suspicious behaviour\n"
            "\u2022  Known malware signatures via VirusTotal\n"
            "\u2022  MITRE ATT&CK techniques from sandbox analysis\n\n"
            "Get started by dropping a .dll, .vst3, or installer .exe onto the\n"
            "drop zone, or use File \u2192 Open to browse."
        )
        tk.Label(
            dialog, text=desc_text,
            font=("Segoe UI", 10),
            fg=_COLOURS["fg"], bg=_COLOURS["bg_dark"],
            justify=tk.LEFT, wraplength=420,
        ).pack(padx=30, pady=16)

        def close_welcome() -> None:
            self._config.is_first_run = False
            dialog.destroy()

        btn_frame = tk.Frame(dialog, bg=_COLOURS["bg_dark"])
        btn_frame.pack(pady=(0, 20))

        tk.Button(
            btn_frame, text="Get Started",
            font=("Segoe UI", 11, "bold"),
            fg=_COLOURS["fg_bright"], bg=_COLOURS["accent"],
            activebackground="#29b6f6", bd=0,
            padx=30, pady=8, cursor="hand2",
            command=close_welcome,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            btn_frame, text="Open Settings",
            font=("Segoe UI", 10),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=20, pady=8, cursor="hand2",
            command=lambda: (close_welcome(), self.root.after(200, self._open_settings)),
        ).pack(side=tk.LEFT)

    # =====================================================================
    # About Dialog
    # =====================================================================

    def _show_about(self) -> None:
        """Display an About dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("About VST-Sentry")
        dialog.configure(bg=_COLOURS["bg_dark"])
        dialog.geometry("400x320")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() - 400) // 2
        py = self.root.winfo_y() + (self.root.winfo_height() - 320) // 2
        dialog.geometry(f"+{px}+{py}")

        tk.Label(
            dialog, text="\u25c8  VST-Sentry",
            font=("Segoe UI", 20, "bold"),
            fg=_COLOURS["accent"], bg=_COLOURS["bg_dark"],
        ).pack(pady=(24, 4))

        tk.Label(
            dialog, text=f"Version {APP_VERSION}",
            font=("Segoe UI", 11),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_dark"],
        ).pack()

        info_text = (
            "A security scanner for VST / DLL plugin files.\n\n"
            "\u2022  103 Red-Flag API detection database\n"
            "\u2022  Shannon entropy analysis (packing / encryption)\n"
            "\u2022  Authenticode digital signature verification\n"
            "\u2022  VirusTotal integration (70+ AV engines)\n"
            "\u2022  MITRE ATT&CK technique mapping\n"
            "\u2022  Sandbox behaviour analysis\n\n"
            "License: MIT"
        )
        tk.Label(
            dialog, text=info_text,
            font=("Segoe UI", 10),
            fg=_COLOURS["fg"], bg=_COLOURS["bg_dark"],
            justify=tk.LEFT,
        ).pack(padx=30, pady=16)

        tk.Button(
            dialog, text="Close",
            font=("Segoe UI", 10),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=20, pady=6, cursor="hand2",
            command=dialog.destroy,
        ).pack(pady=(0, 16))

    # =====================================================================
    # Keyboard Shortcuts Reference
    # =====================================================================

    def _show_shortcuts(self) -> None:
        """Display a keyboard shortcuts quick-reference dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Keyboard Shortcuts")
        dialog.configure(bg=_COLOURS["bg_dark"])
        dialog.geometry("380x380")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.update_idletasks()
        px = self.root.winfo_x() + (self.root.winfo_width() - 380) // 2
        py = self.root.winfo_y() + (self.root.winfo_height() - 380) // 2
        dialog.geometry(f"+{px}+{py}")

        tk.Label(
            dialog, text="Keyboard Shortcuts",
            font=("Segoe UI", 14, "bold"),
            fg=_COLOURS["accent"], bg=_COLOURS["bg_dark"],
        ).pack(pady=(20, 12))

        shortcuts = [
            ("Ctrl + O", "Open file for analysis"),
            ("Ctrl + E", "Export analysis report"),
            ("Ctrl + F", "Find in analysis log"),
            ("Ctrl + L", "Clear the analysis log"),
            ("Ctrl + H", "Toggle scan history panel"),
            ("F5", "Re-scan last analysed file"),
            ("Enter", "Next match (in search bar)"),
            ("Escape", "Close search bar"),
        ]

        for key, desc in shortcuts:
            row = tk.Frame(dialog, bg=_COLOURS["bg_dark"])
            row.pack(fill=tk.X, padx=30, pady=2)
            tk.Label(
                row, text=key, width=14, anchor=tk.W,
                font=("Consolas", 10, "bold"),
                fg=_COLOURS["accent"], bg=_COLOURS["bg_dark"],
            ).pack(side=tk.LEFT)
            tk.Label(
                row, text=desc, anchor=tk.W,
                font=("Segoe UI", 10),
                fg=_COLOURS["fg"], bg=_COLOURS["bg_dark"],
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(
            dialog, text="Close",
            font=("Segoe UI", 10),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=20, pady=6, cursor="hand2",
            command=dialog.destroy,
        ).pack(pady=16)

    # =====================================================================
    # Export
    # =====================================================================

    def _export_report(self) -> None:
        """Save the current analysis report to text, JSON, or HTML."""
        if not self._current_result:
            messagebox.showinfo("Export", "No analysis results to export.")
            return

        default_name = (
            f"VST-Sentry_Report_{self._current_result.file_name}_{datetime.now():%Y%m%d_%H%M%S}.txt"
        )
        file_path = filedialog.asksaveasfilename(
            title="Export Analysis Report",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[
                ("Text files", "*.txt"),
                ("HTML files", "*.html"),
                ("PDF files", "*.pdf"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            if file_path.lower().endswith(".json"):
                content = self._current_result.to_json(indent=2)
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
            elif file_path.lower().endswith((".html", ".htm")):
                content = self._generate_html_report(self._current_result)
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
            elif file_path.lower().endswith(".pdf"):
                pdf_bytes = self._generate_pdf_report(self._current_result)
                with open(file_path, "wb") as fh:
                    fh.write(pdf_bytes)
            else:
                content = generate_report(self._current_result)
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(content)

            self._log(f"\u2714  Report exported to: {file_path}", "success")
        except Exception as exc:
            self._log(f"\u2718  Export failed: {exc}", "error")

    # =====================================================================
    # Copy SHA-256 to Clipboard
    # =====================================================================

    def _copy_sha256(self) -> None:
        """Copy the current result's SHA-256 hash to the system clipboard."""
        if not self._current_result:
            return
        sha = self._current_result.sha256
        self.root.clipboard_clear()
        self.root.clipboard_append(sha)
        self.root.update()  # Required for clipboard to persist on some OS

        # Briefly flash the button text to confirm the copy
        original_text = self._copy_sha_btn.cget("text")
        original_fg = self._copy_sha_btn.cget("fg")
        self._copy_sha_btn.configure(
            text="\u2714  Copied!", fg=_COLOURS["clipboard"],
        )
        self.root.after(
            1200,
            lambda: self._copy_sha_btn.configure(
                text=original_text, fg=original_fg,
            ),
        )
        self._log(f"\u2714  SHA-256 copied to clipboard: {sha}", "success")

    # =====================================================================
    # Compare Two Scan Results
    # =====================================================================

    def _compare_scans(self) -> None:
        """Open a dialog to compare two scan results from history."""
        entries = self._history.entries
        if len(entries) < 2:
            messagebox.showinfo(
                "Compare Scans",
                "At least two scans are needed in history to compare.",
            )
            return

        # Create a simple two-list selection dialog
        dlg = tk.Toplevel(self.root)
        dlg.title("Compare Scans")
        dlg.configure(bg=_COLOURS["bg_dark"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("640x420")
        dlg.resizable(False, False)

        tk.Label(
            dlg, text="Select two scans to compare:",
            font=("Segoe UI", 11, "bold"),
            fg=_COLOURS["fg_bright"], bg=_COLOURS["bg_dark"],
        ).pack(pady=(16, 8))

        list_frame = tk.Frame(dlg, bg=_COLOURS["bg_dark"])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        # Left list — Scan A
        tk.Label(
            list_frame, text="Scan A",
            font=("Segoe UI", 9, "bold"),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_dark"],
        ).grid(row=0, column=0, sticky=tk.W)
        list_a = tk.Listbox(
            list_frame, font=("Consolas", 9),
            bg=_COLOURS["bg_input"], fg=_COLOURS["fg"],
            selectbackground=_COLOURS["accent"],
            height=12, width=38, exportselection=False,
        )
        list_a.grid(row=1, column=0, padx=(0, 8), sticky=tk.NSEW)

        # Right list — Scan B
        tk.Label(
            list_frame, text="Scan B",
            font=("Segoe UI", 9, "bold"),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_dark"],
        ).grid(row=0, column=1, sticky=tk.W)
        list_b = tk.Listbox(
            list_frame, font=("Consolas", 9),
            bg=_COLOURS["bg_input"], fg=_COLOURS["fg"],
            selectbackground=_COLOURS["accent"],
            height=12, width=38, exportselection=False,
        )
        list_b.grid(row=1, column=1, sticky=tk.NSEW)

        list_frame.columnconfigure(0, weight=1)
        list_frame.columnconfigure(1, weight=1)

        # Populate both lists
        for entry in entries:
            label = f"{entry.file_name}  [{entry.verdict}  {entry.risk_score}pts]"
            list_a.insert(tk.END, label)
            list_b.insert(tk.END, label)

        # Pre-select first two
        list_a.selection_set(0)
        list_b.selection_set(1) if len(entries) > 1 else None

        def _on_compare() -> None:
            sel_a = list_a.curselection()
            sel_b = list_b.curselection()
            if not sel_a or not sel_b:
                messagebox.showwarning(
                    "Compare", "Please select one scan from each list.",
                    parent=dlg,
                )
                return
            ea = entries[sel_a[0]]
            eb = entries[sel_b[0]]
            dlg.destroy()
            self._show_comparison(ea, eb)

        tk.Button(
            dlg, text="Compare",
            font=("Segoe UI", 10, "bold"),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=20, pady=6, cursor="hand2",
            command=_on_compare,
        ).pack(pady=(12, 16))

    def _show_comparison(self, a: 'ScanHistoryEntry', b: 'ScanHistoryEntry') -> None:
        """Display a side-by-side comparison of two scan history entries."""
        self._log("", "info")
        self._log(f"{'=' * 60}", "accent")
        self._log("  SCAN COMPARISON", "header")
        self._log(f"{'=' * 60}", "accent")
        self._log("", "info")

        # Header row
        col_w = 28
        self._log(
            f"  {'Field':<18s} {'Scan A':<{col_w}s} {'Scan B':<{col_w}s}",
            "accent",
        )
        self._log(f"  {'-' * 18} {'-' * col_w} {'-' * col_w}", "accent")

        rows = [
            ("File", a.file_name, b.file_name),
            ("Verdict", a.verdict, b.verdict),
            ("Risk Score", str(a.risk_score), str(b.risk_score)),
            ("Flagged APIs", str(a.flagged_count), str(b.flagged_count)),
            ("VT Detections", a.vt_detections or "N/A", b.vt_detections or "N/A"),
            ("SHA-256", a.sha256[:24] + "..." if a.sha256 else "N/A",
             b.sha256[:24] + "..." if b.sha256 else "N/A"),
            ("Date", a.scan_date[:19], b.scan_date[:19]),
        ]

        for label, va, vb in rows:
            # Highlight differences
            tag = "warning" if va != vb else "info"
            self._log(
                f"  {label:<18s} {va:<{col_w}s} {vb:<{col_w}s}", tag,
            )

        self._log("", "info")

        # Score delta
        delta = a.risk_score - b.risk_score
        if delta > 0:
            self._log(
                f"  Scan A scored {delta} points higher than Scan B.", "warning",
            )
        elif delta < 0:
            self._log(
                f"  Scan B scored {abs(delta)} points higher than Scan A.", "warning",
            )
        else:
            self._log("  Both scans returned the same risk score.", "success")

        self._log(f"{'=' * 60}", "accent")
        self._log("", "info")

    @staticmethod
    def _generate_html_report(result: AnalysisResult) -> str:
        """Generate an HTML-formatted analysis report."""
        verdict = result.verdict
        verdict_colour = {
            "Safe": "#00e676", "Suspicious": "#ffd740", "High Risk": "#ff5252",
        }.get(verdict, "#78909c")

        text_report = generate_report(result)
        # Escape HTML entities in the text report
        escaped = (
            text_report
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        # Pre-compute ternary values for the HTML template
        score_range = (
            "Safe range" if result.risk_score <= 4
            else "Suspicious range" if result.risk_score <= 19
            else "High risk"
        )
        api_colour = "#ff5252" if result.flagged_count else "#00e676"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VST-Sentry Report &mdash; {result.file_name}</title>
<style>
  body {{
    background: #1a1a2e; color: #e0e0e0;
    font-family: 'Segoe UI', system-ui, sans-serif;
    margin: 0; padding: 40px;
  }}
  .header {{
    display: flex; align-items: center; gap: 16px;
    border-bottom: 2px solid #2c3e6b; padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .header h1 {{ color: #4fc3f7; margin: 0; font-size: 28px; }}
  .header .version {{ color: #8892a4; font-size: 14px; }}
  .cards {{
    display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;
  }}
  .card {{
    background: #1e2a47; border: 1px solid #2c3e6b;
    border-radius: 8px; padding: 16px 20px; flex: 1; min-width: 140px;
  }}
  .card .label {{ font-size: 11px; color: #8892a4; text-transform: uppercase;
    font-weight: 700; letter-spacing: 0.5px; }}
  .card .value {{ font-size: 28px; font-weight: 700; margin: 4px 0; }}
  .card .detail {{ font-size: 12px; color: #8892a4; }}
  .verdict-card .value {{ color: {verdict_colour}; }}
  .report {{
    background: #0d1b2a; border: 1px solid #2c3e6b;
    border-radius: 8px; padding: 24px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px; line-height: 1.6;
    white-space: pre-wrap; word-wrap: break-word;
    overflow-x: auto;
  }}
  .footer {{
    margin-top: 24px; color: #8892a4; font-size: 12px;
    border-top: 1px solid #2c3e6b; padding-top: 16px;
  }}
</style>
</head>
<body>
  <div class="header">
    <h1>&#x25C8; VST-Sentry Report</h1>
    <span class="version">v{APP_VERSION}</span>
  </div>
  <div class="cards">
    <div class="card verdict-card">
      <div class="label">Verdict</div>
      <div class="value">{verdict.upper()}</div>
      <div class="detail">{result.file_name}</div>
    </div>
    <div class="card">
      <div class="label">Risk Score</div>
      <div class="value" style="color:{verdict_colour}">{result.risk_score}</div>
      <div class="detail">{score_range}</div>
    </div>
    <div class="card">
      <div class="label">Flagged APIs</div>
      <div class="value" style="color:{api_colour}">{result.flagged_count}</div>
      <div class="detail">of {result.total_imports} total imports</div>
    </div>
    <div class="card">
      <div class="label">SHA-256</div>
      <div class="value" style="font-size:11px;word-break:break-all;">{result.sha256}</div>
    </div>
  </div>
  <div class="report">{escaped}</div>
  <div class="footer">
    Generated by VST-Sentry v{APP_VERSION} on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  </div>
</body>
</html>"""
        return html

    # =====================================================================
    # Auto-Update Check (stub)
    # =====================================================================

    def _check_for_updates(self) -> None:
        """Check GitHub releases for a newer version (runs in background)."""
        self._log_ts("Checking for updates...", "info")
        threading.Thread(
            target=self._do_update_check, daemon=True,
        ).start()

    def _do_update_check(self) -> None:
        """Background worker for update check."""
        try:
            req = urllib.request.Request(
                GITHUB_RELEASES_URL,
                headers={"User-Agent": f"VST-Sentry/{APP_VERSION}"},
            )
            with urllib.request.urlopen(
                req, timeout=UPDATE_CHECK_TIMEOUT
            ) as resp:
                # GitHub redirects to /releases/tag/vX.Y.Z
                final_url = resp.url
                # Extract version tag from URL
                tag = final_url.rstrip("/").rsplit("/", 1)[-1]
                remote_ver = tag.lstrip("vV")
                if remote_ver and remote_ver != APP_VERSION:
                    self.root.after(
                        0,
                        lambda: self._notify_update(remote_ver, final_url),
                    )
                else:
                    self.root.after(
                        0,
                        lambda: self._log_ts(
                            f"You are running the latest version (v{APP_VERSION}).",
                            "success",
                        ),
                    )
        except Exception:
            self.root.after(
                0,
                lambda: self._log_ts(
                    "Update check failed \u2014 could not reach GitHub.",
                    "warning",
                ),
            )

    def _notify_update(self, remote_ver: str, url: str) -> None:
        """Show a dialog informing the user about a new version."""
        self._log_ts(
            f"A newer version is available: v{remote_ver} "
            f"(current: v{APP_VERSION})",
            "accent",
        )
        answer = messagebox.askyesno(
            "Update Available",
            f"VST-Sentry v{remote_ver} is available.\n"
            f"You are running v{APP_VERSION}.\n\n"
            f"Open the download page?",
        )
        if answer:
            webbrowser.open(url)

    # =====================================================================
    # PDF Export Helper
    # =====================================================================

    @staticmethod
    def _generate_pdf_report(result: 'AnalysisResult') -> bytes:
        """Generate a simple plain-text PDF report without external libs.

        Uses a minimal PDF 1.4 structure with a single-stream page
        containing the text report rendered in Courier.
        """
        text_report = generate_report(result)
        lines = text_report.splitlines()

        # Minimal PDF builder
        font_size = 10
        leading = 13
        margin_x = 50
        margin_top = 750
        page_height = 842   # A4
        page_width = 595
        bottom_margin = 50

        # Split into pages
        usable = margin_top - bottom_margin
        lines_per_page = max(1, int(usable / leading))
        pages_text: list[list[str]] = []
        for idx in range(0, len(lines), lines_per_page):
            pages_text.append(lines[idx:idx + lines_per_page])
        if not pages_text:
            pages_text = [[""]]

        # PDF helper to escape special chars in text strings
        def _esc(s: str) -> str:
            return (
                s.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
            )

        objects: list[bytes] = []

        def _add_obj(content: bytes) -> int:
            idx_val = len(objects) + 1
            objects.append(content)
            return idx_val

        # Object 1: Catalog
        _add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")

        # Object 2: Pages (placeholder, updated later)
        pages_obj_idx = _add_obj(b"placeholder")

        # Object 3: Font
        _add_obj(
            b"<< /Type /Font /Subtype /Type1 "
            b"/BaseFont /Courier /Encoding /WinAnsiEncoding >>"
        )

        page_obj_ids: list[int] = []
        for page_lines in pages_text:
            # Build stream content
            stream_lines = [
                f"BT /F1 {font_size} Tf {leading} TL",
                f"{margin_x} {margin_top} Td",
            ]
            for line in page_lines:
                safe = _esc(line)
                stream_lines.append(f"({safe}) '")
            stream_lines.append("ET")
            stream_data = "\n".join(stream_lines).encode("latin-1", errors="replace")

            stream_obj = (
                b"<< /Length " + str(len(stream_data)).encode() + b" >>\n"
                b"stream\n" + stream_data + b"\nendstream"
            )
            content_id = _add_obj(stream_obj)

            page_obj = (
                b"<< /Type /Page /Parent 2 0 R "
                b"/MediaBox [0 0 "
                + f"{page_width} {page_height}".encode() + b"] "
                b"/Contents " + f"{content_id} 0 R".encode() + b" "
                b"/Resources << /Font << /F1 3 0 R >> >> >>"
            )
            pid = _add_obj(page_obj)
            page_obj_ids.append(pid)

        # Update Pages object
        kids = " ".join(f"{p} 0 R" for p in page_obj_ids)
        objects[pages_obj_idx - 1] = (
            f"<< /Type /Pages /Kids [{kids}] "
            f"/Count {len(page_obj_ids)} >>"
        ).encode()

        # Serialize
        pdf_parts: list[bytes] = [b"%PDF-1.4\n"]
        offsets: list[int] = []
        for i, obj in enumerate(objects):
            offsets.append(len(b"".join(pdf_parts)))
            pdf_parts.append(
                f"{i + 1} 0 obj\n".encode() + obj + b"\nendobj\n"
            )

        xref_offset = len(b"".join(pdf_parts))
        pdf_parts.append(b"xref\n")
        pdf_parts.append(f"0 {len(objects) + 1}\n".encode())
        pdf_parts.append(b"0000000000 65535 f \n")
        for off in offsets:
            pdf_parts.append(f"{off:010d} 00000 n \n".encode())

        pdf_parts.append(b"trailer\n")
        pdf_parts.append(
            f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
        )
        pdf_parts.append(b"startxref\n")
        pdf_parts.append(f"{xref_offset}\n".encode())
        pdf_parts.append(b"%%EOF\n")

        return b"".join(pdf_parts)

    # =====================================================================
    # Logging Helpers
    # =====================================================================

    def _log(self, message: str, tag: str = "info") -> None:
        """Append a line to the analysis log (thread-safe via root.after)."""

        def _append() -> None:
            self._log_text.configure(state=tk.NORMAL)
            self._log_text.insert(tk.END, message + "\n", tag)
            self._log_text.see(tk.END)
            self._log_text.configure(state=tk.DISABLED)

        # If called from a background thread, schedule on GUI thread
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, _append)
        else:
            _append()

    def _log_ts(self, message: str, tag: str = "info") -> None:
        """Log a message with a HH:MM:SS timestamp prefix and severity icon."""
        ts = datetime.now().strftime("%H:%M:%S")
        icon = _LOG_ICONS.get(tag, "")
        self._log(f"  [{ts}]  {icon}{message}", tag)

    def _clear_log(self) -> None:
        """Clear the analysis log."""
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.configure(state=tk.DISABLED)

    # =====================================================================
    # Status Indicator
    # =====================================================================

    def _set_status(self, level: str, message: str) -> None:
        """
        Update the status indicator dot colour and label text.

        Args:
            level: One of 'Ready', 'Analyzing', 'Safe', 'Suspicious',
                   'High Risk', 'Error'.
            message: Human-readable status text.
        """
        colour = _STATUS_COLOURS.get(level, _COLOURS["grey"])
        self._status_canvas.itemconfig(self._status_dot, fill=colour)
        self._status_canvas.itemconfig(self._glow_dot, outline=colour)
        self._status_label.configure(text=f"Status: {message}")

        # Update detail text
        detail = ""
        if self._current_result and level not in ("Ready", "Analyzing"):
            detail = f"Score: {self._current_result.risk_score}  |  {self._current_result.file_name}"
        self._status_detail.configure(text=detail)

    # =====================================================================
    # Statistics Footer
    # =====================================================================

    def _build_stats_footer(self) -> None:
        """Build a thin footer bar showing lifetime scan statistics."""
        self._stats_bar = tk.Frame(self.root, bg=_COLOURS["bg_mid"], height=24)
        self._stats_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._stats_label = tk.Label(
            self._stats_bar,
            text=self._format_stats_text(),
            font=("Segoe UI", 8),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_mid"],
            anchor=tk.W,
        )
        self._stats_label.pack(side=tk.LEFT, padx=12, pady=2)

        # Version tag on right side
        tk.Label(
            self._stats_bar,
            text=f"v{APP_VERSION}",
            font=("Segoe UI", 8),
            fg=_COLOURS["fg_dim"], bg=_COLOURS["bg_mid"],
            anchor=tk.E,
        ).pack(side=tk.RIGHT, padx=12, pady=2)

    def _format_stats_text(self) -> str:
        """Build the statistics string from history data."""
        entries = self._history.entries
        total = len(entries)
        if total == 0:
            return "No scans yet  \u00b7  Press F1 for shortcuts"
        safe = sum(1 for e in entries if e.verdict == "Safe")
        susp = sum(1 for e in entries if e.verdict == "Suspicious")
        high = sum(1 for e in entries if e.verdict == "High Risk")
        return (
            f"Total scans: {total}  \u00b7  "
            f"\u2714 Safe: {safe}  \u00b7  "
            f"\u26a0 Suspicious: {susp}  \u00b7  "
            f"\u26d4 High Risk: {high}  \u00b7  "
            f"F1 for shortcuts"
        )

    def _update_stats_footer(self) -> None:
        """Refresh the statistics footer text."""
        if hasattr(self, "_stats_label"):
            self._stats_label.configure(text=self._format_stats_text())

    # =====================================================================
    # Keyboard Shortcut Cheat Sheet
    # =====================================================================

    def _show_shortcut_cheat_sheet(self) -> None:
        """Show a modal overlay with all keyboard shortcuts."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Keyboard Shortcuts")
        dlg.configure(bg=_COLOURS["bg_dark"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        dlg.geometry("420x440")

        tk.Label(
            dlg, text="\u2328  Keyboard Shortcuts",
            font=("Segoe UI", 14, "bold"),
            fg=_COLOURS["fg_bright"], bg=_COLOURS["bg_dark"],
        ).pack(pady=(20, 16))

        shortcuts = [
            ("Ctrl+O", "Open file for analysis"),
            ("Ctrl+E", "Export report (TXT/HTML/PDF/JSON)"),
            ("Ctrl+F", "Find in analysis log"),
            ("Ctrl+L", "Clear the analysis log"),
            ("Ctrl+H", "Toggle scan history panel"),
            ("F5", "Re-scan last analysed file"),
            ("F1", "Show this shortcut reference"),
            ("Escape", "Close search bar / dialog"),
        ]

        container = tk.Frame(dlg, bg=_COLOURS["bg_dark"])
        container.pack(fill=tk.BOTH, padx=32, pady=(0, 8))

        for key, desc in shortcuts:
            row = tk.Frame(container, bg=_COLOURS["bg_dark"])
            row.pack(fill=tk.X, pady=3)

            # Key badge
            key_lbl = tk.Label(
                row, text=f" {key} ",
                font=("Consolas", 10, "bold"),
                fg=_COLOURS["fg_bright"],
                bg=_COLOURS["bg_light"],
                padx=6, pady=1,
            )
            key_lbl.pack(side=tk.LEFT, padx=(0, 12))

            tk.Label(
                row, text=desc,
                font=("Segoe UI", 10),
                fg=_COLOURS["fg"], bg=_COLOURS["bg_dark"],
                anchor=tk.W,
            ).pack(side=tk.LEFT)

        tk.Button(
            dlg, text="Close",
            font=("Segoe UI", 10, "bold"),
            fg=_COLOURS["button_fg"], bg=_COLOURS["button_bg"],
            activebackground=_COLOURS["button_hover"],
            bd=0, padx=20, pady=6, cursor="hand2",
            command=dlg.destroy,
        ).pack(pady=(12, 20))

        # Also close with Escape or F1
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.bind("<F1>", lambda e: dlg.destroy())

    # =====================================================================
    # Utilities
    # =====================================================================

    @staticmethod
    def _truncate_path(path: str, max_len: int = 45) -> str:
        """Shorten a file path for display by collapsing the middle."""
        if len(path) <= max_len:
            return path
        head = path[:15]
        tail = path[-(max_len - 18):]
        return f"{head}...{tail}"

    def run(self) -> None:
        """Start the Tkinter main loop."""
        self.root.mainloop()


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main() -> None:
    """Launch the VST-Sentry GUI application."""
    app = VSTSentryApp()
    app.run()


if __name__ == "__main__":
    main()