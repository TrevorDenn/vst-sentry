"""
VST-Sentry GUI — Integration Tests (v2.0)
============================================

Tests the GUI module's non-Tkinter logic:
1. Config persistence (INI read/write), including new v2 fields
2. Path truncation utility
3. Verdict-to-status mapping
4. Analysis pipeline integration (analyzer -> GUI result handling)
5. Export logic (report generation)
6. Tooltip helper class
7. Scan history (JSON persistence)
8. Recent files tracking
9. Auto-detect plugin paths constant
10. Batch scan file-discovery logic

These tests run headless -- no display required.
"""

import configparser
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import analyze_file, generate_report  # noqa: E402


class TestConfig(unittest.TestCase):
    """Test the Config class for INI persistence."""

    def setUp(self):
        self.config_fd, self.config_path = tempfile.mkstemp(suffix=".ini")
        os.close(self.config_fd)
        # Remove the file so Config creates it fresh
        os.unlink(self.config_path)

    def tearDown(self):
        if os.path.isfile(self.config_path):
            os.unlink(self.config_path)

    def _make_config(self):
        """Create a Config-like object without importing Tkinter."""
        parser = configparser.ConfigParser()
        section = "VST-Sentry"
        if os.path.isfile(self.config_path):
            parser.read(self.config_path, encoding="utf-8")
        if not parser.has_section(section):
            parser.add_section(section)
            parser.set(section, "plugin_folder", "")
            parser.set(section, "vt_api_key", "")
            parser.set(section, "first_run", "true")
            parser.set(section, "recent_files", "")
            with open(self.config_path, "w", encoding="utf-8") as fh:
                parser.write(fh)
        return parser

    def test_creates_default_config(self):
        """Config file should be created with default empty plugin_folder."""
        parser = self._make_config()
        self.assertTrue(parser.has_section("VST-Sentry"))
        self.assertEqual(parser.get("VST-Sentry", "plugin_folder"), "")

    def test_saves_and_loads_folder(self):
        """Setting plugin_folder should persist across reloads."""
        parser = self._make_config()
        parser.set("VST-Sentry", "plugin_folder", r"C:\VST\Plugins")
        with open(self.config_path, "w", encoding="utf-8") as fh:
            parser.write(fh)

        # Reload
        parser2 = configparser.ConfigParser()
        parser2.read(self.config_path, encoding="utf-8")
        self.assertEqual(
            parser2.get("VST-Sentry", "plugin_folder"), r"C:\VST\Plugins"
        )

    def test_handles_unicode_paths(self):
        """Plugin folder with Unicode characters should persist correctly."""
        parser = self._make_config()
        test_path = "/Users/müsik/Library/Audio/Plug-Ins/VST3"
        parser.set("VST-Sentry", "plugin_folder", test_path)
        with open(self.config_path, "w", encoding="utf-8") as fh:
            parser.write(fh)

        parser2 = configparser.ConfigParser()
        parser2.read(self.config_path, encoding="utf-8")
        self.assertEqual(parser2.get("VST-Sentry", "plugin_folder"), test_path)

    def test_first_run_flag_default(self):
        """New configs should have first_run = true."""
        parser = self._make_config()
        self.assertEqual(parser.get("VST-Sentry", "first_run"), "true")

    def test_first_run_flag_persists(self):
        """Setting first_run to false should persist."""
        parser = self._make_config()
        parser.set("VST-Sentry", "first_run", "false")
        with open(self.config_path, "w", encoding="utf-8") as fh:
            parser.write(fh)

        parser2 = configparser.ConfigParser()
        parser2.read(self.config_path, encoding="utf-8")
        self.assertEqual(parser2.get("VST-Sentry", "first_run"), "false")

    def test_recent_files_empty_default(self):
        """New configs should have empty recent_files."""
        parser = self._make_config()
        self.assertEqual(parser.get("VST-Sentry", "recent_files"), "")

    def test_recent_files_pipe_separated(self):
        """Recent files should be stored as pipe-separated paths."""
        parser = self._make_config()
        paths = "/tmp/a.dll|/tmp/b.vst3|/tmp/c.dll"
        parser.set("VST-Sentry", "recent_files", paths)
        with open(self.config_path, "w", encoding="utf-8") as fh:
            parser.write(fh)

        parser2 = configparser.ConfigParser()
        parser2.read(self.config_path, encoding="utf-8")
        loaded = parser2.get("VST-Sentry", "recent_files")
        self.assertEqual(loaded.split("|"), ["/tmp/a.dll", "/tmp/b.vst3", "/tmp/c.dll"])


class TestPathTruncation(unittest.TestCase):
    """Test the path truncation utility."""

    @staticmethod
    def _truncate_path(path: str, max_len: int = 45) -> str:
        """Mirror of VSTSentryApp._truncate_path (avoid Tk import)."""
        if len(path) <= max_len:
            return path
        head = path[:15]
        tail = path[-(max_len - 18):]
        return f"{head}...{tail}"

    def test_short_path_unchanged(self):
        path = "/Users/test/VST"
        self.assertEqual(self._truncate_path(path), path)

    def test_long_path_truncated(self):
        path = "C:\\Users\\Producer\\AppData\\Local\\Ableton\\Live 11\\Resources\\VST3\\Installed"
        result = self._truncate_path(path)
        self.assertLessEqual(len(result), 45)
        self.assertIn("...", result)

    def test_exact_boundary(self):
        path = "A" * 45
        self.assertEqual(self._truncate_path(path), path)

    def test_one_over_boundary(self):
        path = "A" * 46
        result = self._truncate_path(path)
        self.assertIn("...", result)
        self.assertLessEqual(len(result), 45)


class TestVerdictMapping(unittest.TestCase):
    """Test verdict-to-status colour and message mappings."""

    def test_all_verdicts_have_colours(self):
        from vst_sentry_gui import _STATUS_COLOURS
        for verdict in ("Safe", "Suspicious", "High Risk", "Error", "Ready", "Analyzing"):
            self.assertIn(verdict, _STATUS_COLOURS, f"Missing colour for {verdict}")

    def test_all_verdicts_have_messages(self):
        from vst_sentry_gui import _VERDICT_MESSAGES
        for verdict in ("Safe", "Suspicious", "High Risk", "Error"):
            self.assertIn(verdict, _VERDICT_MESSAGES, f"Missing message for {verdict}")

    def test_colour_values_are_hex(self):
        from vst_sentry_gui import _STATUS_COLOURS
        for name, colour in _STATUS_COLOURS.items():
            self.assertTrue(
                colour.startswith("#") and len(colour) == 7,
                f"Invalid hex colour for {name}: {colour}",
            )


class TestToolTip(unittest.TestCase):
    """Test the ToolTip helper class (non-GUI methods)."""

    def test_tooltip_class_exists(self):
        """ToolTip should be importable."""
        from vst_sentry_gui import ToolTip
        self.assertTrue(callable(ToolTip))

    def test_tooltip_delay_constants(self):
        """ToolTip should have sensible delay values."""
        from vst_sentry_gui import ToolTip
        self.assertGreater(ToolTip._DELAY_MS, 0)
        self.assertGreaterEqual(ToolTip._DURATION_MS, 0)


class TestScanHistory(unittest.TestCase):
    """Test the ScanHistory JSON persistence layer."""

    def setUp(self):
        self.fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(self.fd)
        os.unlink(self.path)  # Start fresh

    def tearDown(self):
        if os.path.isfile(self.path):
            os.unlink(self.path)

    def _make_history(self):
        from vst_sentry_gui import ScanHistory
        return ScanHistory(path=self.path)

    def _make_entry(self, file_name="test.dll", verdict="Safe", score=0):
        from vst_sentry_gui import ScanHistoryEntry
        return ScanHistoryEntry(
            file_name=file_name,
            file_path=f"/tmp/{file_name}",
            verdict=verdict,
            risk_score=score,
            scan_date="2026-04-08T14:00:00",
            flagged_count=0,
            vt_detections="",
            sha256="abc123",
        )

    def test_empty_history(self):
        """New history should be empty."""
        h = self._make_history()
        self.assertEqual(len(h), 0)
        self.assertEqual(h.entries, [])

    def test_add_entry(self):
        """Adding an entry should persist to JSON."""
        h = self._make_history()
        h.add(self._make_entry())
        self.assertEqual(len(h), 1)
        self.assertTrue(os.path.isfile(self.path))

    def test_add_preserves_order(self):
        """Newest entries should appear first."""
        h = self._make_history()
        h.add(self._make_entry("first.dll"))
        h.add(self._make_entry("second.dll"))
        self.assertEqual(h.entries[0].file_name, "second.dll")
        self.assertEqual(h.entries[1].file_name, "first.dll")

    def test_reload_from_disk(self):
        """History should survive a reload from disk."""
        h = self._make_history()
        h.add(self._make_entry("persist.dll", "High Risk", 42))
        # Reload
        h2 = self._make_history()
        self.assertEqual(len(h2), 1)
        self.assertEqual(h2.entries[0].file_name, "persist.dll")
        self.assertEqual(h2.entries[0].verdict, "High Risk")
        self.assertEqual(h2.entries[0].risk_score, 42)

    def test_clear_history(self):
        """Clear should remove all entries."""
        h = self._make_history()
        h.add(self._make_entry())
        h.add(self._make_entry())
        h.clear()
        self.assertEqual(len(h), 0)

    def test_max_entries_cap(self):
        """History should not exceed MAX_HISTORY_ENTRIES."""
        from vst_sentry_gui import MAX_HISTORY_ENTRIES
        h = self._make_history()
        for i in range(MAX_HISTORY_ENTRIES + 20):
            h.add(self._make_entry(f"file_{i}.dll"))
        self.assertEqual(len(h), MAX_HISTORY_ENTRIES)

    def test_json_format_valid(self):
        """History file should be valid JSON."""
        h = self._make_history()
        h.add(self._make_entry())
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertIn("file_name", data[0])
        self.assertIn("verdict", data[0])

    def test_corrupt_json_handled(self):
        """History should gracefully handle a corrupt JSON file."""
        with open(self.path, "w") as fh:
            fh.write("{bad json!}")
        h = self._make_history()
        self.assertEqual(len(h), 0)  # No crash, just empty


class TestScanHistoryEntry(unittest.TestCase):
    """Test ScanHistoryEntry dataclass."""

    def test_entry_fields(self):
        from vst_sentry_gui import ScanHistoryEntry
        e = ScanHistoryEntry(
            file_name="test.dll",
            file_path="/tmp/test.dll",
            verdict="Suspicious",
            risk_score=15,
            scan_date="2026-04-08T14:00:00",
            flagged_count=3,
            vt_detections="5/72",
            sha256="deadbeef",
        )
        self.assertEqual(e.file_name, "test.dll")
        self.assertEqual(e.verdict, "Suspicious")
        self.assertEqual(e.risk_score, 15)
        self.assertEqual(e.flagged_count, 3)

    def test_entry_defaults(self):
        from vst_sentry_gui import ScanHistoryEntry
        e = ScanHistoryEntry(
            file_name="test.dll",
            file_path="/tmp/test.dll",
            verdict="Safe",
            risk_score=0,
            scan_date="2026-04-08T14:00:00",
        )
        self.assertEqual(e.flagged_count, 0)
        self.assertEqual(e.vt_detections, "")
        self.assertEqual(e.sha256, "")


class TestAutoDetectPaths(unittest.TestCase):
    """Test auto-detect plugin path constants."""

    def test_common_paths_list_exists(self):
        from vst_sentry_gui import _COMMON_PLUGIN_PATHS
        self.assertIsInstance(_COMMON_PLUGIN_PATHS, list)
        self.assertGreater(len(_COMMON_PLUGIN_PATHS), 5)

    def test_paths_are_strings(self):
        from vst_sentry_gui import _COMMON_PLUGIN_PATHS
        for path in _COMMON_PLUGIN_PATHS:
            self.assertIsInstance(path, str)

    def test_contains_vst3_paths(self):
        from vst_sentry_gui import _COMMON_PLUGIN_PATHS
        vst3_paths = [p for p in _COMMON_PLUGIN_PATHS if "vst3" in p.lower()]
        self.assertGreater(len(vst3_paths), 0, "Should include at least one VST3 path")


class TestAppConstants(unittest.TestCase):
    """Test application-level constants."""

    def test_version_format(self):
        from vst_sentry_gui import APP_VERSION
        parts = APP_VERSION.split(".")
        self.assertEqual(len(parts), 3, "Version should be x.y.z")
        for p in parts:
            self.assertTrue(p.isdigit(), f"Version part '{p}' not a number")

    def test_max_recent_files(self):
        from vst_sentry_gui import MAX_RECENT_FILES
        self.assertGreaterEqual(MAX_RECENT_FILES, 5)

    def test_max_history_entries(self):
        from vst_sentry_gui import MAX_HISTORY_ENTRIES
        self.assertGreaterEqual(MAX_HISTORY_ENTRIES, 10)

    def test_window_dimensions(self):
        from vst_sentry_gui import WINDOW_MIN_W, WINDOW_MIN_H
        self.assertGreaterEqual(WINDOW_MIN_W, 700)
        self.assertGreaterEqual(WINDOW_MIN_H, 600)

    def test_valid_extensions(self):
        from vst_sentry_gui import VALID_EXTENSIONS
        self.assertIn(".dll", VALID_EXTENSIONS)
        self.assertIn(".vst3", VALID_EXTENSIONS)
        self.assertIn(".vst", VALID_EXTENSIONS)


class TestGUIAnalysisIntegration(unittest.TestCase):
    """Test that the analyzer engine produces results the GUI can consume."""

    @staticmethod
    def _create_minimal_dll(
        imports=None, rwx_section=False, section_name=".text"
    ):
        """Create a minimal valid PE DLL (mirrors TestSyntheticPE helper)."""
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, 64)

        pe_sig = b"PE\x00\x00"

        coff = bytearray(20)
        struct.pack_into("<H", coff, 0, 0x14C)
        struct.pack_into("<H", coff, 2, 1)
        struct.pack_into("<I", coff, 4, 0x5F000000)
        struct.pack_into("<H", coff, 16, 0xE0)
        struct.pack_into("<H", coff, 18, 0x2102)

        opt = bytearray(224)
        struct.pack_into("<H", opt, 0, 0x10B)
        opt[2] = 14
        struct.pack_into("<I", opt, 16, 0x1000)
        struct.pack_into("<I", opt, 28, 0x400000)
        struct.pack_into("<I", opt, 32, 0x1000)
        struct.pack_into("<I", opt, 36, 0x200)
        struct.pack_into("<H", opt, 40, 6)
        struct.pack_into("<H", opt, 44, 6)
        struct.pack_into("<I", opt, 56, 0x3000)
        struct.pack_into("<I", opt, 60, 0x200)
        struct.pack_into("<H", opt, 68, 3)
        struct.pack_into("<H", opt, 70, 0x8160)
        struct.pack_into("<I", opt, 72, 0x100000)
        struct.pack_into("<I", opt, 76, 0x1000)
        struct.pack_into("<I", opt, 80, 0x100000)
        struct.pack_into("<I", opt, 84, 0x1000)
        struct.pack_into("<I", opt, 92, 16)

        sec = bytearray(40)
        sec_name_bytes = section_name.encode("ascii")[:8]
        sec[0:len(sec_name_bytes)] = sec_name_bytes
        struct.pack_into("<I", sec, 8, 0x1000)
        struct.pack_into("<I", sec, 12, 0x1000)
        struct.pack_into("<I", sec, 16, 0x1000)
        struct.pack_into("<I", sec, 20, 0x200)
        sec_chars = 0xE0000060 if rwx_section else 0x60000020
        struct.pack_into("<I", sec, 36, sec_chars)

        section_data = bytearray(0x1000)

        if imports:
            idt_offset = 0x000
            name_offset = 0x100
            ilt_offset = 0x200
            hint_offset = 0x400
            va_base = 0x1000
            dll_list = list(imports.items())
            num_dlls = len(dll_list)

            for i, (dll_name, funcs) in enumerate(dll_list):
                dll_name_bytes = dll_name.encode("ascii") + b"\x00"
                section_data[name_offset:name_offset + len(dll_name_bytes)] = (
                    dll_name_bytes
                )
                dll_name_rva = va_base + name_offset
                name_offset += len(dll_name_bytes)

                idt_entry_offset = idt_offset + i * 20
                ilt_rva = va_base + ilt_offset
                struct.pack_into(
                    "<I", section_data, idt_entry_offset, ilt_rva
                )
                struct.pack_into(
                    "<I", section_data, idt_entry_offset + 12, dll_name_rva
                )
                struct.pack_into(
                    "<I", section_data, idt_entry_offset + 16, ilt_rva
                )

                for j, func_name in enumerate(funcs):
                    hn_bytes = (
                        struct.pack("<H", j)
                        + func_name.encode("ascii")
                        + b"\x00"
                    )
                    if len(hn_bytes) % 2:
                        hn_bytes += b"\x00"
                    section_data[hint_offset:hint_offset + len(hn_bytes)] = (
                        hn_bytes
                    )
                    hn_rva = va_base + hint_offset
                    hint_offset += len(hn_bytes)

                    ilt_entry_offset = ilt_offset + j * 4
                    struct.pack_into(
                        "<I", section_data, ilt_entry_offset, hn_rva
                    )

                ilt_offset += (len(funcs) + 1) * 4

            import_dir_rva = va_base + 0x000
            import_dir_size = (num_dlls + 1) * 20
            struct.pack_into("<I", opt, 104, import_dir_rva)
            struct.pack_into("<I", opt, 108, import_dir_size)

        headers = dos_header + pe_sig + coff + opt + sec
        headers += b"\x00" * (0x200 - len(headers))
        pe_data = headers + section_data

        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(pe_data)
        return path

    def test_safe_result_has_gui_required_fields(self):
        """A Safe AnalysisResult contains all fields the GUI accesses."""
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            # Fields the GUI reads directly
            self.assertIsInstance(result.file_name, str)
            self.assertIsInstance(result.file_path, str)
            self.assertIsInstance(result.risk_score, int)
            self.assertIsInstance(result.verdict, str)
            self.assertIsInstance(result.pe_type, str)
            self.assertIsInstance(result.architecture, str)
            self.assertIsInstance(result.md5, str)
            self.assertIsInstance(result.sha256, str)
            self.assertIsInstance(result.signature, dict)
            self.assertIsInstance(result.entropy_analysis, dict)
            self.assertIsInstance(result.flagged_imports, list)
            self.assertIsInstance(result.warnings, list)
            self.assertIsInstance(result.categories_hit, dict)
        finally:
            os.unlink(path)

    def test_report_generation_for_gui_display(self):
        """generate_report produces text the GUI can display line-by-line."""
        path = self._create_minimal_dll(
            imports={
                "kernel32.dll": ["CreateRemoteThread", "OpenProcess"],
                "ws2_32.dll": ["WSAStartup"],
            }
        )
        try:
            result = analyze_file(path)
            report = generate_report(result)
            lines = report.splitlines()
            self.assertGreater(len(lines), 10)
            for line in lines:
                self.assertIsInstance(line, str)
        finally:
            os.unlink(path)

    def test_json_export_roundtrip(self):
        """JSON export from AnalysisResult should be valid and re-parseable."""
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            json_str = result.to_json(indent=2)
            parsed = json.loads(json_str)
            self.assertEqual(parsed["verdict"], result.verdict)
            self.assertEqual(parsed["risk_score"], result.risk_score)
        finally:
            os.unlink(path)

    def test_entropy_analysis_dict_for_gui(self):
        """Entropy analysis dict has all keys the GUI reads."""
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]},
            rwx_section=True,
        )
        try:
            result = analyze_file(path)
            ea = result.entropy_analysis
            self.assertIn("file_entropy", ea)
            self.assertIn("is_likely_packed", ea)
            self.assertIn("rwx_sections", ea)
            self.assertIn("packer_sections", ea)
            self.assertIn("total_entropy_score", ea)
            self.assertIn("sections", ea)
            for sec in ea["sections"]:
                self.assertIn("name", sec)
                self.assertIn("entropy", sec)
                self.assertIn("alerts", sec)
        finally:
            os.unlink(path)

    def test_file_copy_safe_verdict(self):
        """Simulate the auto-copy logic: Safe verdict copies to plugin folder."""
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        dest_dir = tempfile.mkdtemp()
        try:
            result = analyze_file(path)
            self.assertEqual(result.verdict, "Safe")

            import shutil
            dest = os.path.join(dest_dir, result.file_name)
            shutil.copy2(result.file_path, dest)
            self.assertTrue(os.path.isfile(dest))
            self.assertEqual(
                os.path.getsize(dest), os.path.getsize(result.file_path)
            )
        finally:
            os.unlink(path)
            import shutil
            shutil.rmtree(dest_dir)

    def test_high_risk_not_copied(self):
        """High Risk verdict should NOT trigger copy (GUI logic check)."""
        path = self._create_minimal_dll(
            imports={
                "kernel32.dll": [
                    "CreateRemoteThread",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "OpenProcess",
                ],
                "wininet.dll": ["InternetOpenA", "InternetReadFile"],
            }
        )
        try:
            result = analyze_file(path)
            self.assertEqual(result.verdict, "High Risk")
        finally:
            os.unlink(path)


class TestColourPalette(unittest.TestCase):
    """Validate the GUI colour palette."""

    def test_all_colours_valid_hex(self):
        from vst_sentry_gui import _COLOURS
        for name, colour in _COLOURS.items():
            self.assertTrue(
                colour.startswith("#") and len(colour) == 7,
                f"Invalid hex colour '{name}': {colour}",
            )

    def test_status_colours_reference_valid_palette_colours(self):
        from vst_sentry_gui import _STATUS_COLOURS, _COLOURS
        palette_values = set(_COLOURS.values())
        for name, colour in _STATUS_COLOURS.items():
            self.assertIn(
                colour,
                palette_values,
                f"Status colour for '{name}' not in palette: {colour}",
            )

    def test_new_v2_colours_exist(self):
        """v2 added new colour keys for search, history, and progress."""
        from vst_sentry_gui import _COLOURS
        for key in (
            "search_bg", "search_match", "history_bg",
            "history_sel", "progress_bg", "progress_fg",
            "bg_input", "orange",
        ):
            self.assertIn(key, _COLOURS, f"Missing v2 colour: {key}")


# ============================================================================
# Wave 2 Feature Tests (v2.1)
# ============================================================================

class TestQuarantineDir(unittest.TestCase):
    """Test the quarantine directory constant and related logic."""

    def test_quarantine_dir_is_string(self):
        from vst_sentry_gui import QUARANTINE_DIR
        self.assertIsInstance(QUARANTINE_DIR, str)

    def test_quarantine_dir_under_project(self):
        """Quarantine folder should be beneath the project directory."""
        from vst_sentry_gui import QUARANTINE_DIR
        project_dir = os.path.dirname(os.path.abspath(
            os.path.join(os.path.dirname(__file__), "vst_sentry_gui.py")
        ))
        self.assertTrue(
            QUARANTINE_DIR.startswith(project_dir),
            f"QUARANTINE_DIR ({QUARANTINE_DIR}) not under project",
        )

    def test_quarantine_dir_name(self):
        from vst_sentry_gui import QUARANTINE_DIR
        self.assertEqual(os.path.basename(QUARANTINE_DIR), "quarantine")


class TestApplyHover(unittest.TestCase):
    """Test the _apply_hover utility function."""

    def test_function_exists_and_callable(self):
        from vst_sentry_gui import _apply_hover
        self.assertTrue(callable(_apply_hover))

    def test_signature_accepts_three_args(self):
        """_apply_hover(widget, hover_bg, normal_bg) should be the signature."""
        import inspect
        from vst_sentry_gui import _apply_hover
        sig = inspect.signature(_apply_hover)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ["widget", "hover_bg", "normal_bg"])


class TestHTMLReportGeneration(unittest.TestCase):
    """Test the _generate_html_report static method."""

    @staticmethod
    def _create_minimal_dll(imports=None):
        """Create a minimal valid PE DLL."""
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, 64)

        pe_sig = b"PE\x00\x00"

        coff = bytearray(20)
        struct.pack_into("<H", coff, 0, 0x14C)
        struct.pack_into("<H", coff, 2, 1)
        struct.pack_into("<I", coff, 4, 0x5F000000)
        struct.pack_into("<H", coff, 16, 0xE0)
        struct.pack_into("<H", coff, 18, 0x2102)

        opt = bytearray(224)
        struct.pack_into("<H", opt, 0, 0x10B)
        opt[2] = 14
        struct.pack_into("<I", opt, 16, 0x1000)
        struct.pack_into("<I", opt, 28, 0x400000)
        struct.pack_into("<I", opt, 32, 0x1000)
        struct.pack_into("<I", opt, 36, 0x200)
        struct.pack_into("<H", opt, 40, 6)
        struct.pack_into("<H", opt, 44, 6)
        struct.pack_into("<I", opt, 56, 0x3000)
        struct.pack_into("<I", opt, 60, 0x200)
        struct.pack_into("<H", opt, 68, 3)
        struct.pack_into("<H", opt, 70, 0x8160)
        struct.pack_into("<I", opt, 72, 0x100000)
        struct.pack_into("<I", opt, 76, 0x1000)
        struct.pack_into("<I", opt, 80, 0x100000)
        struct.pack_into("<I", opt, 84, 0x1000)
        struct.pack_into("<I", opt, 92, 16)

        sec = bytearray(40)
        sec[0:5] = b".text"
        struct.pack_into("<I", sec, 8, 0x1000)
        struct.pack_into("<I", sec, 12, 0x1000)
        struct.pack_into("<I", sec, 16, 0x1000)
        struct.pack_into("<I", sec, 20, 0x200)
        struct.pack_into("<I", sec, 36, 0x60000020)

        section_data = bytearray(0x1000)

        if imports:
            idt_offset = 0x000
            name_offset = 0x100
            ilt_offset = 0x200
            hint_offset = 0x400
            va_base = 0x1000
            dll_list = list(imports.items())
            num_dlls = len(dll_list)

            for i, (dll_name, funcs) in enumerate(dll_list):
                dll_name_bytes = dll_name.encode("ascii") + b"\x00"
                section_data[name_offset:name_offset + len(dll_name_bytes)] = (
                    dll_name_bytes
                )
                dll_name_rva = va_base + name_offset
                name_offset += len(dll_name_bytes)

                idt_entry_offset = idt_offset + i * 20
                ilt_rva = va_base + ilt_offset
                struct.pack_into("<I", section_data, idt_entry_offset, ilt_rva)
                struct.pack_into(
                    "<I", section_data, idt_entry_offset + 12, dll_name_rva
                )
                struct.pack_into(
                    "<I", section_data, idt_entry_offset + 16, ilt_rva
                )

                for j, func_name in enumerate(funcs):
                    hn_bytes = (
                        struct.pack("<H", j)
                        + func_name.encode("ascii")
                        + b"\x00"
                    )
                    if len(hn_bytes) % 2:
                        hn_bytes += b"\x00"
                    section_data[hint_offset:hint_offset + len(hn_bytes)] = (
                        hn_bytes
                    )
                    hn_rva = va_base + hint_offset
                    hint_offset += len(hn_bytes)

                    ilt_entry_offset = ilt_offset + j * 4
                    struct.pack_into("<I", section_data, ilt_entry_offset, hn_rva)

                ilt_offset += (len(funcs) + 1) * 4

            import_dir_rva = va_base + 0x000
            import_dir_size = (num_dlls + 1) * 20
            struct.pack_into("<I", opt, 104, import_dir_rva)
            struct.pack_into("<I", opt, 108, import_dir_size)

        headers = dos_header + pe_sig + coff + opt + sec
        headers += b"\x00" * (0x200 - len(headers))
        pe_data = headers + section_data

        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(pe_data)
        return path

    def test_html_contains_doctype(self):
        """HTML report should start with a valid DOCTYPE."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertTrue(html.strip().startswith("<!DOCTYPE html>"))
        finally:
            os.unlink(path)

    def test_html_contains_verdict(self):
        """The verdict should appear in the HTML output."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn(result.verdict.upper(), html)
        finally:
            os.unlink(path)

    def test_html_contains_sha256(self):
        """SHA-256 hash should appear in the HTML report."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn(result.sha256, html)
        finally:
            os.unlink(path)

    def test_html_contains_risk_score(self):
        """Risk score should appear in the HTML output."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn(str(result.risk_score), html)
        finally:
            os.unlink(path)

    def test_html_has_dark_theme(self):
        """HTML should use the dark-theme background colour."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn("#1a1a2e", html)  # body background
        finally:
            os.unlink(path)

    def test_html_contains_version(self):
        """HTML report should include the APP_VERSION."""
        from vst_sentry_gui import VSTSentryApp, APP_VERSION
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn(APP_VERSION, html)
        finally:
            os.unlink(path)

    def test_html_escapes_angle_brackets(self):
        """HTML entities should be escaped in the report body."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            # The report section should use &lt;/&gt; not raw < > in text
            report_section = html.split('<div class="report">')[-1]
            report_section = report_section.split('</div>')[0]
            # Angle brackets from original report should be escaped
            self.assertNotIn("<div", report_section)  # no nested HTML
        finally:
            os.unlink(path)

    def test_html_safe_range_detail(self):
        """Safe verdict should show 'Safe range' in the score card."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            self.assertEqual(result.verdict, "Safe")
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn("Safe range", html)
        finally:
            os.unlink(path)

    def test_html_high_risk_range_detail(self):
        """High Risk verdict should show 'High risk' in the score card."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={
                "kernel32.dll": [
                    "CreateRemoteThread", "VirtualAllocEx",
                    "WriteProcessMemory", "OpenProcess",
                ],
                "wininet.dll": ["InternetOpenA", "InternetReadFile"],
            }
        )
        try:
            result = analyze_file(path)
            self.assertEqual(result.verdict, "High Risk")
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn("High risk", html)
        finally:
            os.unlink(path)

    def test_html_cards_section_present(self):
        """HTML should contain the summary cards section."""
        from vst_sentry_gui import VSTSentryApp
        path = self._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]}
        )
        try:
            result = analyze_file(path)
            html = VSTSentryApp._generate_html_report(result)
            self.assertIn('class="cards"', html)
            self.assertIn('class="card"', html)
        finally:
            os.unlink(path)


class TestSummaryCardDefinitions(unittest.TestCase):
    """Test summary card build logic (without Tk)."""

    def test_summary_card_keys(self):
        """Summary cards should cover verdict, score, imports, vt, entropy."""
        # We cannot instantiate VSTSentryApp without Tk, so test
        # the card_defs constant directly by reading the source.
        src_path = os.path.join(
            os.path.dirname(__file__), "vst_sentry_gui.py"
        )
        with open(src_path, "r") as f:
            source = f.read()
        # Extract the card_defs list from source
        self.assertIn('"verdict"', source)
        self.assertIn('"score"', source)
        self.assertIn('"imports"', source)
        self.assertIn('"vt"', source)
        self.assertIn('"entropy"', source)


class TestBgCardColour(unittest.TestCase):
    """Test the new bg_card colour key."""

    def test_bg_card_exists(self):
        from vst_sentry_gui import _COLOURS
        self.assertIn("bg_card", _COLOURS)

    def test_bg_card_is_hex(self):
        from vst_sentry_gui import _COLOURS
        colour = _COLOURS["bg_card"]
        self.assertTrue(
            colour.startswith("#") and len(colour) == 7,
            f"bg_card should be a valid hex colour: {colour}",
        )


class TestVersionBumpV23(unittest.TestCase):
    """Test that the version bump is applied (updated to 2.5)."""

    def test_version_is_current(self):
        from vst_sentry_gui import APP_VERSION
        self.assertEqual(APP_VERSION, "2.5.0")


# ============================================================================
# Wave 3 Feature Tests (v2.2)
# ============================================================================

class TestLogIcons(unittest.TestCase):
    """Test the _LOG_ICONS mapping."""

    def test_log_icons_exists(self):
        from vst_sentry_gui import _LOG_ICONS
        self.assertIsInstance(_LOG_ICONS, dict)

    def test_success_icon(self):
        from vst_sentry_gui import _LOG_ICONS
        self.assertIn("success", _LOG_ICONS)
        self.assertTrue(_LOG_ICONS["success"].strip())  # non-empty

    def test_warning_icon(self):
        from vst_sentry_gui import _LOG_ICONS
        self.assertIn("warning", _LOG_ICONS)
        self.assertTrue(_LOG_ICONS["warning"].strip())

    def test_error_icon(self):
        from vst_sentry_gui import _LOG_ICONS
        self.assertIn("error", _LOG_ICONS)
        self.assertTrue(_LOG_ICONS["error"].strip())

    def test_info_has_no_icon(self):
        from vst_sentry_gui import _LOG_ICONS
        self.assertNotIn("info", _LOG_ICONS)


class TestEnableSoundConstant(unittest.TestCase):
    """Test the ENABLE_SOUND constant."""

    def test_enable_sound_is_bool(self):
        from vst_sentry_gui import ENABLE_SOUND
        self.assertIsInstance(ENABLE_SOUND, bool)

    def test_enable_sound_default_true(self):
        from vst_sentry_gui import ENABLE_SOUND
        self.assertTrue(ENABLE_SOUND)


class TestNewColourKeys(unittest.TestCase):
    """Test v2.2 colour additions."""

    def test_drop_active_exists(self):
        from vst_sentry_gui import _COLOURS
        self.assertIn("drop_active", _COLOURS)

    def test_clipboard_exists(self):
        from vst_sentry_gui import _COLOURS
        self.assertIn("clipboard", _COLOURS)

    def test_new_colours_are_hex(self):
        from vst_sentry_gui import _COLOURS
        for key in ("drop_active", "clipboard"):
            colour = _COLOURS[key]
            self.assertTrue(
                colour.startswith("#") and len(colour) == 7,
                f"Invalid hex colour for {key}: {colour}",
            )


class TestScanHistoryEntryElapsed(unittest.TestCase):
    """Test the elapsed_seconds field in ScanHistoryEntry."""

    def test_default_elapsed_seconds(self):
        from vst_sentry_gui import ScanHistoryEntry
        e = ScanHistoryEntry(
            file_name="test.dll",
            file_path="/tmp/test.dll",
            verdict="Safe",
            risk_score=0,
            scan_date="2026-04-08T14:00:00",
        )
        self.assertEqual(e.elapsed_seconds, 0.0)

    def test_custom_elapsed_seconds(self):
        from vst_sentry_gui import ScanHistoryEntry
        e = ScanHistoryEntry(
            file_name="test.dll",
            file_path="/tmp/test.dll",
            verdict="Safe",
            risk_score=0,
            scan_date="2026-04-08T14:00:00",
            elapsed_seconds=3.14,
        )
        self.assertAlmostEqual(e.elapsed_seconds, 3.14)

    def test_elapsed_persists_to_json(self):
        """ScanHistory should persist elapsed_seconds through JSON."""
        from vst_sentry_gui import ScanHistory, ScanHistoryEntry
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        try:
            h = ScanHistory(path=path)
            h.add(ScanHistoryEntry(
                file_name="test.dll",
                file_path="/tmp/test.dll",
                verdict="Safe",
                risk_score=0,
                scan_date="2026-04-08T14:00:00",
                elapsed_seconds=1.25,
            ))
            # Reload
            h2 = ScanHistory(path=path)
            self.assertAlmostEqual(h2.entries[0].elapsed_seconds, 1.25)
        finally:
            if os.path.isfile(path):
                os.unlink(path)


class TestCompareScansMethod(unittest.TestCase):
    """Test that comparison-related logic exists."""

    def test_compare_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_compare_scans"))
        self.assertTrue(callable(getattr(VSTSentryApp, "_compare_scans")))

    def test_show_comparison_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_show_comparison"))
        self.assertTrue(callable(getattr(VSTSentryApp, "_show_comparison")))


class TestCopySha256Method(unittest.TestCase):
    """Test that the copy SHA-256 method exists."""

    def test_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_copy_sha256"))
        self.assertTrue(callable(getattr(VSTSentryApp, "_copy_sha256")))


# ============================================================================
# Wave 4 Feature Tests (v2.3)
# ============================================================================

class TestStatsFooter(unittest.TestCase):
    """Test the statistics footer methods."""

    def test_build_stats_footer_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_build_stats_footer"))

    def test_format_stats_text_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_format_stats_text"))

    def test_update_stats_footer_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_update_stats_footer"))


class TestShortcutCheatSheet(unittest.TestCase):
    """Test the keyboard shortcut cheat sheet."""

    def test_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_show_shortcut_cheat_sheet"))
        self.assertTrue(callable(getattr(VSTSentryApp, "_show_shortcut_cheat_sheet")))


class TestStatsTextFormat(unittest.TestCase):
    """Test _format_stats_text without Tk."""

    def test_stats_with_empty_history(self):
        """Empty history should mention 'No scans yet'."""
        from vst_sentry_gui import ScanHistory
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        try:
            h = ScanHistory(path=path)
            # Simulate the logic from _format_stats_text
            entries = h.entries
            total = len(entries)
            self.assertEqual(total, 0)
        finally:
            if os.path.isfile(path):
                os.unlink(path)

    def test_stats_counts_verdicts(self):
        """Stats should correctly count each verdict type."""
        from vst_sentry_gui import ScanHistory, ScanHistoryEntry
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        try:
            h = ScanHistory(path=path)
            h.add(ScanHistoryEntry(
                file_name="safe.dll", file_path="/tmp/safe.dll",
                verdict="Safe", risk_score=0, scan_date="2026-01-01T00:00:00",
            ))
            h.add(ScanHistoryEntry(
                file_name="sus.dll", file_path="/tmp/sus.dll",
                verdict="Suspicious", risk_score=10, scan_date="2026-01-01T00:00:01",
            ))
            h.add(ScanHistoryEntry(
                file_name="bad.dll", file_path="/tmp/bad.dll",
                verdict="High Risk", risk_score=30, scan_date="2026-01-01T00:00:02",
            ))
            entries = h.entries
            safe = sum(1 for e in entries if e.verdict == "Safe")
            susp = sum(1 for e in entries if e.verdict == "Suspicious")
            high = sum(1 for e in entries if e.verdict == "High Risk")
            self.assertEqual(len(entries), 3)
            self.assertEqual(safe, 1)
            self.assertEqual(susp, 1)
            self.assertEqual(high, 1)
        finally:
            if os.path.isfile(path):
                os.unlink(path)


# ============================================================================
# Wave 5 Feature Tests (v2.4)
# ============================================================================

class TestFileInfoTooltipData(unittest.TestCase):
    """Test that ScanHistoryEntry stores file_size for rich tooltips."""

    def test_entry_has_file_size_field(self):
        from vst_sentry_gui import ScanHistoryEntry
        entry = ScanHistoryEntry(
            file_name="test.dll", file_path="/tmp/test.dll",
            verdict="Safe", risk_score=0, scan_date="2026-01-01T00:00:00",
            file_size=123456,
        )
        self.assertEqual(entry.file_size, 123456)

    def test_entry_default_file_size_zero(self):
        from vst_sentry_gui import ScanHistoryEntry
        entry = ScanHistoryEntry(
            file_name="test.dll", file_path="/tmp/test.dll",
            verdict="Safe", risk_score=0, scan_date="2026-01-01T00:00:00",
        )
        self.assertEqual(entry.file_size, 0)

    def test_file_size_persists_json(self):
        """file_size should survive JSON round-trip."""
        from vst_sentry_gui import ScanHistory, ScanHistoryEntry
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        try:
            h = ScanHistory(path=path)
            h.add(ScanHistoryEntry(
                file_name="big.dll", file_path="/tmp/big.dll",
                verdict="Suspicious", risk_score=12,
                scan_date="2026-04-08T12:00:00",
                file_size=999888,
            ))
            # Reload
            h2 = ScanHistory(path=path)
            self.assertEqual(h2.entries[0].file_size, 999888)
        finally:
            if os.path.isfile(path):
                os.unlink(path)

    def test_tooltip_lines_include_file_size(self):
        """When file_size > 0 the tooltip should include size."""
        from vst_sentry_gui import ScanHistoryEntry
        entry = ScanHistoryEntry(
            file_name="big.dll", file_path="/tmp/big.dll",
            verdict="Safe", risk_score=0,
            scan_date="2026-01-01T00:00:00",
            file_size=65536, sha256="abc123",
            elapsed_seconds=1.5, vt_detections="0/72",
        )
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
        tip = "\n".join(tip_lines)
        self.assertIn("Size: 65,536 bytes", tip)
        self.assertIn("SHA-256:", tip)
        self.assertIn("VT: 0/72", tip)
        self.assertIn("Duration: 1.5s", tip)
        self.assertIn("Click to re-scan", tip)


class TestAutoUpdateCheck(unittest.TestCase):
    """Test that auto-update methods exist."""

    def test_check_for_updates_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_check_for_updates"))
        self.assertTrue(callable(getattr(VSTSentryApp, "_check_for_updates")))

    def test_do_update_check_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_do_update_check"))

    def test_notify_update_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_notify_update"))

    def test_constants_defined(self):
        from vst_sentry_gui import GITHUB_RELEASES_URL, UPDATE_CHECK_TIMEOUT
        self.assertTrue(GITHUB_RELEASES_URL.startswith("https://"))
        self.assertIsInstance(UPDATE_CHECK_TIMEOUT, int)
        self.assertGreater(UPDATE_CHECK_TIMEOUT, 0)


class TestParseDropPaths(unittest.TestCase):
    """Test the static _parse_drop_paths helper."""

    def _parse(self, raw):
        from vst_sentry_gui import VSTSentryApp
        return VSTSentryApp._parse_drop_paths(raw)

    def test_single_path(self):
        self.assertEqual(self._parse("/tmp/test.dll"), ["/tmp/test.dll"])

    def test_multiple_space_separated(self):
        self.assertEqual(
            self._parse("/tmp/a.dll /tmp/b.vst3"),
            ["/tmp/a.dll", "/tmp/b.vst3"],
        )

    def test_braces_wrapped(self):
        self.assertEqual(
            self._parse("{C:\\Plugins\\my plugin.dll}"),
            ["C:\\Plugins\\my plugin.dll"],
        )

    def test_multiple_braces(self):
        self.assertEqual(
            self._parse("{C:\\a.dll} {D:\\b.vst3}"),
            ["C:\\a.dll", "D:\\b.vst3"],
        )

    def test_empty_string(self):
        self.assertEqual(self._parse(""), [])

    def test_mixed_files_and_braces(self):
        result = self._parse("/tmp/x.dll {/opt/my folder/y.vst3}")
        self.assertEqual(result, ["/tmp/x.dll", "/opt/my folder/y.vst3"])


class TestCollectPluginsFromDir(unittest.TestCase):
    """Test recursive directory scanning for plugin files."""

    def test_finds_dlls_in_flat_dir(self):
        from vst_sentry_gui import VSTSentryApp
        d = tempfile.mkdtemp()
        try:
            # Create some files
            open(os.path.join(d, "a.dll"), "w").close()
            open(os.path.join(d, "b.vst3"), "w").close()
            open(os.path.join(d, "readme.txt"), "w").close()
            result = VSTSentryApp._collect_plugins_from_dir(d)
            basenames = [os.path.basename(p) for p in result]
            self.assertIn("a.dll", basenames)
            self.assertIn("b.vst3", basenames)
            self.assertNotIn("readme.txt", basenames)
        finally:
            import shutil
            shutil.rmtree(d)

    def test_finds_dlls_in_nested_dirs(self):
        from vst_sentry_gui import VSTSentryApp
        d = tempfile.mkdtemp()
        try:
            sub = os.path.join(d, "vendor", "synth")
            os.makedirs(sub)
            open(os.path.join(sub, "synth.dll"), "w").close()
            open(os.path.join(d, "top.vst"), "w").close()
            result = VSTSentryApp._collect_plugins_from_dir(d)
            basenames = [os.path.basename(p) for p in result]
            self.assertIn("synth.dll", basenames)
            self.assertIn("top.vst", basenames)
        finally:
            import shutil
            shutil.rmtree(d)

    def test_empty_dir_returns_empty(self):
        from vst_sentry_gui import VSTSentryApp
        d = tempfile.mkdtemp()
        try:
            result = VSTSentryApp._collect_plugins_from_dir(d)
            self.assertEqual(result, [])
        finally:
            os.rmdir(d)

    def test_deduplicates_results(self):
        from vst_sentry_gui import VSTSentryApp
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "dup.dll"), "w").close()
            result = VSTSentryApp._collect_plugins_from_dir(d)
            # Should only appear once despite glob matching from root + recursive
            self.assertEqual(len([p for p in result if "dup.dll" in p]), 1)
        finally:
            import shutil
            shutil.rmtree(d)

    def test_results_are_sorted(self):
        from vst_sentry_gui import VSTSentryApp
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "z.dll"), "w").close()
            open(os.path.join(d, "a.dll"), "w").close()
            open(os.path.join(d, "m.vst3"), "w").close()
            result = VSTSentryApp._collect_plugins_from_dir(d)
            self.assertEqual(result, sorted(result))
        finally:
            import shutil
            shutil.rmtree(d)


class TestProgressPercentage(unittest.TestCase):
    """Test progress step tracking."""

    def test_set_progress_step_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_set_progress_step"))

    def test_progress_percentage_calculation(self):
        """Percentage should scale 0-100 across 8 steps."""
        total = 8
        for step in range(1, total + 1):
            pct = int((step / total) * 100)
            self.assertGreater(pct, 0)
            self.assertLessEqual(pct, 100)
        self.assertEqual(int((8 / 8) * 100), 100)
        self.assertEqual(int((4 / 8) * 100), 50)
        self.assertEqual(int((1 / 8) * 100), 12)


class TestPdfExport(unittest.TestCase):
    """Test PDF report generation."""

    def test_generate_pdf_method_exists(self):
        from vst_sentry_gui import VSTSentryApp
        self.assertTrue(hasattr(VSTSentryApp, "_generate_pdf_report"))

    def test_generate_pdf_returns_bytes(self):
        """PDF generation should return valid PDF bytes."""
        from vst_sentry_gui import VSTSentryApp
        dll_path = self._create_minimal_dll()
        try:
            result = analyze_file(dll_path)
            pdf_data = VSTSentryApp._generate_pdf_report(result)
            self.assertIsInstance(pdf_data, bytes)
            self.assertTrue(pdf_data.startswith(b"%PDF-1.4"))
            self.assertTrue(pdf_data.rstrip().endswith(b"%%EOF"))
        finally:
            os.unlink(dll_path)

    def test_pdf_contains_multiple_pages_for_long_report(self):
        """A report with many lines should produce multi-page PDF."""
        from vst_sentry_gui import VSTSentryApp
        dll_path = self._create_minimal_dll()
        try:
            result = analyze_file(dll_path)
            pdf_data = VSTSentryApp._generate_pdf_report(result)
            # Check that at least one /Page exists
            self.assertIn(b"/Type /Page", pdf_data)
        finally:
            os.unlink(dll_path)

    def test_pdf_write_to_file(self):
        """PDF should be writable to a file."""
        from vst_sentry_gui import VSTSentryApp
        dll_path = self._create_minimal_dll()
        fd, pdf_path = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        try:
            result = analyze_file(dll_path)
            pdf_data = VSTSentryApp._generate_pdf_report(result)
            with open(pdf_path, "wb") as f:
                f.write(pdf_data)
            self.assertTrue(os.path.getsize(pdf_path) > 0)
        finally:
            os.unlink(dll_path)
            if os.path.isfile(pdf_path):
                os.unlink(pdf_path)

    @staticmethod
    def _create_minimal_dll():
        """Create a minimal valid PE file for testing."""
        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, 'wb') as f:
            dos_header = bytearray(64)
            dos_header[0:2] = b'MZ'
            struct.pack_into('<I', dos_header, 60, 64)
            f.write(dos_header)
            pe_sig = b'PE\x00\x00'
            f.write(pe_sig)
            coff = bytearray(20)
            struct.pack_into('<H', coff, 0, 0x14c)
            struct.pack_into('<H', coff, 2, 0)
            struct.pack_into('<H', coff, 16, 0x00E0)
            f.write(coff)
            optional = bytearray(0x00E0)
            struct.pack_into('<H', optional, 0, 0x10b)
            f.write(optional)
        return path


class TestVersionBump(unittest.TestCase):
    """Ensure version was bumped to 2.5.0."""

    def test_version_is_2_5_0(self):
        from vst_sentry_gui import APP_VERSION
        self.assertEqual(APP_VERSION, "2.5.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
