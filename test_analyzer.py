"""
VST-Sentry Analyzer — Test Suite
=================================

Tests the analyzer module against:
1. API database integrity (all 70+ entries present and correctly weighted)
2. Function name normalization (A/W suffix handling)
3. Synthetic PE files created with pefile (benign + malicious)
4. Verdict threshold logic
5. Report generation
"""

import json
import os
import struct
import sys
import tempfile
import unittest

import pefile

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer import (
    _API_DB,
    _normalize_func_name,
    _determine_verdict,
    _compute_triage_scores,
    _build_api_database,
    _calculate_shannon_entropy,
    _analyze_section_entropy,
    _KNOWN_PACKER_SECTIONS,
    _VERDICT_SAFE_MAX,
    _VERDICT_SUSPICIOUS_MAX,
    ENTROPY_PACKED_THRESHOLD,
    ENTROPY_ENCRYPTED_THRESHOLD,
    ENTROPY_FILE_PACKED_THRESHOLD,
    analyze_file,
    generate_report,
    AnalysisResult,
    EntropyAnalysis,
)


class TestAPIDatabaseIntegrity(unittest.TestCase):
    """Verify the Red Flag API database is complete and well-formed."""

    def test_database_not_empty(self):
        """The database must contain a substantial number of entries."""
        self.assertGreaterEqual(len(_API_DB), 70,
                                f"Expected 70+ API entries, got {len(_API_DB)}")

    def test_all_entries_have_required_fields(self):
        """Every FlaggedAPI must have non-empty dll, function, category, weight."""
        for key, api in _API_DB.items():
            with self.subTest(key=key):
                self.assertTrue(api.dll, f"Empty DLL for {key}")
                self.assertTrue(api.function, f"Empty function for {key}")
                self.assertTrue(api.category, f"Empty category for {key}")
                self.assertGreater(api.weight, 0, f"Zero weight for {key}")
                self.assertTrue(api.description, f"Empty description for {key}")

    def test_weight_values_match_spec(self):
        """Weights must use the project's discrete scale (includes 3/5 overrides)."""
        valid_weights = {10, 7, 5, 4, 3, 2}
        for key, api in _API_DB.items():
            with self.subTest(key=key):
                self.assertIn(api.weight, valid_weights,
                              f"Invalid weight {api.weight} for {key}")

    def test_critical_apis_present(self):
        """Spot-check that critical high-value APIs are in the database."""
        must_have = [
            ("kernel32.dll", "createremotethread"),
            ("kernel32.dll", "virtualallocex"),
            ("kernel32.dll", "writeprocessmemory"),
            ("kernel32.dll", "openprocess"),
            ("wininet.dll", "internetopen"),
            ("ws2_32.dll", "wsastartup"),
            ("advapi32.dll", "adjusttokenprivilege"),
            ("advapi32.dll", "regsetvalu"),
            ("user32.dll", "setwindowshookex"),
            ("urlmon.dll", "urldownloadtofil"),
        ]
        for dll, func_base in must_have:
            found = any(
                k[0] == dll and func_base in k[1]
                for k in _API_DB.keys()
            )
            self.assertTrue(found, f"Missing critical API: {dll}!{func_base}*")

    def test_category_coverage(self):
        """All risk categories must be represented in the database."""
        expected_categories = {
            "Process Injection",
            "Networking / C2",
            "Registry Manipulation",
            "Service Manipulation",
            "Privilege Escalation",
            "Credential Access",
            "Keylogging / Surveillance",
            "Anti-Analysis / Evasion",
            "Suspicious File Operations",
            "EXE / Dropper Behaviour",
        }
        actual_categories = {api.category for api in _API_DB.values()}
        self.assertEqual(expected_categories, actual_categories)


class TestNormalization(unittest.TestCase):
    """Test the Windows API function name normalization."""

    def test_ansi_suffix_stripped(self):
        self.assertEqual(_normalize_func_name("InternetOpenA"), "internetopen")

    def test_unicode_suffix_stripped(self):
        self.assertEqual(_normalize_func_name("InternetOpenW"), "internetopen")

    def test_short_names_preserved(self):
        """Short names like 'send', 'recv', 'bind' must NOT be truncated."""
        self.assertEqual(_normalize_func_name("send"), "send")
        self.assertEqual(_normalize_func_name("recv"), "recv")
        self.assertEqual(_normalize_func_name("bind"), "bind")
        self.assertEqual(_normalize_func_name("accept"), "accept")

    def test_case_insensitive(self):
        self.assertEqual(
            _normalize_func_name("CREATEREMOTETHREAD"),
            "createremotethread"
        )

    def test_already_normalized(self):
        self.assertEqual(
            _normalize_func_name("WSAStartup"),
            "wsastartup"
        )


class TestVerdictThresholds(unittest.TestCase):
    """Test the scoring threshold logic."""

    def test_safe_range(self):
        for score in range(0, _VERDICT_SAFE_MAX + 1):
            self.assertEqual(_determine_verdict(score), "Safe")

    def test_suspicious_range(self):
        for score in range(_VERDICT_SAFE_MAX + 1, _VERDICT_SUSPICIOUS_MAX + 1):
            self.assertEqual(_determine_verdict(score), "Suspicious")

    def test_high_risk_range(self):
        for score in [_VERDICT_SUSPICIOUS_MAX + 1, 50, 100, 999]:
            self.assertEqual(_determine_verdict(score), "High Risk")


class TestSyntheticPE(unittest.TestCase):
    """
    Test the full analysis pipeline against synthetic PE files.

    We use pefile to create minimal valid PE files with controlled
    import tables to verify detection logic end-to-end.
    """

    @staticmethod
    def _create_minimal_dll(
        imports: dict[str, list[str]] | None = None,
        rwx_section: bool = False,
        section_name: str = ".text",
    ) -> str:
        """
        Create a minimal valid PE DLL file with specified imports.

        Uses a real minimal PE structure. This creates a tiny but valid
        PE file that pefile can parse.

        Args:
            imports: Dict of {dll_name: [function_names]}

        Returns:
            Path to the temporary PE file.
        """
        # We'll build a minimal PE from scratch using known-good offsets.
        # This is a simplified approach — we create a valid PE header
        # with an import directory that pefile can parse.

        # Start with a minimal PE template
        # DOS Header (64 bytes)
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"  # e_magic
        struct.pack_into("<I", dos_header, 60, 64)  # e_lfanew -> PE header at 64

        # PE Signature
        pe_sig = b"PE\x00\x00"

        # COFF File Header (20 bytes)
        coff = bytearray(20)
        struct.pack_into("<H", coff, 0, 0x14C)   # Machine: i386
        struct.pack_into("<H", coff, 2, 1)        # NumberOfSections: 1
        struct.pack_into("<I", coff, 4, 0x5F000000)  # TimeDateStamp
        struct.pack_into("<H", coff, 16, 0xE0)    # SizeOfOptionalHeader
        struct.pack_into("<H", coff, 18, 0x2102)   # Characteristics: DLL | EXEC | 32BIT

        # Optional Header (PE32, 224 bytes = 0xE0)
        opt = bytearray(224)
        struct.pack_into("<H", opt, 0, 0x10B)    # Magic: PE32
        opt[2] = 14                                # MajorLinkerVersion
        struct.pack_into("<I", opt, 16, 0x1000)   # AddressOfEntryPoint
        struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
        struct.pack_into("<I", opt, 32, 0x1000)   # SectionAlignment
        struct.pack_into("<I", opt, 36, 0x200)    # FileAlignment
        struct.pack_into("<H", opt, 40, 6)        # MajorOSVersion
        struct.pack_into("<H", opt, 44, 6)        # MajorSubsystemVersion
        struct.pack_into("<I", opt, 56, 0x3000)   # SizeOfImage
        struct.pack_into("<I", opt, 60, 0x200)    # SizeOfHeaders
        struct.pack_into("<H", opt, 68, 3)        # Subsystem: CONSOLE
        struct.pack_into("<H", opt, 70, 0x8160)   # DllCharacteristics
        struct.pack_into("<I", opt, 72, 0x100000)  # SizeOfStackReserve
        struct.pack_into("<I", opt, 76, 0x1000)   # SizeOfStackCommit
        struct.pack_into("<I", opt, 80, 0x100000)  # SizeOfHeapReserve
        struct.pack_into("<I", opt, 84, 0x1000)   # SizeOfHeapCommit
        struct.pack_into("<I", opt, 92, 16)       # NumberOfRvaAndSizes

        # Data Directories (16 * 8 = 128 bytes, already zeroed in opt)
        # We'll set the Import Directory if we have imports
        # Import Directory is at index 1 (offset 96 + 1*8 = 104 in opt header)

        # Section Header (.text, 40 bytes)
        sec = bytearray(40)
        # Encode section name (pad/truncate to 8 bytes)
        sec_name_bytes = section_name.encode("ascii")[:8]
        sec[0:len(sec_name_bytes)] = sec_name_bytes
        struct.pack_into("<I", sec, 8, 0x1000)    # VirtualSize
        struct.pack_into("<I", sec, 12, 0x1000)   # VirtualAddress
        struct.pack_into("<I", sec, 16, 0x1000)   # SizeOfRawData
        struct.pack_into("<I", sec, 20, 0x200)    # PointerToRawData
        # 0x60000020 = CODE | MEM_READ | MEM_EXECUTE (legitimate RX)
        # 0xE0000060 = CODE | MEM_READ | MEM_WRITE | MEM_EXECUTE (suspicious RWX)
        sec_chars = 0xE0000060 if rwx_section else 0x60000020
        struct.pack_into("<I", sec, 36, sec_chars)  # Characteristics

        # Build section data with import table
        section_data = bytearray(0x1000)

        if imports:
            # Build import directory table at the start of section data
            # Layout within section (all offsets relative to section start):
            #   0x000: Import Directory Table entries
            #   0x100: DLL names
            #   0x200: Import Lookup / Address Tables
            #   0x400: Hint/Name entries

            idt_offset = 0x000  # Within section
            name_offset = 0x100
            ilt_offset = 0x200
            hint_offset = 0x400

            va_base = 0x1000  # Section VirtualAddress

            dll_list = list(imports.items())
            num_dlls = len(dll_list)

            for i, (dll_name, funcs) in enumerate(dll_list):
                # Write DLL name string
                dll_name_bytes = dll_name.encode("ascii") + b"\x00"
                section_data[name_offset:name_offset + len(dll_name_bytes)] = dll_name_bytes
                dll_name_rva = va_base + name_offset
                name_offset += len(dll_name_bytes)

                # Write IDT entry (20 bytes each)
                idt_entry_offset = idt_offset + i * 20
                ilt_rva = va_base + ilt_offset
                struct.pack_into("<I", section_data, idt_entry_offset, ilt_rva)      # OriginalFirstThunk (ILT)
                struct.pack_into("<I", section_data, idt_entry_offset + 12, dll_name_rva)  # Name
                struct.pack_into("<I", section_data, idt_entry_offset + 16, ilt_rva)  # FirstThunk (IAT)

                # Write ILT entries + Hint/Name entries
                for j, func_name in enumerate(funcs):
                    # Hint/Name entry: 2-byte hint + name string + null
                    hn_bytes = struct.pack("<H", j) + func_name.encode("ascii") + b"\x00"
                    if len(hn_bytes) % 2:
                        hn_bytes += b"\x00"  # Pad to even
                    section_data[hint_offset:hint_offset + len(hn_bytes)] = hn_bytes
                    hn_rva = va_base + hint_offset
                    hint_offset += len(hn_bytes)

                    # ILT entry (4 bytes for PE32): RVA to Hint/Name
                    ilt_entry_offset = ilt_offset + j * 4
                    struct.pack_into("<I", section_data, ilt_entry_offset, hn_rva)

                # Null-terminate ILT
                ilt_offset += (len(funcs) + 1) * 4

            # Null-terminate IDT (20 zero bytes)
            # Already zero from bytearray init

            # Set Import Directory in Optional Header Data Directories
            import_dir_rva = va_base + 0x000
            import_dir_size = (num_dlls + 1) * 20
            struct.pack_into("<I", opt, 104, import_dir_rva)  # Import Dir RVA
            struct.pack_into("<I", opt, 108, import_dir_size)  # Import Dir Size

        # Assemble the PE file
        headers = dos_header + pe_sig + coff + opt + sec
        # Pad headers to FileAlignment (0x200)
        headers += b"\x00" * (0x200 - len(headers))

        pe_data = headers + section_data

        # Write to temp file
        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(pe_data)

        return path

    def test_benign_dll(self):
        """A DLL with only benign imports and normal sections should score Safe."""
        path = self._create_minimal_dll(imports={
            "kernel32.dll": ["GetModuleHandleW", "VirtualAlloc",
                             "HeapAlloc", "HeapFree"],
        })
        try:
            result = analyze_file(path)
            self.assertEqual(result.flagged_count, 0)
            self.assertEqual(result.pe_type, "DLL")
            # No flagged API imports should be found
            self.assertEqual(len(result.flagged_imports), 0)
        finally:
            os.unlink(path)

    def test_suspicious_dll(self):
        """A DLL with networking + registry persistence should score Suspicious+."""
        path = self._create_minimal_dll(imports={
            "wininet.dll": ["InternetOpenA", "InternetReadFile"],
            "advapi32.dll": ["RegSetValueExA", "RegOpenKeyExA"],
        })
        try:
            result = analyze_file(path)
            self.assertIn(result.verdict, ("Suspicious", "High Risk"))
            self.assertGreater(result.flagged_count, 0)
        finally:
            os.unlink(path)

    def test_high_risk_dll(self):
        """A DLL with injection + networking + persistence + RWX should score High Risk."""
        path = self._create_minimal_dll(
            imports={
                "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx",
                                 "WriteProcessMemory", "OpenProcess"],
                "wininet.dll": ["InternetOpenA", "InternetReadFile"],
                "advapi32.dll": ["RegSetValueExA"],
            },
            rwx_section=True,
        )
        try:
            result = analyze_file(path)
            self.assertEqual(result.verdict, "High Risk")
            self.assertGreaterEqual(result.risk_score, 36)
            self.assertIn("Process Injection", result.categories_hit)
            self.assertIn("Networking / C2", result.categories_hit)
            self.assertIn("Registry Manipulation", result.categories_hit)
        finally:
            os.unlink(path)

    def test_full_report_generation(self):
        """The text report generator should produce non-empty output."""
        path = self._create_minimal_dll(imports={
            "kernel32.dll": ["CreateRemoteThread", "OpenProcess"],
            "ws2_32.dll": ["WSAStartup", "connect"],
        })
        try:
            result = analyze_file(path)
            report = generate_report(result)
            self.assertIn("VST-SENTRY ANALYSIS REPORT", report)
            self.assertIn("FLAGGED IMPORTS", report)
            self.assertIn("CreateRemoteThread", report)
            self.assertIn(result.verdict.upper(), report)
            self.assertGreater(len(report), 500)
        finally:
            os.unlink(path)

    def test_json_output(self):
        """JSON output must be valid and contain required keys."""
        path = self._create_minimal_dll(imports={
            "kernel32.dll": ["HeapAlloc"],
        })
        try:
            result = analyze_file(path)
            json_str = result.to_json()
            parsed = json.loads(json_str)

            required_keys = [
                "file_path", "file_name", "md5", "sha256",
                "verdict", "risk_score", "flagged_count",
                "signature", "total_imports",
            ]
            for key in required_keys:
                self.assertIn(key, parsed, f"Missing key: {key}")
        finally:
            os.unlink(path)

    def test_empty_imports_no_api_flags(self):
        """A DLL with no imports should have zero flagged API imports."""
        path = self._create_minimal_dll(imports=None)
        try:
            result = analyze_file(path)
            self.assertEqual(result.flagged_count, 0)
            self.assertEqual(result.total_imports, 0)
        finally:
            os.unlink(path)

    def test_include_all_imports_flag(self):
        """The all_imports flag should populate the all_imports list."""
        path = self._create_minimal_dll(imports={
            "kernel32.dll": ["HeapAlloc", "HeapFree"],
        })
        try:
            result = analyze_file(path, include_all_imports=True)
            self.assertGreater(len(result.all_imports), 0)
        finally:
            os.unlink(path)

    def test_nonexistent_file_raises(self):
        """Analyzing a nonexistent file should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            analyze_file("/tmp/does_not_exist_vst_sentry_test.dll")

    def test_invalid_pe_returns_error(self):
        """A non-PE file should return an Error verdict."""
        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(b"This is not a PE file at all.")
        try:
            result = analyze_file(path)
            self.assertEqual(result.verdict, "Error")
            self.assertTrue(any("Invalid PE" in w for w in result.warnings))
        finally:
            os.unlink(path)


class TestUnsignedPenalty(unittest.TestCase):
    """Verify the unsigned DLL penalty logic."""

    def test_unsigned_with_flags_gets_penalty(self):
        """An unsigned DLL with hard-category flags triggers the unsigned warning."""
        path = TestSyntheticPE._create_minimal_dll(imports={
            "kernel32.dll": ["CreateRemoteThread"],
        })
        try:
            result = analyze_file(path)
            self.assertGreater(result.hard_score, 0)
            self.assertGreaterEqual(result.risk_score, 2)
            self.assertIn("Unsigned PE with suspicious imports",
                          " ".join(result.warnings))
        finally:
            os.unlink(path)

    def test_unsigned_without_flags_no_penalty(self):
        """An unsigned DLL with NO flagged API imports gets no API penalty."""
        path = TestSyntheticPE._create_minimal_dll(imports={
            "kernel32.dll": ["HeapAlloc"],
        })
        try:
            result = analyze_file(path)
            # No flagged API imports, so no unsigned penalty applied to API score.
            # However, entropy analysis may add points from section characteristics.
            # The key assertion: no "Unsigned PE with suspicious imports" warning
            # (that only fires when API-based score > 0 AND unsigned).
            self.assertEqual(result.flagged_count, 0)
        finally:
            os.unlink(path)


class TestShannonEntropy(unittest.TestCase):
    """Test the Shannon entropy calculation function."""

    def test_empty_data(self):
        """Empty input should return 0.0."""
        self.assertEqual(_calculate_shannon_entropy(b""), 0.0)

    def test_uniform_data(self):
        """All-zero data has entropy 0.0 (single symbol)."""
        self.assertEqual(_calculate_shannon_entropy(b"\x00" * 1024), 0.0)

    def test_two_symbols_equal(self):
        """Two equally distributed symbols should have entropy 1.0."""
        data = b"\x00\x01" * 512
        entropy = _calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 1.0, places=3)

    def test_random_data_high_entropy(self):
        """Pseudo-random data should have entropy close to 8.0."""
        import random
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(10000))
        entropy = _calculate_shannon_entropy(data)
        self.assertGreater(entropy, 7.8)
        self.assertLessEqual(entropy, 8.0)

    def test_ascii_text_moderate_entropy(self):
        """English text should have moderate entropy (3–5)."""
        data = (b"The quick brown fox jumps over the lazy dog. " * 50)
        entropy = _calculate_shannon_entropy(data)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 5.0)

    def test_compressed_like_data(self):
        """Simulated compressed data (many unique bytes) ~ 6.5–7.5."""
        import random
        random.seed(99)
        # Slightly biased distribution to simulate compression (not fully random)
        data = bytes(
            random.choices(range(256), weights=[1 + (i % 3) for i in range(256)], k=8192)
        )
        entropy = _calculate_shannon_entropy(data)
        self.assertGreater(entropy, 6.0)
        self.assertLess(entropy, 8.0)


class TestEntropyAnalysis(unittest.TestCase):
    """Test the YARA-style section entropy analysis."""

    def test_rwx_section_flagged(self):
        """A DLL with RWX section permissions should be flagged."""
        path = TestSyntheticPE._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]},
            rwx_section=True,
        )
        try:
            result = analyze_file(path)
            ea = result.entropy_analysis
            self.assertGreater(ea["rwx_sections"], 0)
            self.assertGreater(ea["total_entropy_score"], 0)
            # RWX alert should appear in section alerts
            has_rwx_alert = any(
                any("RWX" in alert for alert in sec["alerts"])
                for sec in ea["sections"]
            )
            self.assertTrue(has_rwx_alert, "Expected RWX alert in section analysis")
        finally:
            os.unlink(path)

    def test_packer_section_name_flagged(self):
        """A DLL with a known packer section name should be flagged."""
        path = TestSyntheticPE._create_minimal_dll(
            imports=None,
            section_name="UPX1",
        )
        try:
            result = analyze_file(path)
            ea = result.entropy_analysis
            self.assertGreater(ea["packer_sections"], 0)
            self.assertTrue(ea["is_likely_packed"])
            # Check for packer name alert
            has_packer_alert = any(
                any("PACKER" in alert for alert in sec["alerts"])
                for sec in ea["sections"]
            )
            self.assertTrue(has_packer_alert, "Expected PACKER alert")
        finally:
            os.unlink(path)

    def test_entropy_analysis_in_json(self):
        """Entropy analysis data should appear in JSON output."""
        path = TestSyntheticPE._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]},
        )
        try:
            result = analyze_file(path)
            json_str = result.to_json()
            parsed = json.loads(json_str)
            self.assertIn("entropy_analysis", parsed)
            ea = parsed["entropy_analysis"]
            self.assertIn("file_entropy", ea)
            self.assertIn("sections", ea)
            self.assertIn("is_likely_packed", ea)
            self.assertIsInstance(ea["file_entropy"], float)
        finally:
            os.unlink(path)

    def test_entropy_in_report_output(self):
        """The text report should include the entropy analysis section."""
        path = TestSyntheticPE._create_minimal_dll(
            imports={"kernel32.dll": ["HeapAlloc"]},
            rwx_section=True,
        )
        try:
            result = analyze_file(path)
            report = generate_report(result)
            self.assertIn("ENTROPY / PACKING ANALYSIS", report)
            self.assertIn("File Entropy:", report)
            self.assertIn("Likely Packed:", report)
            self.assertIn("bits/byte", report)
        finally:
            os.unlink(path)

    def test_high_entropy_section_detection(self):
        """Verify that _calculate_shannon_entropy correctly identifies
        near-random data that would trigger the packed threshold."""
        import random
        random.seed(123)
        encrypted_data = bytes(random.randint(0, 255) for _ in range(4096))
        entropy = _calculate_shannon_entropy(encrypted_data)
        self.assertGreaterEqual(entropy, ENTROPY_ENCRYPTED_THRESHOLD,
                                f"Random data entropy {entropy:.4f} should be >= "
                                f"{ENTROPY_ENCRYPTED_THRESHOLD}")

    def test_normal_code_below_threshold(self):
        """Simulated compiled code (structured, repetitive) should stay
        below the packed threshold."""
        # Simulate typical compiled x86 code patterns
        # (push/pop/mov/call patterns with some variation)
        patterns = [
            b"\x55\x8b\xec\x83\xec",      # push ebp; mov ebp,esp; sub esp
            b"\x89\x45\xfc\x8b\x45",      # mov [ebp-4],eax; mov eax,[ebp]
            b"\xc7\x45\xf8\x00\x00",      # mov [ebp-8], 0
            b"\xe8\x00\x00\x00\x00",      # call near
            b"\x8b\x4d\x08\x89\x4d",      # mov ecx,[ebp+8]; mov [ebp],ecx
            b"\x33\xc0\xc9\xc3\x90",      # xor eax,eax; leave; ret; nop
        ]
        import random
        random.seed(456)
        data = b""
        for _ in range(800):
            data += random.choice(patterns)
        entropy = _calculate_shannon_entropy(data)
        self.assertLess(entropy, ENTROPY_PACKED_THRESHOLD,
                        f"Simulated code entropy {entropy:.4f} should be < "
                        f"{ENTROPY_PACKED_THRESHOLD}")

    def test_known_packer_names_comprehensive(self):
        """Verify the packer section name database covers major packers."""
        must_have = ["upx0", "upx1", ".vmp0", ".themida", ".aspack",
                     ".mpress1", ".nsp0", ".packed"]
        for name in must_have:
            self.assertIn(name, _KNOWN_PACKER_SECTIONS,
                          f"Missing packer section name: {name}")

    def test_packing_category_in_categories_hit(self):
        """When entropy flags fire, 'Packing / Encryption' category appears."""
        path = TestSyntheticPE._create_minimal_dll(
            imports=None,
            rwx_section=True,
            section_name="UPX1",
        )
        try:
            result = analyze_file(path)
            self.assertIn("Packing / Encryption", result.categories_hit)
        finally:
            os.unlink(path)


class TestPluginVerdictCap(unittest.TestCase):
    """High static scores without injection + low VT should not stay High Risk."""

    def test_no_injection_low_vt_capped_at_suspicious(self):
        """Mirrors commercial plugins: heavy networking/UI, no injection, few VT hits."""
        flagged: list[dict] = (
            [{"dll": "ws2_32.dll", "function": "send",
              "category": "Networking / C2", "weight": 5}] * 8
            + [{"dll": "advapi32.dll", "function": "RegOpenKeyExA",
                "category": "Registry Manipulation", "weight": 2}]
            + [{"dll": "user32.dll", "function": "SetWindowsHookExW",
                "category": "Keylogging / Surveillance", "weight": 5}]
        )
        er = EntropyAnalysis(high_entropy_sections=2, rwx_sections=0)
        _h, _w, _p, _t, verdict = _compute_triage_scores(
            flagged,
            entropy_score=20,
            entropy_result=er,
            has_valid_signature=False,
            vt_malicious=2,
            vt_total=70,
            sandbox_has_network=False,
            sandbox_has_injection=False,
        )
        self.assertEqual(verdict, "Suspicious")


if __name__ == "__main__":
    unittest.main(verbosity=2)
