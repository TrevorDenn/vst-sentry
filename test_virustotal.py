"""
VST-Sentry — VirusTotal Module Test Suite
============================================

Tests the virustotal.py module:
1. VTResult dataclass and serialisation
2. Scoring logic (_compute_vt_score)
3. Response parsing (_parse_vt_response)
4. API client (lookup_hash) with mocked HTTP responses
5. Error handling (auth, rate-limit, timeout, network)
6. Integration with analyzer.py (vt_api_key parameter)

All HTTP calls are mocked — no real VT API key required.
"""

import json
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from virustotal import (
    VTResult,
    VTBehaviourResult,
    MitreTechnique,
    _compute_vt_score,
    _parse_vt_response,
    _parse_behaviour_response,
    lookup_hash,
    lookup_behaviours,
    get_mitre_technique,
    get_mitre_knowledge_base,
    VT_SCORE_CLEAN,
    VT_SCORE_LOW,
    VT_SCORE_MEDIUM,
    VT_SCORE_HIGH,
    VT_SCORE_NOT_FOUND,
    VT_API_BASE,
    _BEH_CAP_NETWORK,
    _BEH_CAP_FILES,
    _BEH_CAP_GENERAL,
    _BEH_CAP_MITRE,
)


# ---------------------------------------------------------------------------
# Mock VT API Responses
# ---------------------------------------------------------------------------

def _make_vt_response(
    malicious: int = 0,
    suspicious: int = 0,
    undetected: int = 60,
    harmless: int = 0,
    threat_label: str = "",
    threat_names: list | None = None,
    reputation: int = 0,
    times_submitted: int = 1,
) -> dict:
    """Build a realistic VT API v3 /files/{hash} response body."""
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "timeout": 0,
        "confirmed-timeout": 0,
        "failure": 1,
        "type-unsupported": 5,
    }
    attrs = {
        "last_analysis_stats": stats,
        "reputation": reputation,
        "times_submitted": times_submitted,
    }
    if threat_label:
        popular = {"suggested_threat_label": threat_label}
        if threat_names:
            popular["popular_threat_name"] = [
                {"value": n, "count": 10} for n in threat_names
            ]
        attrs["popular_threat_classification"] = popular

    return {
        "data": {
            "id": "abc123",
            "type": "file",
            "attributes": attrs,
        }
    }


class _MockResponse:
    """Minimal mock for requests.Response."""

    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body


# ---------------------------------------------------------------------------
# Tests: VTResult
# ---------------------------------------------------------------------------

class TestVTResult(unittest.TestCase):
    """Test the VTResult dataclass."""

    def test_default_state(self):
        r = VTResult()
        self.assertFalse(r.queried)
        self.assertFalse(r.found)
        self.assertEqual(r.error, "")
        self.assertEqual(r.malicious, 0)
        self.assertEqual(r.score_contribution, 0)

    def test_detection_ratio_found(self):
        r = VTResult(found=True, malicious=12, total_engines=72)
        self.assertEqual(r.detection_ratio_str(), "12 / 72")

    def test_detection_ratio_not_found(self):
        r = VTResult(found=False)
        self.assertEqual(r.detection_ratio_str(), "N/A")

    def test_to_dict_keys(self):
        r = VTResult(queried=True, found=True, malicious=5, total_engines=70)
        d = r.to_dict()
        expected_keys = {
            "queried", "found", "error", "total_engines", "malicious",
            "suspicious", "undetected", "harmless", "threat_label",
            "threat_names", "reputation", "times_submitted",
            "score_contribution", "permalink", "detection_ratio",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_to_dict_is_json_serialisable(self):
        r = VTResult(
            queried=True, found=True, malicious=3,
            threat_names=["trojan", "worm"],
        )
        json_str = json.dumps(r.to_dict())
        parsed = json.loads(json_str)
        self.assertEqual(parsed["malicious"], 3)
        self.assertEqual(parsed["threat_names"], ["trojan", "worm"])


# ---------------------------------------------------------------------------
# Tests: Scoring Logic
# ---------------------------------------------------------------------------

class TestVTScoring(unittest.TestCase):
    """Test the _compute_vt_score function."""

    def test_not_found_returns_zero(self):
        self.assertEqual(_compute_vt_score(0, found=False), VT_SCORE_NOT_FOUND)

    def test_clean_gives_bonus(self):
        self.assertEqual(_compute_vt_score(0, found=True), VT_SCORE_CLEAN)
        self.assertLess(VT_SCORE_CLEAN, 0)  # Bonus must be negative

    def test_low_detections(self):
        for mal in (1, 2, 3, 4):
            self.assertEqual(
                _compute_vt_score(mal, found=True), VT_SCORE_LOW,
                f"Failed for malicious={mal}",
            )

    def test_medium_detections(self):
        for mal in (5, 10, 14):
            self.assertEqual(
                _compute_vt_score(mal, found=True), VT_SCORE_MEDIUM,
                f"Failed for malicious={mal}",
            )

    def test_high_detections(self):
        for mal in (15, 30, 60):
            self.assertEqual(
                _compute_vt_score(mal, found=True), VT_SCORE_HIGH,
                f"Failed for malicious={mal}",
            )

    def test_score_ordering(self):
        """Scores must increase with severity."""
        self.assertLess(VT_SCORE_CLEAN, VT_SCORE_NOT_FOUND)
        self.assertLess(VT_SCORE_NOT_FOUND, VT_SCORE_LOW)
        self.assertLess(VT_SCORE_LOW, VT_SCORE_MEDIUM)
        self.assertLess(VT_SCORE_MEDIUM, VT_SCORE_HIGH)


# ---------------------------------------------------------------------------
# Tests: Response Parsing
# ---------------------------------------------------------------------------

class TestVTResponseParsing(unittest.TestCase):
    """Test _parse_vt_response with synthetic API responses."""

    def test_clean_file(self):
        data = _make_vt_response(malicious=0, undetected=70)
        result = _parse_vt_response(data, VTResult(queried=True), "abc123sha")
        self.assertTrue(result.found)
        self.assertEqual(result.malicious, 0)
        self.assertEqual(result.score_contribution, VT_SCORE_CLEAN)
        self.assertIn("abc123sha", result.permalink)

    def test_malicious_file(self):
        data = _make_vt_response(
            malicious=25,
            undetected=40,
            threat_label="trojan.generickd",
            threat_names=["Trojan.Generic", "Win32.Malware"],
        )
        result = _parse_vt_response(data, VTResult(queried=True), "deadbeef")
        self.assertTrue(result.found)
        self.assertEqual(result.malicious, 25)
        self.assertEqual(result.score_contribution, VT_SCORE_HIGH)
        self.assertEqual(result.threat_label, "trojan.generickd")
        self.assertIn("Trojan.Generic", result.threat_names)

    def test_low_detection_file(self):
        data = _make_vt_response(malicious=2, undetected=68)
        result = _parse_vt_response(data, VTResult(queried=True), "hash123")
        self.assertEqual(result.score_contribution, VT_SCORE_LOW)

    def test_total_engines_calculation(self):
        data = _make_vt_response(
            malicious=10, suspicious=2, undetected=50, harmless=3
        )
        result = _parse_vt_response(data, VTResult(queried=True), "hash456")
        # Total = 10 + 2 + 50 + 3 + 0 + 0 + 1(failure) + 5(type-unsupported) = 71
        self.assertEqual(result.total_engines, 71)

    def test_empty_threat_classification(self):
        data = _make_vt_response(malicious=0)
        result = _parse_vt_response(data, VTResult(queried=True), "cleanfile")
        self.assertEqual(result.threat_label, "")
        self.assertEqual(result.threat_names, [])

    def test_reputation_and_submissions(self):
        data = _make_vt_response(reputation=-50, times_submitted=12)
        result = _parse_vt_response(data, VTResult(queried=True), "hash")
        self.assertEqual(result.reputation, -50)
        self.assertEqual(result.times_submitted, 12)


# ---------------------------------------------------------------------------
# Tests: API Client (mocked HTTP)
# ---------------------------------------------------------------------------

class TestLookupHash(unittest.TestCase):
    """Test lookup_hash with mocked requests.get."""

    def test_no_api_key_skips_lookup(self):
        result = lookup_hash("abc123", "")
        self.assertFalse(result.queried)
        self.assertIn("No API key", result.error)

    def test_empty_api_key_skips_lookup(self):
        result = lookup_hash("abc123", "   ")
        self.assertFalse(result.queried)

    @patch("virustotal.requests.get")
    def test_successful_clean_lookup(self, mock_get):
        mock_get.return_value = _MockResponse(
            200, _make_vt_response(malicious=0, undetected=70)
        )
        result = lookup_hash("sha256hash", "valid_key")
        self.assertTrue(result.queried)
        self.assertTrue(result.found)
        self.assertEqual(result.malicious, 0)
        self.assertEqual(result.score_contribution, VT_SCORE_CLEAN)

    @patch("virustotal.requests.get")
    def test_successful_malicious_lookup(self, mock_get):
        mock_get.return_value = _MockResponse(
            200,
            _make_vt_response(
                malicious=20,
                threat_label="trojan.loudminer",
                threat_names=["LoudMiner", "CoinMiner"],
            ),
        )
        result = lookup_hash("sha256hash", "valid_key")
        self.assertTrue(result.found)
        self.assertEqual(result.malicious, 20)
        self.assertEqual(result.score_contribution, VT_SCORE_HIGH)
        self.assertEqual(result.threat_label, "trojan.loudminer")

    @patch("virustotal.requests.get")
    def test_hash_not_found_404(self, mock_get):
        mock_get.return_value = _MockResponse(404)
        result = lookup_hash("unknownhash", "valid_key")
        self.assertTrue(result.queried)
        self.assertFalse(result.found)
        self.assertEqual(result.error, "")
        self.assertEqual(result.score_contribution, VT_SCORE_NOT_FOUND)

    @patch("virustotal.requests.get")
    def test_invalid_key_401(self, mock_get):
        mock_get.return_value = _MockResponse(401)
        result = lookup_hash("hash", "bad_key")
        self.assertTrue(result.queried)
        self.assertFalse(result.found)
        self.assertIn("Invalid API key", result.error)

    @patch("virustotal.requests.get")
    def test_rate_limit_429(self, mock_get):
        mock_get.return_value = _MockResponse(429)
        result = lookup_hash("hash", "valid_key")
        self.assertIn("Rate limit", result.error)
        self.assertEqual(result.score_contribution, 0)

    @patch("virustotal.requests.get")
    def test_unexpected_status_code(self, mock_get):
        mock_get.return_value = _MockResponse(500)
        result = lookup_hash("hash", "valid_key")
        self.assertIn("Unexpected HTTP 500", result.error)

    @patch("virustotal.requests.get")
    def test_connection_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.ConnectionError("DNS failure")
        result = lookup_hash("hash", "valid_key")
        self.assertIn("Connection error", result.error)

    @patch("virustotal.requests.get")
    def test_timeout_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.Timeout("timed out")
        result = lookup_hash("hash", "valid_key")
        self.assertIn("timed out", result.error)

    @patch("virustotal.requests.get")
    def test_request_uses_correct_url_and_headers(self, mock_get):
        mock_get.return_value = _MockResponse(404)
        lookup_hash("deadbeef123", "my_api_key_42")
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], f"{VT_API_BASE}/deadbeef123")
        self.assertEqual(kwargs["headers"]["x-apikey"], "my_api_key_42")
        self.assertEqual(kwargs["headers"]["accept"], "application/json")


# ---------------------------------------------------------------------------
# Tests: Analyzer Integration
# ---------------------------------------------------------------------------

class TestAnalyzerVTIntegration(unittest.TestCase):
    """Test that analyzer.py correctly calls VT and folds results into scoring."""

    @staticmethod
    def _create_minimal_dll(imports=None):
        """Create a minimal PE DLL (simplified helper)."""
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
            idt_offset, name_offset, ilt_offset, hint_offset = 0x000, 0x100, 0x200, 0x400
            va_base = 0x1000
            dll_list = list(imports.items())
            for i, (dll_name, funcs) in enumerate(dll_list):
                dll_name_bytes = dll_name.encode("ascii") + b"\x00"
                section_data[name_offset:name_offset + len(dll_name_bytes)] = dll_name_bytes
                dll_name_rva = va_base + name_offset
                name_offset += len(dll_name_bytes)
                idt_entry_offset = idt_offset + i * 20
                ilt_rva = va_base + ilt_offset
                struct.pack_into("<I", section_data, idt_entry_offset, ilt_rva)
                struct.pack_into("<I", section_data, idt_entry_offset + 12, dll_name_rva)
                struct.pack_into("<I", section_data, idt_entry_offset + 16, ilt_rva)
                for j, func_name in enumerate(funcs):
                    hn_bytes = struct.pack("<H", j) + func_name.encode("ascii") + b"\x00"
                    if len(hn_bytes) % 2:
                        hn_bytes += b"\x00"
                    section_data[hint_offset:hint_offset + len(hn_bytes)] = hn_bytes
                    hn_rva = va_base + hint_offset
                    hint_offset += len(hn_bytes)
                    struct.pack_into("<I", section_data, ilt_offset + j * 4, hn_rva)
                ilt_offset += (len(funcs) + 1) * 4
            struct.pack_into("<I", opt, 104, va_base)
            struct.pack_into("<I", opt, 108, (len(dll_list) + 1) * 20)

        headers = dos_header + pe_sig + coff + opt + sec
        headers += b"\x00" * (0x200 - len(headers))
        pe_data = headers + section_data

        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(pe_data)
        return path

    def test_no_vt_key_skips_lookup(self):
        """When vt_api_key is empty, vt_lookup should show queried=False."""
        from analyzer import analyze_file
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result = analyze_file(path, vt_api_key="")
            self.assertFalse(result.vt_lookup.get("queried", True))
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_hash")
    def test_vt_clean_reduces_score(self, mock_vt):
        """A VT-clean result should apply the clean bonus (negative score)."""
        from analyzer import analyze_file
        mock_vt.return_value = VTResult(
            queried=True, found=True, malicious=0,
            total_engines=72, score_contribution=VT_SCORE_CLEAN,
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result = analyze_file(path, vt_api_key="test_key")
            vt = result.vt_lookup
            self.assertTrue(vt["queried"])
            self.assertTrue(vt["found"])
            self.assertEqual(vt["malicious"], 0)
            # Clean bonus should be applied
            self.assertIn("Clean", " ".join(result.warnings))
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_hash")
    def test_vt_malicious_increases_score(self, mock_vt):
        """A VT-malicious result should add significant points to the score."""
        from analyzer import analyze_file
        mock_vt.return_value = VTResult(
            queried=True, found=True, malicious=25,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
            threat_label="trojan.loudminer",
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result_without_vt = analyze_file(path, vt_api_key="")
            base_score = result_without_vt.risk_score

            result_with_vt = analyze_file(path, vt_api_key="test_key")
            self.assertGreater(result_with_vt.risk_score, base_score)
            self.assertIn("VirusTotal Detections", result_with_vt.categories_hit)
            self.assertIn("25/72", " ".join(result_with_vt.warnings))
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_hash")
    def test_vt_not_found_no_score_change(self, mock_vt):
        """A VT 404 (hash not found) should not change the score."""
        from analyzer import analyze_file
        mock_vt.return_value = VTResult(
            queried=True, found=False, score_contribution=VT_SCORE_NOT_FOUND,
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result_no_vt = analyze_file(path, vt_api_key="")
            result_vt = analyze_file(path, vt_api_key="test_key")
            self.assertEqual(result_no_vt.risk_score, result_vt.risk_score)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_hash")
    def test_vt_error_no_score_change(self, mock_vt):
        """A VT API error should not change the score."""
        from analyzer import analyze_file
        mock_vt.return_value = VTResult(
            queried=True, found=False,
            error="Rate limit exceeded (HTTP 429)",
            score_contribution=0,
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result_no_vt = analyze_file(path, vt_api_key="")
            result_vt = analyze_file(path, vt_api_key="test_key")
            self.assertEqual(result_no_vt.risk_score, result_vt.risk_score)
            # Error should appear in warnings
            self.assertIn("VirusTotal: Rate limit", " ".join(result_vt.warnings))
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_hash")
    def test_vt_lookup_in_json_output(self, mock_vt):
        """VT lookup data should appear in JSON export."""
        from analyzer import analyze_file
        mock_vt.return_value = VTResult(
            queried=True, found=True, malicious=10,
            total_engines=72, score_contribution=VT_SCORE_MEDIUM,
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result = analyze_file(path, vt_api_key="test_key")
            parsed = json.loads(result.to_json())
            self.assertIn("vt_lookup", parsed)
            self.assertTrue(parsed["vt_lookup"]["queried"])
            self.assertEqual(parsed["vt_lookup"]["malicious"], 10)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_hash")
    def test_vt_in_text_report(self, mock_vt):
        """VT section should appear in text report when queried."""
        from analyzer import analyze_file, generate_report
        mock_vt.return_value = VTResult(
            queried=True, found=True, malicious=15,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
            threat_label="trojan.generic",
            permalink="https://www.virustotal.com/gui/file/abc123",
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result = analyze_file(path, vt_api_key="test_key")
            report = generate_report(result)
            self.assertIn("VIRUSTOTAL LOOKUP", report)
            self.assertIn("15 / 72", report)
            self.assertIn("trojan.generic", report)
            self.assertIn("virustotal.com", report)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: VTBehaviourResult Dataclass
# ---------------------------------------------------------------------------

class TestVTBehaviourResult(unittest.TestCase):
    """Test the VTBehaviourResult dataclass."""

    def test_default_state(self):
        r = VTBehaviourResult()
        self.assertFalse(r.queried)
        self.assertFalse(r.found)
        self.assertEqual(r.error, "")
        self.assertEqual(r.dns_lookups, [])
        self.assertEqual(r.ip_traffic, [])
        self.assertEqual(r.files_dropped, [])
        self.assertEqual(r.command_executions, [])
        self.assertEqual(r.registry_keys_set, [])
        self.assertEqual(r.tags, [])

    def test_has_network_activity_false_when_empty(self):
        r = VTBehaviourResult()
        self.assertFalse(r.has_network_activity)

    def test_has_network_activity_true_with_dns(self):
        r = VTBehaviourResult(dns_lookups=[{"hostname": "evil.com"}])
        self.assertTrue(r.has_network_activity)

    def test_has_network_activity_true_with_ip(self):
        r = VTBehaviourResult(ip_traffic=[{"destination_ip": "1.2.3.4"}])
        self.assertTrue(r.has_network_activity)

    def test_has_network_activity_true_with_http(self):
        r = VTBehaviourResult(http_conversations=[{"url": "http://c2.evil.com"}])
        self.assertTrue(r.has_network_activity)

    def test_has_file_system_activity_false_when_empty(self):
        r = VTBehaviourResult()
        self.assertFalse(r.has_file_system_activity)

    def test_has_file_system_activity_true_with_dropped(self):
        r = VTBehaviourResult(files_dropped=[{"path": "C:\\temp\\malware.exe"}])
        self.assertTrue(r.has_file_system_activity)

    def test_has_file_system_activity_true_with_written(self):
        r = VTBehaviourResult(files_written=["C:\\temp\\log.txt"])
        self.assertTrue(r.has_file_system_activity)

    def test_has_process_activity_false_when_empty(self):
        r = VTBehaviourResult()
        self.assertFalse(r.has_process_activity)

    def test_has_process_activity_true_with_commands(self):
        r = VTBehaviourResult(command_executions=["cmd.exe /c del *"])
        self.assertTrue(r.has_process_activity)

    def test_has_process_activity_true_with_processes(self):
        r = VTBehaviourResult(processes_created=["svchost.exe"])
        self.assertTrue(r.has_process_activity)

    def test_vst_sandbox_harness_not_injection_like(self):
        """VT often loads plugins via rundll32 + GetPluginFactory — not injection."""
        r = VTBehaviourResult(
            processes_created=[
                'rundll32.exe "C:\\Users\\user\\Desktop\\readme.dll",GetPluginFactory',
                "rundll32.exe readme.dll,InitDll",
            ],
        )
        self.assertTrue(r.has_process_activity)
        self.assertFalse(r.has_injection_like_sandbox_process_activity)

    def test_powershell_in_process_blob_is_injection_like(self):
        r = VTBehaviourResult(
            command_executions=['powershell.exe -EncodedCommand abc'],
            processes_created=["rundll32.exe x.dll,GetPluginFactory"],
        )
        self.assertTrue(r.has_injection_like_sandbox_process_activity)

    def test_rundll32_without_plugin_exports_still_injection_like(self):
        r = VTBehaviourResult(
            processes_created=['rundll32.exe "C:\\mal\\evil.dll",DllMain'],
        )
        self.assertTrue(r.has_injection_like_sandbox_process_activity)

    def test_has_mitre_data_false_when_empty(self):
        r = VTBehaviourResult()
        self.assertFalse(r.has_mitre_data)

    def test_has_mitre_data_true_with_techniques(self):
        r = VTBehaviourResult(
            mitre_attack_techniques=[{"id": "T1055", "severity": "HIGH"}]
        )
        self.assertTrue(r.has_mitre_data)

    def test_to_dict_keys(self):
        r = VTBehaviourResult(queried=True, found=True)
        d = r.to_dict()
        expected_keys = {
            "queried", "found", "error",
            "dns_lookups", "ip_traffic", "http_conversations",
            "files_dropped", "files_written",
            "command_executions", "processes_created", "processes_tree",
            "registry_keys_set", "mutexes_created", "services_created",
            "calls_highlighted", "tags", "mitre_attack_techniques",
            "has_network_activity", "has_file_system_activity",
            "has_process_activity", "has_injection_like_sandbox_process_activity",
            "has_mitre_data",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_to_dict_is_json_serialisable(self):
        r = VTBehaviourResult(
            queried=True, found=True,
            dns_lookups=[{"hostname": "evil.com", "resolved_ips": ["1.2.3.4"]}],
            command_executions=["powershell -enc BASE64"],
            tags=["miner", "rat"],
        )
        json_str = json.dumps(r.to_dict())
        parsed = json.loads(json_str)
        self.assertEqual(parsed["dns_lookups"][0]["hostname"], "evil.com")
        self.assertTrue(parsed["has_network_activity"])
        self.assertTrue(parsed["has_process_activity"])


# ---------------------------------------------------------------------------
# Tests: Behaviour Response Parsing
# ---------------------------------------------------------------------------

def _make_behaviour_response(
    dns_lookups=None,
    ip_traffic=None,
    http_conversations=None,
    files_dropped=None,
    files_written=None,
    command_executions=None,
    processes_created=None,
    processes_tree=None,
    registry_keys_set=None,
    mutexes_created=None,
    services_created=None,
    calls_highlighted=None,
    tags=None,
    mitre_attack_techniques=None,
):
    """Build a realistic VT /behaviour_summary response."""
    data = {}
    if dns_lookups is not None:
        data["dns_lookups"] = dns_lookups
    if ip_traffic is not None:
        data["ip_traffic"] = ip_traffic
    if http_conversations is not None:
        data["http_conversations"] = http_conversations
    if files_dropped is not None:
        data["files_dropped"] = files_dropped
    if files_written is not None:
        data["files_written"] = files_written
    if command_executions is not None:
        data["command_executions"] = command_executions
    if processes_created is not None:
        data["processes_created"] = processes_created
    if processes_tree is not None:
        data["processes_tree"] = processes_tree
    if registry_keys_set is not None:
        data["registry_keys_set"] = registry_keys_set
    if mutexes_created is not None:
        data["mutexes_created"] = mutexes_created
    if services_created is not None:
        data["services_created"] = services_created
    if calls_highlighted is not None:
        data["calls_highlighted"] = calls_highlighted
    if tags is not None:
        data["tags"] = tags
    if mitre_attack_techniques is not None:
        data["mitre_attack_techniques"] = mitre_attack_techniques
    return {"data": data}


class TestBehaviourResponseParsing(unittest.TestCase):
    """Test _parse_behaviour_response with synthetic data."""

    def test_parses_dns_lookups(self):
        data = _make_behaviour_response(
            dns_lookups=[
                {"hostname": "c2.evil.com", "resolved_ips": ["1.2.3.4", "5.6.7.8"]},
                {"hostname": "update.malware.net", "resolved_ips": []},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertTrue(result.found)
        self.assertEqual(len(result.dns_lookups), 2)
        self.assertEqual(result.dns_lookups[0]["hostname"], "c2.evil.com")
        self.assertEqual(result.dns_lookups[0]["resolved_ips"], ["1.2.3.4", "5.6.7.8"])

    def test_parses_ip_traffic(self):
        data = _make_behaviour_response(
            ip_traffic=[
                {"destination_ip": "10.0.0.1", "destination_port": 443,
                 "transport_layer_protocol": "TCP"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.ip_traffic), 1)
        self.assertEqual(result.ip_traffic[0]["destination_ip"], "10.0.0.1")
        self.assertEqual(result.ip_traffic[0]["destination_port"], 443)
        self.assertEqual(result.ip_traffic[0]["protocol"], "TCP")

    def test_parses_http_conversations(self):
        data = _make_behaviour_response(
            http_conversations=[
                {"url": "http://evil.com/payload", "request_method": "POST",
                 "response_status_code": 200},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.http_conversations), 1)
        self.assertEqual(result.http_conversations[0]["url"], "http://evil.com/payload")
        self.assertEqual(result.http_conversations[0]["method"], "POST")
        self.assertEqual(result.http_conversations[0]["status_code"], 200)

    def test_parses_files_dropped(self):
        data = _make_behaviour_response(
            files_dropped=[
                {"path": "C:\\Temp\\miner.exe", "sha256": "abcdef1234567890" * 4},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.files_dropped), 1)
        self.assertEqual(result.files_dropped[0]["path"], "C:\\Temp\\miner.exe")
        self.assertTrue(result.files_dropped[0]["sha256"].startswith("abcdef"))

    def test_parses_files_written(self):
        data = _make_behaviour_response(
            files_written=["C:\\Users\\victim\\log.txt", "C:\\Temp\\data.bin"]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.files_written), 2)
        self.assertIn("C:\\Users\\victim\\log.txt", result.files_written)

    def test_parses_command_executions(self):
        data = _make_behaviour_response(
            command_executions=["cmd.exe /c whoami", "powershell -enc AAAA"]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.command_executions), 2)
        self.assertIn("cmd.exe /c whoami", result.command_executions)

    def test_parses_processes_created(self):
        data = _make_behaviour_response(
            processes_created=["svchost.exe", "conhost.exe"]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.processes_created), 2)

    def test_parses_registry_keys_set(self):
        data = _make_behaviour_response(
            registry_keys_set=[
                {"key": "HKLM\\Software\\Run\\Evil", "value": "C:\\malware.exe"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.registry_keys_set), 1)
        self.assertEqual(result.registry_keys_set[0]["key"], "HKLM\\Software\\Run\\Evil")

    def test_parses_mutexes_and_services(self):
        data = _make_behaviour_response(
            mutexes_created=["Global\\MyMutex"],
            services_created=["MalwareService"],
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(result.mutexes_created, ["Global\\MyMutex"])
        self.assertEqual(result.services_created, ["MalwareService"])

    def test_parses_tags_and_calls_highlighted(self):
        data = _make_behaviour_response(
            tags=["miner", "trojan", "rat"],
            calls_highlighted=["CreateRemoteThread", "VirtualAllocEx"],
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(result.tags, ["miner", "trojan", "rat"])
        self.assertEqual(len(result.calls_highlighted), 2)

    def test_caps_network_entries(self):
        """Verify that network lists are capped at _BEH_CAP_NETWORK."""
        many_dns = [{"hostname": f"host{i}.com", "resolved_ips": []} for i in range(50)]
        data = _make_behaviour_response(dns_lookups=many_dns)
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.dns_lookups), _BEH_CAP_NETWORK)

    def test_caps_file_entries(self):
        """Verify that file lists are capped at _BEH_CAP_FILES."""
        many_files = [f"C:\\file{i}.txt" for i in range(50)]
        data = _make_behaviour_response(files_written=many_files)
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.files_written), _BEH_CAP_FILES)

    def test_caps_general_entries(self):
        """Verify that process/persistence lists are capped at _BEH_CAP_GENERAL."""
        many_cmds = [f"cmd /c echo {i}" for i in range(30)]
        data = _make_behaviour_response(command_executions=many_cmds)
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.command_executions), _BEH_CAP_GENERAL)

    def test_empty_response_data(self):
        """An empty data dict should still set found=True with empty lists."""
        data = {"data": {}}
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertTrue(result.found)
        self.assertFalse(result.has_network_activity)
        self.assertFalse(result.has_file_system_activity)
        self.assertFalse(result.has_process_activity)

    def test_malformed_entries_skipped(self):
        """Non-dict entries in DNS list should be skipped."""
        data = _make_behaviour_response(
            dns_lookups=["not_a_dict", 42, {"hostname": "valid.com", "resolved_ips": []}]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.dns_lookups), 1)
        self.assertEqual(result.dns_lookups[0]["hostname"], "valid.com")

    def test_full_behaviour_response(self):
        """Test with a realistic multi-field response."""
        data = _make_behaviour_response(
            dns_lookups=[
                {"hostname": "pool.mining.com", "resolved_ips": ["93.184.216.34"]},
            ],
            ip_traffic=[
                {"destination_ip": "93.184.216.34", "destination_port": 3333,
                 "transport_layer_protocol": "TCP"},
            ],
            files_dropped=[
                {"path": "C:\\Windows\\Temp\\xmrig.exe", "sha256": "a" * 64},
            ],
            command_executions=["xmrig.exe --donate-level 0"],
            registry_keys_set=[
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Miner",
                 "value": "C:\\Windows\\Temp\\xmrig.exe"},
            ],
            tags=["miner", "persistence"],
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertTrue(result.found)
        self.assertTrue(result.has_network_activity)
        self.assertTrue(result.has_file_system_activity)
        self.assertTrue(result.has_process_activity)
        self.assertEqual(len(result.dns_lookups), 1)
        self.assertEqual(len(result.ip_traffic), 1)
        self.assertEqual(len(result.files_dropped), 1)
        self.assertEqual(len(result.command_executions), 1)
        self.assertEqual(len(result.registry_keys_set), 1)
        self.assertEqual(result.tags, ["miner", "persistence"])


# ---------------------------------------------------------------------------
# Tests: lookup_behaviours (mocked HTTP)
# ---------------------------------------------------------------------------

class TestLookupBehaviours(unittest.TestCase):
    """Test lookup_behaviours with mocked requests.get."""

    def test_no_api_key_skips_lookup(self):
        result = lookup_behaviours("abc123", "")
        self.assertFalse(result.queried)
        self.assertIn("No API key", result.error)

    def test_empty_api_key_skips_lookup(self):
        result = lookup_behaviours("abc123", "   ")
        self.assertFalse(result.queried)

    @patch("virustotal.requests.get")
    def test_successful_behaviour_lookup(self, mock_get):
        body = _make_behaviour_response(
            dns_lookups=[{"hostname": "evil.com", "resolved_ips": ["1.2.3.4"]}],
            command_executions=["malware.exe --run"],
        )
        mock_get.return_value = _MockResponse(200, body)
        result = lookup_behaviours("sha256hash", "valid_key")
        self.assertTrue(result.queried)
        self.assertTrue(result.found)
        self.assertEqual(len(result.dns_lookups), 1)
        self.assertEqual(len(result.command_executions), 1)

    @patch("virustotal.requests.get")
    def test_behaviour_not_found_404(self, mock_get):
        mock_get.return_value = _MockResponse(404)
        result = lookup_behaviours("unknownhash", "valid_key")
        self.assertTrue(result.queried)
        self.assertFalse(result.found)
        self.assertEqual(result.error, "")

    @patch("virustotal.requests.get")
    def test_behaviour_rate_limit_429(self, mock_get):
        mock_get.return_value = _MockResponse(429)
        result = lookup_behaviours("hash", "valid_key")
        self.assertIn("Rate limit", result.error)

    @patch("virustotal.requests.get")
    def test_behaviour_unexpected_status(self, mock_get):
        mock_get.return_value = _MockResponse(500)
        result = lookup_behaviours("hash", "valid_key")
        self.assertIn("HTTP 500", result.error)

    @patch("virustotal.requests.get")
    def test_behaviour_connection_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.ConnectionError("DNS failure")
        result = lookup_behaviours("hash", "valid_key")
        self.assertIn("Connection error", result.error)

    @patch("virustotal.requests.get")
    def test_behaviour_timeout_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.Timeout("timed out")
        result = lookup_behaviours("hash", "valid_key")
        self.assertIn("timed out", result.error)

    @patch("virustotal.requests.get")
    def test_behaviour_uses_correct_url(self, mock_get):
        mock_get.return_value = _MockResponse(404)
        lookup_behaviours("deadbeef123", "my_key")
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], f"{VT_API_BASE}/deadbeef123/behaviour_summary")
        self.assertEqual(kwargs["headers"]["x-apikey"], "my_key")


# ---------------------------------------------------------------------------
# Tests: Analyzer Behaviour Integration
# ---------------------------------------------------------------------------

class TestAnalyzerBehaviourIntegration(unittest.TestCase):
    """Test that analyzer.py correctly calls behaviour lookup and integrates data."""

    @staticmethod
    def _create_minimal_dll(imports=None):
        """Create a minimal PE DLL (same helper as TestAnalyzerVTIntegration)."""
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
            idt_offset, name_offset, ilt_offset, hint_offset = 0x000, 0x100, 0x200, 0x400
            va_base = 0x1000
            dll_list = list(imports.items())
            for i, (dll_name, funcs) in enumerate(dll_list):
                dll_name_bytes = dll_name.encode("ascii") + b"\x00"
                section_data[name_offset:name_offset + len(dll_name_bytes)] = dll_name_bytes
                dll_name_rva = va_base + name_offset
                name_offset += len(dll_name_bytes)
                idt_entry_offset = idt_offset + i * 20
                ilt_rva = va_base + ilt_offset
                struct.pack_into("<I", section_data, idt_entry_offset, ilt_rva)
                struct.pack_into("<I", section_data, idt_entry_offset + 12, dll_name_rva)
                struct.pack_into("<I", section_data, idt_entry_offset + 16, ilt_rva)
                for j, func_name in enumerate(funcs):
                    hn_bytes = struct.pack("<H", j) + func_name.encode("ascii") + b"\x00"
                    if len(hn_bytes) % 2:
                        hn_bytes += b"\x00"
                    section_data[hint_offset:hint_offset + len(hn_bytes)] = hn_bytes
                    hn_rva = va_base + hint_offset
                    hint_offset += len(hn_bytes)
                    struct.pack_into("<I", section_data, ilt_offset + j * 4, hn_rva)
                ilt_offset += (len(funcs) + 1) * 4
            struct.pack_into("<I", opt, 104, va_base)
            struct.pack_into("<I", opt, 108, (len(dll_list) + 1) * 20)

        headers = dos_header + pe_sig + coff + opt + sec
        headers += b"\x00" * (0x200 - len(headers))
        pe_data = headers + section_data

        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(pe_data)
        return path

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_called_for_high_risk_vt_match(self, mock_vt_hash, mock_vt_beh):
        """Behaviour lookup should be called when verdict is High Risk and VT found."""
        from analyzer import analyze_file
        # Simulate VT finding a heavily-detected malware (High Risk)
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            dns_lookups=[{"hostname": "c2.evil.com", "resolved_ips": ["1.2.3.4"]}],
            files_dropped=[{"path": "C:\\Temp\\payload.exe", "sha256": "a" * 64}],
            command_executions=["payload.exe --install"],
        )
        # Use imports that trigger High Risk even without VT
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            self.assertEqual(result.verdict, "High Risk")
            mock_vt_beh.assert_called_once()

            # Behaviour data should be populated
            beh = result.vt_behaviours
            self.assertTrue(beh["queried"])
            self.assertTrue(beh["found"])
            self.assertEqual(len(beh["dns_lookups"]), 1)
            self.assertEqual(len(beh["files_dropped"]), 1)
            self.assertEqual(len(beh["command_executions"]), 1)

            # Warnings should include sandbox context
            warnings_str = " ".join(result.warnings)
            self.assertIn("Sandbox: Network activity", warnings_str)
            self.assertIn("Sandbox: File-system activity", warnings_str)
            self.assertIn("Sandbox: Process activity", warnings_str)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_not_called_for_safe_verdict(self, mock_vt_hash, mock_vt_beh):
        """Behaviour lookup should NOT be called for Safe verdicts."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=0,
            total_engines=72, score_contribution=VT_SCORE_CLEAN,
        )
        path = self._create_minimal_dll({"kernel32.dll": ["HeapAlloc"]})
        try:
            result = analyze_file(path, vt_api_key="test_key")
            mock_vt_beh.assert_not_called()
            self.assertFalse(result.vt_behaviours.get("queried", False))
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_not_called_when_vt_not_found(self, mock_vt_hash, mock_vt_beh):
        """Behaviour lookup should NOT be called if VT hash was not found."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=False, score_contribution=VT_SCORE_NOT_FOUND,
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            mock_vt_beh.assert_not_called()
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_not_called_without_vt_key(self, mock_vt_hash, mock_vt_beh):
        """Behaviour lookup should NOT be called when no API key is provided."""
        from analyzer import analyze_file
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="")
            mock_vt_beh.assert_not_called()
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_error_added_to_warnings(self, mock_vt_hash, mock_vt_beh):
        """Behaviour lookup errors should appear in warnings."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=False,
            error="Rate limit exceeded during behaviour lookup",
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            warnings_str = " ".join(result.warnings)
            self.assertIn("Sandbox behaviour lookup", warnings_str)
            self.assertIn("Rate limit", warnings_str)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_in_report(self, mock_vt_hash, mock_vt_beh):
        """Behaviour data should appear in the text report."""
        from analyzer import analyze_file, generate_report
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            dns_lookups=[{"hostname": "pool.mining.com", "resolved_ips": ["93.184.216.34"]}],
            files_dropped=[{"path": "C:\\Temp\\xmrig.exe", "sha256": "a" * 64}],
            command_executions=["xmrig.exe --donate-level 0"],
            registry_keys_set=[{"key": "HKCU\\Run\\Miner", "value": "xmrig.exe"}],
            tags=["miner"],
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            report = generate_report(result)
            self.assertIn("SANDBOX BEHAVIOUR", report)
            self.assertIn("pool.mining.com", report)
            self.assertIn("xmrig.exe", report)
            self.assertIn("HKCU", report)
            self.assertIn("miner", report)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_behaviour_in_json_output(self, mock_vt_hash, mock_vt_beh):
        """Behaviour data should appear in JSON export."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            dns_lookups=[{"hostname": "evil.com", "resolved_ips": []}],
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            parsed = json.loads(result.to_json())
            self.assertIn("vt_behaviours", parsed)
            self.assertTrue(parsed["vt_behaviours"]["queried"])
            self.assertTrue(parsed["vt_behaviours"]["found"])
            self.assertEqual(len(parsed["vt_behaviours"]["dns_lookups"]), 1)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Tests: MITRE ATT&CK Knowledge Base
# ---------------------------------------------------------------------------

class TestMitreKnowledgeBase(unittest.TestCase):
    """Test the MITRE ATT&CK knowledge base and lookup functions."""

    def test_knowledge_base_not_empty(self):
        kb = get_mitre_knowledge_base()
        self.assertGreater(len(kb), 50)  # We registered ~90+ techniques

    def test_known_technique_lookup(self):
        tech = get_mitre_technique("T1055")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.technique_id, "T1055")
        self.assertEqual(tech.name, "Process Injection")
        self.assertEqual(tech.tactic, "Defense Evasion")
        self.assertEqual(tech.category, "evasion")
        self.assertIn("T1055", tech.url)

    def test_subtechnique_lookup(self):
        tech = get_mitre_technique("T1059.001")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.name, "PowerShell")
        self.assertEqual(tech.category, "process")

    def test_unknown_technique_returns_none(self):
        self.assertIsNone(get_mitre_technique("T9999"))

    def test_network_techniques_exist(self):
        for tid in ("T1071", "T1071.001", "T1071.004", "T1573", "T1095"):
            tech = get_mitre_technique(tid)
            self.assertIsNotNone(tech, f"Missing network technique {tid}")
            self.assertEqual(tech.category, "network")

    def test_persistence_techniques_exist(self):
        for tid in ("T1547.001", "T1543.003", "T1574.001", "T1574.002"):
            tech = get_mitre_technique(tid)
            self.assertIsNotNone(tech, f"Missing persistence technique {tid}")
            self.assertEqual(tech.category, "persistence")

    def test_mitre_url_format(self):
        tech = get_mitre_technique("T1070.004")
        self.assertEqual(
            tech.url,
            "https://attack.mitre.org/techniques/T1070/004/",
        )

    def test_mitre_technique_is_frozen(self):
        tech = get_mitre_technique("T1055")
        with self.assertRaises(AttributeError):
            tech.name = "Modified"  # frozen dataclass

    def test_resource_hijacking_for_cryptomining(self):
        tech = get_mitre_technique("T1496")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.name, "Resource Hijacking")


# ---------------------------------------------------------------------------
# Tests: MITRE ATT&CK Parsing from Behaviour Response
# ---------------------------------------------------------------------------

class TestMitreBehaviourParsing(unittest.TestCase):
    """Test parsing of mitre_attack_techniques from behaviour_summary."""

    def test_parses_mitre_techniques(self):
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                {"id": "T1055", "signature_description": "Spawns processes",
                 "severity": "HIGH"},
                {"id": "T1082", "signature_description": "Reads software policies",
                 "severity": "INFO"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.mitre_attack_techniques), 2)
        self.assertTrue(result.has_mitre_data)

    def test_enriches_known_technique(self):
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                {"id": "T1059.001", "signature_description": "Uses PowerShell",
                 "severity": "MEDIUM"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        tech = result.mitre_attack_techniques[0]
        self.assertEqual(tech["id"], "T1059.001")
        self.assertEqual(tech["name"], "PowerShell")
        self.assertEqual(tech["tactic"], "Execution")
        self.assertEqual(tech["category"], "process")
        self.assertIn("T1059/001", tech["url"])

    def test_unknown_technique_gets_empty_name(self):
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                {"id": "T9999", "signature_description": "Unknown",
                 "severity": "LOW"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        tech = result.mitre_attack_techniques[0]
        self.assertEqual(tech["id"], "T9999")
        self.assertEqual(tech["name"], "")  # Not in KB
        self.assertEqual(tech["category"], "general")  # Default
        self.assertIn("T9999", tech["url"])  # URL still generated

    def test_deduplicates_techniques(self):
        """Duplicate technique IDs should be deduplicated."""
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                {"id": "T1055", "signature_description": "First", "severity": "HIGH"},
                {"id": "T1055", "signature_description": "Duplicate", "severity": "MEDIUM"},
                {"id": "T1082", "signature_description": "Different", "severity": "INFO"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.mitre_attack_techniques), 2)
        ids = [t["id"] for t in result.mitre_attack_techniques]
        self.assertIn("T1055", ids)
        self.assertIn("T1082", ids)

    def test_case_insensitive_ids(self):
        """Lowercase IDs from VT should be normalised to uppercase."""
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                {"id": "t1055", "signature_description": "Lower case",
                 "severity": "HIGH"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(result.mitre_attack_techniques[0]["id"], "T1055")
        # Should still match KB for enrichment
        self.assertEqual(result.mitre_attack_techniques[0]["name"], "Process Injection")

    def test_caps_mitre_entries(self):
        """Verify that MITRE techniques list is capped."""
        many_techs = [
            {"id": f"T{i}", "signature_description": f"Desc {i}", "severity": "INFO"}
            for i in range(60)
        ]
        data = _make_behaviour_response(mitre_attack_techniques=many_techs)
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertLessEqual(len(result.mitre_attack_techniques), _BEH_CAP_MITRE)

    def test_malformed_mitre_entries_skipped(self):
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                "not_a_dict",
                42,
                {"id": "", "signature_description": "Empty ID", "severity": "LOW"},
                {"id": "T1082", "signature_description": "Valid", "severity": "INFO"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertEqual(len(result.mitre_attack_techniques), 1)
        self.assertEqual(result.mitre_attack_techniques[0]["id"], "T1082")

    def test_mitre_in_to_dict(self):
        r = VTBehaviourResult(
            queried=True, found=True,
            mitre_attack_techniques=[
                {"id": "T1055", "description": "test", "severity": "HIGH",
                 "name": "Process Injection", "tactic": "Defense Evasion",
                 "category": "evasion", "url": "https://attack.mitre.org/techniques/T1055/"}
            ]
        )
        d = r.to_dict()
        self.assertEqual(len(d["mitre_attack_techniques"]), 1)
        self.assertTrue(d["has_mitre_data"])

    def test_severity_preserved(self):
        data = _make_behaviour_response(
            mitre_attack_techniques=[
                {"id": "T1055", "signature_description": "Spawns", "severity": "HIGH"},
                {"id": "T1082", "signature_description": "Reads", "severity": "info"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        severities = {t["id"]: t["severity"] for t in result.mitre_attack_techniques}
        self.assertEqual(severities["T1055"], "HIGH")
        self.assertEqual(severities["T1082"], "INFO")  # Normalised to uppercase

    def test_combined_behaviour_and_mitre(self):
        """Full response with behaviour data + MITRE techniques."""
        data = _make_behaviour_response(
            dns_lookups=[
                {"hostname": "pool.mining.com", "resolved_ips": ["93.184.216.34"]},
            ],
            command_executions=["xmrig.exe --donate-level 0"],
            mitre_attack_techniques=[
                {"id": "T1496", "signature_description": "CPU mining detected",
                 "severity": "HIGH"},
                {"id": "T1071.004", "signature_description": "DNS C2 channel",
                 "severity": "MEDIUM"},
                {"id": "T1059.003", "signature_description": "cmd.exe used",
                 "severity": "MEDIUM"},
            ]
        )
        result = _parse_behaviour_response(data, VTBehaviourResult(queried=True))
        self.assertTrue(result.has_network_activity)
        self.assertTrue(result.has_process_activity)
        self.assertTrue(result.has_mitre_data)
        self.assertEqual(len(result.mitre_attack_techniques), 3)

        # Verify categories were enriched from KB
        categories = {t["id"]: t["category"] for t in result.mitre_attack_techniques}
        self.assertEqual(categories["T1496"], "network")      # Resource Hijacking
        self.assertEqual(categories["T1071.004"], "network")  # DNS C2
        self.assertEqual(categories["T1059.003"], "process")  # Windows Command Shell


# ---------------------------------------------------------------------------
# Tests: Analyzer MITRE ATT&CK Integration
# ---------------------------------------------------------------------------

class TestAnalyzerMitreIntegration(unittest.TestCase):
    """Test that analyzer.py includes MITRE ATT&CK data in output."""

    @staticmethod
    def _create_minimal_dll(imports=None):
        """Create a minimal PE DLL (reused helper)."""
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
            idt_offset, name_offset, ilt_offset, hint_offset = 0x000, 0x100, 0x200, 0x400
            va_base = 0x1000
            dll_list = list(imports.items())
            for i, (dll_name, funcs) in enumerate(dll_list):
                dll_name_bytes = dll_name.encode("ascii") + b"\x00"
                section_data[name_offset:name_offset + len(dll_name_bytes)] = dll_name_bytes
                dll_name_rva = va_base + name_offset
                name_offset += len(dll_name_bytes)
                idt_entry_offset = idt_offset + i * 20
                ilt_rva = va_base + ilt_offset
                struct.pack_into("<I", section_data, idt_entry_offset, ilt_rva)
                struct.pack_into("<I", section_data, idt_entry_offset + 12, dll_name_rva)
                struct.pack_into("<I", section_data, idt_entry_offset + 16, ilt_rva)
                for j, func_name in enumerate(funcs):
                    hn_bytes = struct.pack("<H", j) + func_name.encode("ascii") + b"\x00"
                    if len(hn_bytes) % 2:
                        hn_bytes += b"\x00"
                    section_data[hint_offset:hint_offset + len(hn_bytes)] = hn_bytes
                    hn_rva = va_base + hint_offset
                    hint_offset += len(hn_bytes)
                    struct.pack_into("<I", section_data, ilt_offset + j * 4, hn_rva)
                ilt_offset += (len(funcs) + 1) * 4
            struct.pack_into("<I", opt, 104, va_base)
            struct.pack_into("<I", opt, 108, (len(dll_list) + 1) * 20)

        headers = dos_header + pe_sig + coff + opt + sec
        headers += b"\x00" * (0x200 - len(headers))
        pe_data = headers + section_data

        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(pe_data)
        return path

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_mitre_warning_generated(self, mock_vt_hash, mock_vt_beh):
        """MITRE ATT&CK warning should appear when techniques are present."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            dns_lookups=[{"hostname": "c2.evil.com", "resolved_ips": ["1.2.3.4"]}],
            mitre_attack_techniques=[
                {"id": "T1055", "description": "Spawns processes",
                 "severity": "HIGH", "name": "Process Injection",
                 "tactic": "Defense Evasion", "category": "evasion",
                 "url": "https://attack.mitre.org/techniques/T1055/"},
                {"id": "T1082", "description": "Reads policies",
                 "severity": "INFO", "name": "System Information Discovery",
                 "tactic": "Discovery", "category": "discovery",
                 "url": "https://attack.mitre.org/techniques/T1082/"},
            ],
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            warnings_str = " ".join(result.warnings)
            self.assertIn("MITRE ATT&CK", warnings_str)
            self.assertIn("2 techniques", warnings_str)
            self.assertIn("1 HIGH", warnings_str)
            self.assertIn("1 INFO", warnings_str)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_mitre_in_report(self, mock_vt_hash, mock_vt_beh):
        """MITRE ATT&CK MAPPING section should appear in text report."""
        from analyzer import analyze_file, generate_report
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            mitre_attack_techniques=[
                {"id": "T1496", "description": "CPU mining detected",
                 "severity": "HIGH", "name": "Resource Hijacking",
                 "tactic": "Impact", "category": "network",
                 "url": "https://attack.mitre.org/techniques/T1496/"},
                {"id": "T1059.001", "description": "PowerShell executed",
                 "severity": "MEDIUM", "name": "PowerShell",
                 "tactic": "Execution", "category": "process",
                 "url": "https://attack.mitre.org/techniques/T1059/001/"},
            ],
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            report = generate_report(result)
            self.assertIn("MITRE ATT&CK MAPPING", report)
            self.assertIn("T1496", report)
            self.assertIn("Resource Hijacking", report)
            self.assertIn("T1059.001", report)
            self.assertIn("PowerShell", report)
            self.assertIn("attack.mitre.org", report)
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_mitre_in_json_output(self, mock_vt_hash, mock_vt_beh):
        """MITRE ATT&CK techniques should appear in JSON export."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            mitre_attack_techniques=[
                {"id": "T1055", "description": "Spawns", "severity": "HIGH",
                 "name": "Process Injection", "tactic": "Defense Evasion",
                 "category": "evasion",
                 "url": "https://attack.mitre.org/techniques/T1055/"},
            ],
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            parsed = json.loads(result.to_json())
            mitre = parsed["vt_behaviours"]["mitre_attack_techniques"]
            self.assertEqual(len(mitre), 1)
            self.assertEqual(mitre[0]["id"], "T1055")
            self.assertEqual(mitre[0]["name"], "Process Injection")
            self.assertTrue(parsed["vt_behaviours"]["has_mitre_data"])
        finally:
            os.unlink(path)

    @patch("analyzer._vt_lookup_behaviours")
    @patch("analyzer._vt_lookup_hash")
    def test_no_mitre_warning_when_empty(self, mock_vt_hash, mock_vt_beh):
        """No MITRE warning when behaviour data has no techniques."""
        from analyzer import analyze_file
        mock_vt_hash.return_value = VTResult(
            queried=True, found=True, malicious=30,
            total_engines=72, score_contribution=VT_SCORE_HIGH,
        )
        mock_vt_beh.return_value = VTBehaviourResult(
            queried=True, found=True,
            dns_lookups=[{"hostname": "evil.com", "resolved_ips": []}],
            mitre_attack_techniques=[],  # Empty
        )
        path = self._create_minimal_dll({
            "kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
        })
        try:
            result = analyze_file(path, vt_api_key="test_key")
            warnings_str = " ".join(result.warnings)
            self.assertNotIn("MITRE ATT&CK", warnings_str)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
