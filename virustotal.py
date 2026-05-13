"""
VST-Sentry — VirusTotal API v3 Client
========================================

Performs hash-based lookups against the VirusTotal file database to
cross-reference locally analysed DLLs with 70+ antivirus engine results.
For High-Risk verdicts, also pulls sandbox behaviour data (network
connections, dropped files, process activity) from the /behaviour_summary
endpoint.

This module is intentionally separate from the core analyser so that:
    1. The static analyser still works fully offline (no API key required).
    2. The VT lookup can be unit-tested and mocked independently.
    3. Rate-limiting logic lives in a single, auditable location.

API Reference:
    GET  https://www.virustotal.com/api/v3/files/{sha256}
    GET  https://www.virustotal.com/api/v3/files/{sha256}/behaviour_summary
    Docs https://docs.virustotal.com/reference/file-info
    Docs https://docs.virustotal.com/reference/file-all-behaviours-summary

Free-tier constraints (as of 2024):
    - 4 requests / minute
    - 500 requests / day

Author:  VST-Sentry Project
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VT_API_BASE = "https://www.virustotal.com/api/v3/files"
VT_REQUEST_TIMEOUT = 30          # seconds
VT_RATE_LIMIT_PAUSE = 16         # seconds to wait on 429 (free tier = 4 req/min)

# Scoring thresholds — how many VT detections map to how many risk points
VT_SCORE_CLEAN = -2              # Hash known and 0 detections = slight bonus
VT_SCORE_LOW = 2                 # 1–4 detections (informational; avoid FP inflation)
VT_SCORE_MEDIUM = 20             # 5–14 detections
VT_SCORE_HIGH = 30               # 15+ detections
VT_SCORE_NOT_FOUND = 0           # Hash not in VT database — no data, no penalty
VT_SCORE_ERROR = 0               # API error / no key — skip gracefully


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------
@dataclass
class VTResult:
    """Structured result of a VirusTotal hash lookup."""

    # Lookup status
    queried: bool = False          # Was a VT request actually attempted?
    found: bool = False            # Was the hash found in VT's database?
    error: str = ""                # Non-empty if the lookup failed

    # Detection statistics (from last_analysis_stats)
    total_engines: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0

    # Threat metadata
    threat_label: str = ""         # popular_threat_classification.suggested_threat_label
    threat_names: list[str] = field(default_factory=list)  # top engine detection names
    reputation: int = 0            # VT community reputation score
    times_submitted: int = 0

    # Score contribution to VST-Sentry's risk model
    score_contribution: int = 0

    # Permalink for the user
    permalink: str = ""

    def detection_ratio_str(self) -> str:
        """Return a human-readable detection ratio, e.g. '12 / 72'."""
        if not self.found:
            return "N/A"
        return f"{self.malicious} / {self.total_engines}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON embedding."""
        return {
            "queried": self.queried,
            "found": self.found,
            "error": self.error,
            "total_engines": self.total_engines,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "undetected": self.undetected,
            "harmless": self.harmless,
            "threat_label": self.threat_label,
            "threat_names": self.threat_names,
            "reputation": self.reputation,
            "times_submitted": self.times_submitted,
            "score_contribution": self.score_contribution,
            "permalink": self.permalink,
            "detection_ratio": self.detection_ratio_str(),
        }


# ---------------------------------------------------------------------------
# Scoring Logic
# ---------------------------------------------------------------------------
def _compute_vt_score(malicious: int, found: bool) -> int:
    """
    Map VT detection count to a VST-Sentry risk-score contribution.

    Args:
        malicious: Number of AV engines flagging the file as malicious.
        found:     Whether the hash was found in VT's database at all.

    Returns:
        An integer score adjustment (can be negative for verified-clean files).
    """
    if not found:
        return VT_SCORE_NOT_FOUND

    if malicious == 0:
        return VT_SCORE_CLEAN      # Known file, zero detections = good sign
    elif malicious <= 4:
        return VT_SCORE_LOW        # Few detections — possibly PUP or FP
    elif malicious <= 14:
        return VT_SCORE_MEDIUM     # Moderate detections — likely unwanted
    else:
        return VT_SCORE_HIGH       # Broadly flagged — almost certainly malicious


# ---------------------------------------------------------------------------
# API Client
# ---------------------------------------------------------------------------
def lookup_hash(
    sha256: str,
    api_key: str,
    *,
    timeout: int = VT_REQUEST_TIMEOUT,
) -> VTResult:
    """
    Query VirusTotal API v3 for a file report by SHA-256 hash.

    Args:
        sha256:  The SHA-256 hash of the file to look up.
        api_key: A valid VirusTotal API key (free or premium).
        timeout: HTTP request timeout in seconds.

    Returns:
        A VTResult dataclass with detection data and score contribution.
        On any failure (network, auth, rate-limit exhaustion) the result's
        ``error`` field describes what went wrong and ``score_contribution``
        is 0 so the local analysis is unaffected.
    """
    result = VTResult(queried=True)

    if not api_key or not api_key.strip():
        result.error = "No API key provided"
        result.queried = False
        return result

    url = f"{VT_API_BASE}/{sha256}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key.strip(),
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.ConnectionError:
        result.error = "Connection error — check your internet connection"
        return result
    except requests.Timeout:
        result.error = f"Request timed out after {timeout}s"
        return result
    except requests.RequestException as exc:
        result.error = f"Request failed: {exc}"
        return result

    # --- Handle HTTP status codes ---
    if resp.status_code == 200:
        return _parse_vt_response(resp.json(), result, sha256)

    elif resp.status_code == 404:
        # Hash not found in VT database — not an error
        result.found = False
        result.score_contribution = VT_SCORE_NOT_FOUND
        return result

    elif resp.status_code == 401:
        result.error = "Invalid API key (HTTP 401)"
        return result

    elif resp.status_code == 429:
        result.error = "Rate limit exceeded (HTTP 429) — try again later"
        return result

    else:
        result.error = f"Unexpected HTTP {resp.status_code}"
        return result


def _parse_vt_response(
    data: dict[str, Any],
    result: VTResult,
    sha256: str,
) -> VTResult:
    """
    Parse a successful VT API v3 /files/{hash} response.

    Populates the VTResult with detection stats, threat labels, and scoring.
    """
    result.found = True
    result.permalink = f"https://www.virustotal.com/gui/file/{sha256}"

    attrs = data.get("data", {}).get("attributes", {})

    # --- Detection statistics ---
    stats = attrs.get("last_analysis_stats", {})
    result.malicious = stats.get("malicious", 0)
    result.suspicious = stats.get("suspicious", 0)
    result.undetected = stats.get("undetected", 0)
    result.harmless = stats.get("harmless", 0)
    result.total_engines = (
        result.malicious
        + result.suspicious
        + result.undetected
        + result.harmless
        + stats.get("timeout", 0)
        + stats.get("confirmed-timeout", 0)
        + stats.get("failure", 0)
        + stats.get("type-unsupported", 0)
    )

    # --- Threat classification ---
    threat_class = attrs.get("popular_threat_classification", {})
    result.threat_label = threat_class.get("suggested_threat_label", "")

    # Extract top threat names from popular_threat_name entries
    threat_name_entries = threat_class.get("popular_threat_name", [])
    if isinstance(threat_name_entries, list):
        result.threat_names = [
            entry.get("value", "") for entry in threat_name_entries[:5]
            if isinstance(entry, dict) and entry.get("value")
        ]

    # --- Community reputation ---
    result.reputation = attrs.get("reputation", 0)
    result.times_submitted = attrs.get("times_submitted", 0)

    # --- Score contribution ---
    result.score_contribution = _compute_vt_score(result.malicious, True)

    return result


# ---------------------------------------------------------------------------
# Sandbox Behaviour Data
# ---------------------------------------------------------------------------

# Caps to prevent overwhelming the analysis log with thousands of entries
_BEH_CAP_NETWORK = 25
_BEH_CAP_FILES = 25
_BEH_CAP_GENERAL = 15
_BEH_CAP_MITRE = 40            # Max ATT&CK techniques to retain


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Knowledge Base
# ---------------------------------------------------------------------------
# Maps technique IDs returned by VT sandboxes to human-readable names,
# MITRE URLs, and a behavioural category tag so we can cross-reference
# observed DNS lookups / dropped files / process commands with the
# relevant ATT&CK technique in the report.
#
# Categories align with the four behavioural data groups we already
# collect: network, file_system, process, persistence, evasion, discovery.
# Techniques that don't match a specific group get "general".

@dataclass(frozen=True)
class MitreTechnique:
    """Static metadata for a known MITRE ATT&CK technique."""
    technique_id: str
    name: str
    tactic: str          # Primary ATT&CK tactic (e.g. "Command and Control")
    category: str        # Local category tag for cross-referencing
    url: str


# Curated set of ATT&CK techniques most relevant to trojanised VST/DLL
# malware based on the VST-Sentry Threat Intelligence Report.
_MITRE_KNOWLEDGE_BASE: dict[str, MitreTechnique] = {}


def _mt(tid: str, name: str, tactic: str, category: str) -> None:
    """Helper to register a technique in the knowledge base."""
    _MITRE_KNOWLEDGE_BASE[tid] = MitreTechnique(
        technique_id=tid,
        name=name,
        tactic=tactic,
        category=category,
        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    )


# -- Command and Control / Network --
_mt("T1071",     "Application Layer Protocol",         "Command and Control", "network")
_mt("T1071.001", "Web Protocols",                      "Command and Control", "network")
_mt("T1071.004", "DNS",                                "Command and Control", "network")
_mt("T1568",     "Dynamic Resolution",                 "Command and Control", "network")
_mt("T1568.002", "Domain Generation Algorithms",       "Command and Control", "network")
_mt("T1573",     "Encrypted Channel",                  "Command and Control", "network")
_mt("T1573.001", "Symmetric Cryptography",             "Command and Control", "network")
_mt("T1573.002", "Asymmetric Cryptography",            "Command and Control", "network")
_mt("T1095",     "Non-Application Layer Protocol",     "Command and Control", "network")
_mt("T1572",     "Protocol Tunneling",                 "Command and Control", "network")
_mt("T1102",     "Web Service",                        "Command and Control", "network")
_mt("T1219",     "Remote Access Software",             "Command and Control", "network")
_mt("T1090",     "Proxy",                              "Command and Control", "network")
_mt("T1132",     "Data Encoding",                      "Command and Control", "network")
_mt("T1001",     "Data Obfuscation",                   "Command and Control", "network")
_mt("T1104",     "Multi-Stage Channels",               "Command and Control", "network")

# -- Exfiltration (network-adjacent) --
_mt("T1041",     "Exfiltration Over C2 Channel",       "Exfiltration",        "network")
_mt("T1048",     "Exfiltration Over Alternative Protocol", "Exfiltration",   "network")
_mt("T1567",     "Exfiltration Over Web Service",      "Exfiltration",        "network")

# -- Execution / Process --
_mt("T1059",     "Command and Scripting Interpreter",   "Execution",          "process")
_mt("T1059.001", "PowerShell",                          "Execution",          "process")
_mt("T1059.003", "Windows Command Shell",               "Execution",          "process")
_mt("T1059.005", "Visual Basic",                        "Execution",          "process")
_mt("T1059.006", "Python",                              "Execution",          "process")
_mt("T1059.007", "JavaScript",                          "Execution",          "process")
_mt("T1106",     "Native API",                          "Execution",          "process")
_mt("T1047",     "Windows Management Instrumentation",  "Execution",          "process")
_mt("T1053",     "Scheduled Task/Job",                  "Execution",          "process")
_mt("T1053.005", "Scheduled Task",                      "Execution",          "process")
_mt("T1569",     "System Services",                     "Execution",          "process")
_mt("T1569.002", "Service Execution",                   "Execution",          "process")
_mt("T1204",     "User Execution",                      "Execution",          "process")
_mt("T1129",     "Shared Modules",                      "Execution",          "process")

# -- Persistence --
_mt("T1547",     "Boot or Logon Autostart Execution",   "Persistence",        "persistence")
_mt("T1547.001", "Registry Run Keys / Startup Folder",  "Persistence",        "persistence")
_mt("T1543",     "Create or Modify System Process",     "Persistence",        "persistence")
_mt("T1543.003", "Windows Service",                     "Persistence",        "persistence")
_mt("T1546",     "Event Triggered Execution",           "Persistence",        "persistence")
_mt("T1546.015", "Component Object Model Hijacking",    "Persistence",        "persistence")
_mt("T1574",     "Hijack Execution Flow",               "Persistence",        "persistence")
_mt("T1574.001", "DLL Search Order Hijacking",          "Persistence",        "persistence")
_mt("T1574.002", "DLL Side-Loading",                    "Persistence",        "persistence")
_mt("T1197",     "BITS Jobs",                           "Persistence",        "persistence")
_mt("T1176",     "Browser Extensions",                  "Persistence",        "persistence")

# -- Defense Evasion --
_mt("T1055",     "Process Injection",                   "Defense Evasion",    "evasion")
_mt("T1055.001", "Dynamic-link Library Injection",      "Defense Evasion",    "evasion")
_mt("T1055.012", "Process Hollowing",                   "Defense Evasion",    "evasion")
_mt("T1036",     "Masquerading",                        "Defense Evasion",    "evasion")
_mt("T1070",     "Indicator Removal",                   "Defense Evasion",    "evasion")
_mt("T1070.004", "File Deletion",                       "Defense Evasion",    "evasion")
_mt("T1027",     "Obfuscated Files or Information",     "Defense Evasion",    "evasion")
_mt("T1027.002", "Software Packing",                    "Defense Evasion",    "evasion")
_mt("T1140",     "Deobfuscate/Decode Files",            "Defense Evasion",    "evasion")
_mt("T1562",     "Impair Defenses",                     "Defense Evasion",    "evasion")
_mt("T1562.001", "Disable or Modify Tools",             "Defense Evasion",    "evasion")
_mt("T1112",     "Modify Registry",                     "Defense Evasion",    "evasion")
_mt("T1497",     "Virtualization/Sandbox Evasion",      "Defense Evasion",    "evasion")
_mt("T1497.001", "System Checks",                       "Defense Evasion",    "evasion")
_mt("T1218",     "System Binary Proxy Execution",       "Defense Evasion",    "evasion")
_mt("T1218.011", "Rundll32",                            "Defense Evasion",    "evasion")
_mt("T1564",     "Hide Artifacts",                      "Defense Evasion",    "evasion")
_mt("T1564.001", "Hidden Files and Directories",        "Defense Evasion",    "evasion")

# -- Discovery --
_mt("T1082",     "System Information Discovery",        "Discovery",          "discovery")
_mt("T1083",     "File and Directory Discovery",        "Discovery",          "discovery")
_mt("T1012",     "Query Registry",                      "Discovery",          "discovery")
_mt("T1057",     "Process Discovery",                   "Discovery",          "discovery")
_mt("T1018",     "Remote System Discovery",             "Discovery",          "discovery")
_mt("T1016",     "System Network Configuration Discovery", "Discovery",       "discovery")
_mt("T1049",     "System Network Connections Discovery", "Discovery",         "discovery")
_mt("T1007",     "System Service Discovery",            "Discovery",          "discovery")
_mt("T1033",     "System Owner/User Discovery",         "Discovery",          "discovery")
_mt("T1135",     "Network Share Discovery",             "Discovery",          "discovery")
_mt("T1010",     "Application Window Discovery",        "Discovery",          "discovery")
_mt("T1518",     "Software Discovery",                  "Discovery",          "discovery")
_mt("T1614",     "System Location Discovery",           "Discovery",          "discovery")

# -- File-System / Lateral Movement --
_mt("T1105",     "Ingress Tool Transfer",               "Command and Control", "file_system")
_mt("T1570",     "Lateral Tool Transfer",               "Lateral Movement",    "file_system")
_mt("T1486",     "Data Encrypted for Impact",           "Impact",              "file_system")
_mt("T1485",     "Data Destruction",                    "Impact",              "file_system")
_mt("T1565",     "Data Manipulation",                   "Impact",              "file_system")

# -- Credential Access --
_mt("T1003",     "OS Credential Dumping",               "Credential Access",  "process")
_mt("T1056",     "Input Capture",                       "Collection",         "process")
_mt("T1056.001", "Keylogging",                          "Collection",         "process")
_mt("T1560",     "Archive Collected Data",              "Collection",         "process")

# -- Resource Hijacking (crypto mining — very relevant to trojanised VSTs) --
_mt("T1496",     "Resource Hijacking",                  "Impact",             "network")

# Clean up the helper
del _mt


def get_mitre_technique(technique_id: str) -> MitreTechnique | None:
    """
    Look up a MITRE ATT&CK technique by ID from the local knowledge base.

    Args:
        technique_id: ATT&CK technique ID (e.g. "T1055", "T1059.001").

    Returns:
        A MitreTechnique if found, else None.
    """
    return _MITRE_KNOWLEDGE_BASE.get(technique_id)


def get_mitre_knowledge_base() -> dict[str, MitreTechnique]:
    """Return the full MITRE knowledge base dict (read-only use)."""
    return _MITRE_KNOWLEDGE_BASE


@dataclass
class VTBehaviourResult:
    """Structured result of a VirusTotal sandbox behaviour lookup."""

    # Lookup status
    queried: bool = False
    found: bool = False
    error: str = ""

    # Network indicators
    dns_lookups: list[dict[str, Any]] = field(default_factory=list)
    ip_traffic: list[dict[str, Any]] = field(default_factory=list)
    http_conversations: list[dict[str, Any]] = field(default_factory=list)

    # File-system activity
    files_dropped: list[dict[str, Any]] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)

    # Process / execution
    command_executions: list[str] = field(default_factory=list)
    processes_created: list[str] = field(default_factory=list)
    processes_tree: list[dict[str, Any]] = field(default_factory=list)

    # Persistence / system modification
    registry_keys_set: list[dict[str, str]] = field(default_factory=list)
    mutexes_created: list[str] = field(default_factory=list)
    services_created: list[str] = field(default_factory=list)

    # Metadata
    calls_highlighted: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # MITRE ATT&CK techniques (from VT behaviour_summary)
    # Each entry: {"id": "T1059.001", "description": "...", "severity": "HIGH"}
    mitre_attack_techniques: list[dict[str, str]] = field(default_factory=list)

    # Convenience flags
    @property
    def has_network_activity(self) -> bool:
        """True if any DNS, IP, or HTTP traffic was observed."""
        return bool(self.dns_lookups or self.ip_traffic or self.http_conversations)

    @property
    def has_file_system_activity(self) -> bool:
        """True if any files were dropped or written during sandbox execution."""
        return bool(self.files_dropped or self.files_written)

    @property
    def has_process_activity(self) -> bool:
        """True if any commands were executed or child processes spawned."""
        return bool(self.command_executions or self.processes_created)

    @property
    def has_injection_like_sandbox_process_activity(self) -> bool:
        """
        True when sandbox process telemetry looks like hostile execution chains.

        VirusTotal sandboxes load VST2/VST3 DLLs via ``rundll32`` / ``loaddll64``
        with exports such as ``GetPluginFactory`` / ``InitDll`` — that is **not**
        process injection, but ``has_process_activity`` would still be true.
        """
        if not self.has_process_activity:
            return False
        parts: list[str] = []
        parts.extend(str(c) for c in self.command_executions)
        parts.extend(str(p) for p in self.processes_created)
        blob = "\n".join(s.lower() for s in parts)

        # Obvious second-stage / LOLBins — treat as injection-like regardless.
        hostile = (
            "powershell", "pwsh", "wscript", "cscript", "mshta",
            "bitsadmin", "certutil", "encodedcommand", "frombase64string",
            "regsvr32", "odbcconf", "msiexec", "installutil",
        )
        if any(h in blob for h in hostile):
            return True

        # Typical VT / PE-sandbox harness for audio plugins (VST2/VST3 shell).
        harness_host = "rundll32" in blob or "loaddll64" in blob
        harness_export = any(
            m in blob
            for m in (
                "getpluginfactory",
                "initdll",
                "exitdll",
                "vstpluginmain",
                "canopus",
            )
        )
        if harness_host and harness_export:
            return False

        return True

    @property
    def has_mitre_data(self) -> bool:
        """True if at least one MITRE ATT&CK technique was mapped."""
        return bool(self.mitre_attack_techniques)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON embedding."""
        return {
            "queried": self.queried,
            "found": self.found,
            "error": self.error,
            "dns_lookups": self.dns_lookups,
            "ip_traffic": self.ip_traffic,
            "http_conversations": self.http_conversations,
            "files_dropped": self.files_dropped,
            "files_written": self.files_written,
            "command_executions": self.command_executions,
            "processes_created": self.processes_created,
            "processes_tree": self.processes_tree,
            "registry_keys_set": self.registry_keys_set,
            "mutexes_created": self.mutexes_created,
            "services_created": self.services_created,
            "calls_highlighted": self.calls_highlighted,
            "tags": self.tags,
            "mitre_attack_techniques": self.mitre_attack_techniques,
            "has_network_activity": self.has_network_activity,
            "has_file_system_activity": self.has_file_system_activity,
            "has_process_activity": self.has_process_activity,
            "has_injection_like_sandbox_process_activity": (
                self.has_injection_like_sandbox_process_activity
            ),
            "has_mitre_data": self.has_mitre_data,
        }


def lookup_behaviours(
    sha256: str,
    api_key: str,
    *,
    timeout: int = VT_REQUEST_TIMEOUT,
) -> VTBehaviourResult:
    """
    Query VT API v3 for sandbox behaviour data by SHA-256 hash.

    Uses the /behaviour_summary endpoint which merges all sandbox
    reports into a single aggregated view.

    Args:
        sha256:  SHA-256 hash of the file.
        api_key: VirusTotal API key.
        timeout: HTTP request timeout in seconds.

    Returns:
        A VTBehaviourResult with network, file-system, and process data.
        On failure, the ``error`` field is set and all lists are empty.
    """
    result = VTBehaviourResult(queried=True)

    if not api_key or not api_key.strip():
        result.error = "No API key provided"
        result.queried = False
        return result

    url = f"{VT_API_BASE}/{sha256}/behaviour_summary"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key.strip(),
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.ConnectionError:
        result.error = "Connection error during behaviour lookup"
        return result
    except requests.Timeout:
        result.error = f"Behaviour lookup timed out after {timeout}s"
        return result
    except requests.RequestException as exc:
        result.error = f"Behaviour request failed: {exc}"
        return result

    if resp.status_code == 200:
        return _parse_behaviour_response(resp.json(), result)
    elif resp.status_code == 404:
        result.found = False
        return result
    elif resp.status_code == 429:
        result.error = "Rate limit exceeded during behaviour lookup"
        return result
    else:
        result.error = f"Behaviour lookup HTTP {resp.status_code}"
        return result


def _parse_behaviour_response(
    data: dict[str, Any],
    result: VTBehaviourResult,
) -> VTBehaviourResult:
    """
    Parse the /behaviour_summary response.

    The summary endpoint returns data directly under "data" (no
    "attributes" wrapper), unlike the per-sandbox /behaviours endpoint.
    """
    result.found = True

    # The summary endpoint puts fields directly under "data"
    attrs = data.get("data", {})

    # --- Network ---
    raw_dns = attrs.get("dns_lookups", [])
    if isinstance(raw_dns, list):
        for entry in raw_dns[:_BEH_CAP_NETWORK]:
            if isinstance(entry, dict):
                result.dns_lookups.append({
                    "hostname": entry.get("hostname", ""),
                    "resolved_ips": entry.get("resolved_ips", []),
                })

    raw_ip = attrs.get("ip_traffic", [])
    if isinstance(raw_ip, list):
        for entry in raw_ip[:_BEH_CAP_NETWORK]:
            if isinstance(entry, dict):
                result.ip_traffic.append({
                    "destination_ip": entry.get("destination_ip", ""),
                    "destination_port": entry.get("destination_port", 0),
                    "protocol": entry.get("transport_layer_protocol", "TCP"),
                })

    raw_http = attrs.get("http_conversations", [])
    if isinstance(raw_http, list):
        for entry in raw_http[:_BEH_CAP_NETWORK]:
            if isinstance(entry, dict):
                result.http_conversations.append({
                    "url": entry.get("url", ""),
                    "method": entry.get("request_method", "GET"),
                    "status_code": entry.get("response_status_code", 0),
                })

    # --- File system ---
    raw_dropped = attrs.get("files_dropped", [])
    if isinstance(raw_dropped, list):
        for entry in raw_dropped[:_BEH_CAP_FILES]:
            if isinstance(entry, dict):
                result.files_dropped.append({
                    "path": entry.get("path", ""),
                    "sha256": entry.get("sha256", ""),
                })

    raw_written = attrs.get("files_written", [])
    if isinstance(raw_written, list):
        result.files_written = [str(f) for f in raw_written[:_BEH_CAP_FILES]]

    # --- Process / execution ---
    raw_cmds = attrs.get("command_executions", [])
    if isinstance(raw_cmds, list):
        result.command_executions = [str(c) for c in raw_cmds[:_BEH_CAP_GENERAL]]

    raw_procs = attrs.get("processes_created", [])
    if isinstance(raw_procs, list):
        result.processes_created = [str(p) for p in raw_procs[:_BEH_CAP_GENERAL]]

    raw_tree = attrs.get("processes_tree", [])
    if isinstance(raw_tree, list):
        for entry in raw_tree[:_BEH_CAP_GENERAL]:
            if isinstance(entry, dict):
                result.processes_tree.append({
                    "name": entry.get("name", ""),
                    "process_id": entry.get("process_id", ""),
                })

    # --- Persistence / system modification ---
    raw_reg = attrs.get("registry_keys_set", [])
    if isinstance(raw_reg, list):
        for entry in raw_reg[:_BEH_CAP_GENERAL]:
            if isinstance(entry, dict):
                result.registry_keys_set.append({
                    "key": entry.get("key", ""),
                    "value": str(entry.get("value", ""))[:200],  # Truncate long values
                })

    raw_mutex = attrs.get("mutexes_created", [])
    if isinstance(raw_mutex, list):
        result.mutexes_created = [str(m) for m in raw_mutex[:_BEH_CAP_GENERAL]]

    raw_svc = attrs.get("services_created", [])
    if isinstance(raw_svc, list):
        result.services_created = [str(s) for s in raw_svc[:_BEH_CAP_GENERAL]]

    # --- Metadata ---
    raw_calls = attrs.get("calls_highlighted", [])
    if isinstance(raw_calls, list):
        result.calls_highlighted = [str(c) for c in raw_calls[:_BEH_CAP_GENERAL]]

    raw_tags = attrs.get("tags", [])
    if isinstance(raw_tags, list):
        result.tags = [str(t) for t in raw_tags[:_BEH_CAP_GENERAL]]

    # --- MITRE ATT&CK Techniques ---
    raw_mitre = attrs.get("mitre_attack_techniques", [])
    if isinstance(raw_mitre, list):
        seen_ids: set[str] = set()
        for entry in raw_mitre[:_BEH_CAP_MITRE]:
            if not isinstance(entry, dict):
                continue
            technique_id = str(entry.get("id", "")).strip().upper()
            if not technique_id or technique_id in seen_ids:
                continue  # Skip duplicates and empty IDs
            seen_ids.add(technique_id)

            description = str(entry.get("signature_description", "")).strip()
            severity = str(entry.get("severity", "UNKNOWN")).strip().upper()

            # Enrich with human-readable name and category from KB
            kb_entry = get_mitre_technique(technique_id)
            enriched: dict[str, str] = {
                "id": technique_id,
                "description": description,
                "severity": severity,
                "name": kb_entry.name if kb_entry else "",
                "tactic": kb_entry.tactic if kb_entry else "",
                "category": kb_entry.category if kb_entry else "general",
                "url": (
                    kb_entry.url if kb_entry
                    else f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                ),
            }
            result.mitre_attack_techniques.append(enriched)

    return result
