"""
VST-Sentry — Static Analysis Engine for VST / DLL Plugin Files
===============================================================

This module performs static analysis on Windows Portable Executable (PE) files
(.dll, .vst3, .exe) to detect indicators of malicious intent. It cross-references
the Import Address Table (IAT) against a curated database of "Red Flag" Windows
API functions that have no legitimate purpose inside an audio-processing plugin.

Usage:
    from analyzer import analyze_file
    result = analyze_file(r"C:\\path\\to\\plugin.dll")
    # result is a dict with keys: verdict, score, details, ...

Scoring Model (from VST-Sentry Threat Intelligence Report):
    - CRITICAL  (10 pts) — Process Injection & Networking APIs
    - PACKING   (8  pts) — Entropy anomalies, packer signatures, RWX sections
    - HIGH      (7  pts) — Registry, Services, Privilege Escalation,
                           Credential Access, Keylogging/Surveillance
    - MEDIUM    (4  pts) — Anti-Analysis & Evasion
    - LOW       (2  pts) — Suspicious File Operations

Entropy Analysis (YARA-style):
    Per-section Shannon entropy is calculated on a 0–8 bits-per-byte scale.
    Thresholds derived from YARA community rules and academic research:
        Normal code  (.text) : 4.0 – 6.5
        Normal data  (.data) : 0.0 – 5.0
        Packed/compressed    : 6.8 – 7.4
        Encrypted            : 7.4 – 8.0
    Additional heuristics:
        - Known packer section names (UPX0, UPX1, .aspack, .nsp0, etc.)
        - RWX (Read-Write-Execute) section permissions
        - VirtualSize >> RawSize ratio anomalies
        - Whole-file entropy above 6.85

Triage verdict thresholds (after caps / VT / sandbox modifiers):
    Safe       :  0 – 10
    Suspicious : 11 – 35
    High Risk  : 36+

Author:  VST-Sentry Project
License: MIT
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import pefile

from virustotal import (
    VTResult,
    VTBehaviourResult,
    lookup_hash as _vt_lookup_hash,
    lookup_behaviours as _vt_lookup_behaviours,
)


# ---------------------------------------------------------------------------
# Red-Flag API Database
# ---------------------------------------------------------------------------
# Each entry maps (dll_name_lower, function_name_lower) -> (category, weight).
# Function names are stored in lowercase for case-insensitive matching.
# The "A" / "W" / "Ex" suffixes are handled by a normalization step so that
# both "InternetOpenA" and "InternetOpenW" match the same rule.

@dataclass(frozen=True)
class FlaggedAPI:
    """Represents a single flagged Windows API function."""
    dll: str
    function: str
    category: str
    weight: int
    description: str


# ---- Category 1: Process Injection & Manipulation (CRITICAL — 10 pts) ----
_PROCESS_INJECTION: list[tuple[str, str, str]] = [
    ("kernel32.dll", "CreateRemoteThread",
     "Creates a thread in a remote process — primary DLL injection vector."),
    ("kernel32.dll", "VirtualAllocEx",
     "Allocates memory in a remote process — used to stage shellcode before injection."),
    ("kernel32.dll", "WriteProcessMemory",
     "Writes data into another process's memory — copies malicious payload."),
    ("kernel32.dll", "ReadProcessMemory",
     "Reads memory from another process — credential dumping / process inspection."),
    ("kernel32.dll", "OpenProcess",
     "Opens a handle to another process with elevated access rights."),
    ("kernel32.dll", "SuspendThread",
     "Suspends a thread in another process — used in process hollowing."),
    ("kernel32.dll", "ResumeThread",
     "Resumes a suspended thread — paired with SuspendThread in injection chains."),
    ("kernel32.dll", "SetThreadContext",
     "Modifies register values of a remote thread — redirects execution to injected code."),
    ("kernel32.dll", "GetThreadContext",
     "Reads register state of a remote thread — reconnaissance before thread hijacking."),
    ("kernel32.dll", "QueueUserAPC",
     "Queues code execution in another thread — APC injection technique."),
    ("kernel32.dll", "VirtualProtectEx",
     "Changes memory protection in a remote process — makes injected code executable."),
    ("ntdll.dll", "NtCreateThreadEx",
     "Low-level thread creation — stealthier alternative to CreateRemoteThread."),
    ("ntdll.dll", "NtSetInformationProcess",
     "Changes process privilege level or bypasses DEP."),
    ("kernel32.dll", "CreateToolhelp32Snapshot",
     "Enumerates running processes — target reconnaissance for injection."),
    ("kernel32.dll", "Process32First",
     "Iterates through process list — locating injection targets."),
    ("kernel32.dll", "Process32Next",
     "Continues iterating through process list."),
    ("kernel32.dll", "EnumProcesses",
     "Enumerates all running process IDs."),
    ("kernel32.dll", "EnumProcessModules",
     "Enumerates loaded modules for a process — mapping injection targets."),
]
_PROCESS_INJECTION_WEIGHTS: dict[str, int] = {
    "createtoolhelp32snapshot": 4,
    "process32first": 4,
    "process32next": 4,
    "enumprocesses": 4,
    "enumprocessmodules": 4,
}

# ---- Category 2: Networking & C2 Communication (CRITICAL — 10 pts) ----
_NETWORKING: list[tuple[str, str, str]] = [
    ("wininet.dll", "InternetOpen",
     "Initializes WinINet for HTTP/HTTPS/FTP — start of C2 communication."),
    ("wininet.dll", "InternetOpenUrl",
     "Opens a specific URL — downloading payloads or contacting C2."),
    ("wininet.dll", "InternetReadFile",
     "Reads data from a URL connection — receiving C2 commands or payload data."),
    ("wininet.dll", "InternetWriteFile",
     "Writes data to an HTTP connection — exfiltrating stolen data."),
    ("wininet.dll", "HttpSendRequest",
     "Sends an HTTP request — C2 communication or data exfiltration."),
    ("wininet.dll", "InternetConnect",
     "Connects to an FTP or HTTP server."),
    ("wininet.dll", "HttpOpenRequest",
     "Creates an HTTP request handle — preparing C2 communication."),
    ("wininet.dll", "InternetCrackUrl",
     "Parses a URL into components — processing C2 server addresses."),
    ("wininet.dll", "InternetQueryDataAvailable",
     "Checks for available data on a connection — polling C2 for commands."),
    ("wininet.dll", "FtpPutFile",
     "Uploads a file to an FTP server — data exfiltration."),
    ("winhttp.dll", "WinHttpOpen",
     "Initializes WinHTTP — alternative to WinINet for C2 communication."),
    ("winhttp.dll", "WinHttpConnect",
     "Establishes connection to an HTTP server."),
    ("winhttp.dll", "WinHttpSendRequest",
     "Sends an HTTP request via WinHTTP."),
    ("winhttp.dll", "WinHttpReceiveResponse",
     "Receives an HTTP response via WinHTTP."),
    ("ws2_32.dll", "WSAStartup",
     "Initializes Winsock — starting point for all low-level network activity."),
    ("ws2_32.dll", "connect",
     "Connects to a remote socket — raw C2 communication."),
    ("ws2_32.dll", "send",
     "Sends data over raw sockets — C2 communication."),
    ("ws2_32.dll", "recv",
     "Receives data over raw sockets — C2 communication."),
    ("ws2_32.dll", "bind",
     "Binds a socket to a local address — reverse shell / backdoor listener."),
    ("ws2_32.dll", "accept",
     "Accepts incoming connections — backdoor listener."),
    ("ws2_32.dll", "listen",
     "Listens for incoming connections on a socket."),
    ("ws2_32.dll", "gethostbyname",
     "DNS resolution — resolving C2 server hostname."),
    ("ws2_32.dll", "gethostname",
     "Retrieves local hostname — victim machine fingerprinting."),
    ("ws2_32.dll", "inet_addr",
     "Converts IP address string to binary — connecting to hardcoded C2 IP."),
    ("wsock32.dll", "connect",
     "Legacy Winsock connect — same risk as ws2_32.connect."),
    ("wsock32.dll", "send",
     "Legacy Winsock send."),
    ("wsock32.dll", "recv",
     "Legacy Winsock recv."),
    ("urlmon.dll", "URLDownloadToFile",
     "Downloads a file from the internet to disk — dropper/downloader behavior."),
]
_NETWORKING_WEIGHTS: dict[str, int] = {
    "gethostbyname": 3,
    "gethostname": 3,
    "wsastartup": 3,
    "internetcrackurl": 3,
    "internetquerydataavailable": 3,
    "internetopen": 5,
    "internetopenurl": 5,
    "internetreadfile": 5,
    "internetconnect": 5,
    "httpopenrequest": 5,
    "internetwritefile": 7,
    "connect": 5,
    "send": 5,
    "recv": 5,
    "bind": 4,
    "listen": 4,
    "accept": 4,
    "inet_addr": 4,
}

# ---- Category 3: Registry Manipulation & Persistence (HIGH — 7 pts) ----
_REGISTRY: list[tuple[str, str, str]] = [
    ("advapi32.dll", "RegOpenKeyEx",
     "Opens a registry key — reading system config or preparing persistence."),
    ("advapi32.dll", "RegSetValueEx",
     "Writes a registry value — establishing persistence via Run keys."),
    ("advapi32.dll", "RegCreateKeyEx",
     "Creates a new registry key — persistence mechanism."),
    ("advapi32.dll", "RegDeleteKey",
     "Deletes a registry key — covering tracks or disabling security."),
    ("advapi32.dll", "RegDeleteValue",
     "Deletes a registry value."),
    ("ntdll.dll", "RtlCreateRegistryKey",
     "Kernel-mode registry key creation — rootkit behavior."),
    ("ntdll.dll", "RtlWriteRegistryValue",
     "Kernel-mode registry write — rootkit behavior."),
]
_REGISTRY_WEIGHTS: dict[str, int] = {
    "regopenkeyex": 2,
}

# ---- Category 4: Service Manipulation (HIGH — 7 pts) ----
_SERVICES: list[tuple[str, str, str]] = [
    ("advapi32.dll", "CreateService",
     "Creates a Windows service — persistence mechanism for malware."),
    ("advapi32.dll", "ControlService",
     "Starts, stops, or modifies a running service."),
    ("advapi32.dll", "StartServiceCtrlDispatcher",
     "Registers as a service — indicates code designed to run as a service."),
    ("advapi32.dll", "OpenSCManager",
     "Opens the Service Control Manager — prerequisite for service manipulation."),
    ("advapi32.dll", "StartService",
     "Starts a service."),
    ("advapi32.dll", "DeleteService",
     "Deletes a service — anti-forensics."),
]

# ---- Category 5: Privilege Escalation & Token Manipulation (HIGH — 7 pts) ----
_PRIVILEGE: list[tuple[str, str, str]] = [
    ("advapi32.dll", "AdjustTokenPrivileges",
     "Enables/disables access privileges — escalation to gain SeDebugPrivilege."),
    ("advapi32.dll", "OpenProcessToken",
     "Opens the access token of a process — prerequisite for privilege manipulation."),
    ("advapi32.dll", "LookupPrivilegeValue",
     "Looks up privilege LUID — used before AdjustTokenPrivileges."),
    ("advapi32.dll", "ImpersonateLoggedOnUser",
     "Impersonates another user's security context."),
    ("advapi32.dll", "GetTokenInformation",
     "Queries token details — reconnaissance for privilege escalation."),
    ("advapi32.dll", "DuplicateTokenEx",
     "Duplicates an access token — token impersonation attacks."),
]

# ---- Category 6: Credential Access & Cryptography (HIGH — 7 pts) ----
_CREDENTIAL: list[tuple[str, str, str]] = [
    ("advapi32.dll", "CryptAcquireContext",
     "Initializes Windows encryption — may indicate ransomware or C2 encryption."),
    ("advapi32.dll", "CryptEncrypt",
     "Encrypts data — ransomware payload encryption."),
    ("advapi32.dll", "CryptDecrypt",
     "Decrypts data — C2 data obfuscation."),
    ("advapi32.dll", "CryptGenKey",
     "Generates a cryptographic key — ransomware key generation."),
    ("crypt32.dll", "CertOpenSystemStore",
     "Accesses system certificate store — certificate theft."),
    ("advapi32.dll", "LsaEnumerateLogonSessions",
     "Enumerates logon sessions — credential stealing."),
    ("samlib.dll", "SamIConnect",
     "Connects to SAM database — password hash dumping."),
    ("samlib.dll", "SamIGetPrivateData",
     "Queries private SAM data — password hash extraction."),
    ("samlib.dll", "SamQueryInformationUse",
     "Queries SAM user information — hash dumping."),
]
_CREDENTIAL_WEIGHTS: dict[str, int] = {
    "cryptacquirecontext": 3,
    "cryptgenkey": 3,
    "cryptencrypt": 5,
    "cryptdecrypt": 5,
}

# ---- Category 7: Keylogging & Surveillance (HIGH — 7 pts) ----
_KEYLOGGING: list[tuple[str, str, str]] = [
    ("user32.dll", "SetWindowsHookEx",
     "Installs a system-wide hook — keylogging and input capture."),
    ("user32.dll", "GetAsyncKeyState",
     "Checks if a key is pressed — keylogger implementation."),
    ("user32.dll", "GetKeyState",
     "Gets key status — keylogger implementation."),
    ("user32.dll", "GetForegroundWindow",
     "Gets active window handle — identifying which app receives keystrokes."),
    ("user32.dll", "AttachThreadInput",
     "Attaches to another thread's input queue — spyware behavior."),
    ("gdi32.dll", "BitBlt",
     "Copies screen graphics — screenshot capture / screen spy."),
    ("user32.dll", "GetDC",
     "Gets device context for screen — screenshot capture."),
    ("user32.dll", "MapVirtualKey",
     "Translates virtual-key codes to characters — keylogger output formatting."),
    ("user32.dll", "RegisterHotKey",
     "Registers a global hotkey — spyware hidden activation trigger."),
]
_KEYLOGGING_WEIGHTS: dict[str, int] = {
    "setwindowshookex": 5,
    "getasynckeystate": 4,
    "bitblt": 2,
    "getdc": 2,
    "getforegroundwindow": 2,
    "getkeystate": 3,
    "mapvirtualkey": 2,
}

# ---- Category 8: Anti-Analysis & Evasion (MEDIUM — 4 pts) ----
_ANTI_ANALYSIS: list[tuple[str, str, str]] = [
    ("kernel32.dll", "IsDebuggerPresent",
     "Checks if a debugger is attached — anti-analysis technique."),
    ("kernel32.dll", "CheckRemoteDebuggerPresent",
     "Detects remote debugger — anti-analysis."),
    ("ntdll.dll", "NtQueryInformationProcess",
     "Queries process info — anti-debugging detection."),
    ("kernel32.dll", "OutputDebugString",
     "Outputs debug string — can crash or confuse debuggers."),
    ("kernel32.dll", "IsWoW64Process",
     "Checks if running in WoW64 — environment fingerprinting."),
    ("kernel32.dll", "SetFileTime",
     "Modifies file timestamps — timestomping to conceal malware presence."),
    ("user32.dll", "FindWindow",
     "Searches for windows by name — detecting debugger/analysis tools."),
    ("kernel32.dll", "SfcTerminateWatcherThread",
     "Disables Windows File Protection — tampering with protected files."),
    ("kernel32.dll", "GetTickCount",
     "Gets system uptime — sandbox detection (short uptime = sandbox)."),
    ("kernel32.dll", "CreateMutex",
     "Creates a named mutex — ensuring single malware instance."),
    ("kernel32.dll", "OpenMutex",
     "Opens a named mutex — checking if malware already running."),
]

# ---- Category 9: Suspicious File Operations (LOW — 2 pts) ----
_FILE_OPS: list[tuple[str, str, str]] = [
    ("kernel32.dll", "GetWindowsDirectory",
     "Gets Windows directory path — locating system files for tampering."),
    ("kernel32.dll", "GetTempPath",
     "Gets temp directory — common malware staging location."),
    ("shell32.dll", "ShellExecute",
     "Launches external programs — executing dropped payloads."),
    ("kernel32.dll", "WinExec",
     "Executes a program — legacy API, rarely used by legitimate modern software."),
    ("kernel32.dll", "DeviceIoControl",
     "Communicates with device drivers — rootkit communication channel."),
    ("kernel32.dll", "GetModuleFileName",
     "Returns filename of loaded module — self-location for copying/persistence."),
    ("ntdll.dll", "NtQueryDirectoryFile",
     "Returns directory info — rootkits hook this to hide files."),
    ("kernel32.dll", "ConnectNamedPipe",
     "Creates server pipe for IPC — reverse shell communication."),
    ("kernel32.dll", "PeekNamedPipe",
     "Reads from named pipe without removing data — reverse shell I/O."),
]



# ---- EXE-Specific APIs: elevated risk when found in a standalone executable
# bundled alongside a VST plugin. Installers and helper EXEs sitting in plugin
# directories are the primary real-world malware delivery vector.  (HIGH — 7 pts)
_EXE_SPECIFIC: list[tuple[str, str, str]] = [
    ("kernel32.dll", "CreateProcess",
     "Spawns a child process — dropper launching a second-stage payload."),
    ("kernel32.dll", "CreateProcessInternal",
     "Internal CreateProcess variant — used to evade API hooks."),
    ("kernel32.dll", "WaitForSingleObject",
     "Waits for a process/thread — dropper waiting for payload to finish."),
    ("kernel32.dll", "MoveFileEx",
     "Moves/renames a file on reboot — persistence via MOVEFILE_DELAY_UNTIL_REBOOT."),
    ("kernel32.dll", "CopyFile",
     "Copies a file — self-replication or payload staging."),
    ("kernel32.dll", "DeleteFile",
     "Deletes a file — covering tracks after dropper completes."),
    ("advapi32.dll", "InstallHinfSection",
     "Runs an INF setup section — silent software installation."),
    ("msi.dll",      "MsiInstallProduct",
     "Silently installs an MSI package — dropper installing malware."),
    ("shell32.dll",  "SHFileOperation",
     "Performs bulk file operations (copy/move/delete) — dropper staging."),
]

def _build_api_database() -> dict[tuple[str, str], FlaggedAPI]:
    """
    Compile all Red Flag API lists into a single lookup dictionary.

    Returns:
        A dict keyed by (dll_lower, func_base_lower) -> FlaggedAPI.
        The function base name has A/W/Ex suffixes stripped for fuzzy
        matching (e.g., "InternetOpenA" -> "internetopen").
    """
    db: dict[tuple[str, str], FlaggedAPI] = {}

    categories: list[tuple[list, str, int, dict[str, int]]] = [
        (_PROCESS_INJECTION, "Process Injection", 10, _PROCESS_INJECTION_WEIGHTS),
        (_NETWORKING, "Networking / C2", 10, _NETWORKING_WEIGHTS),
        (_REGISTRY, "Registry Manipulation", 7, _REGISTRY_WEIGHTS),
        (_SERVICES, "Service Manipulation", 7, {}),
        (_PRIVILEGE, "Privilege Escalation", 7, {}),
        (_CREDENTIAL, "Credential Access", 7, _CREDENTIAL_WEIGHTS),
        (_KEYLOGGING, "Keylogging / Surveillance", 7, _KEYLOGGING_WEIGHTS),
        (_ANTI_ANALYSIS, "Anti-Analysis / Evasion", 4, {}),
        (_FILE_OPS, "Suspicious File Operations", 2, {}),
        (_EXE_SPECIFIC, "EXE / Dropper Behaviour", 7, {}),
    ]

    for api_list, category, default_weight, overrides in categories:
        for dll, func, desc in api_list:
            base = _normalize_func_name(func)
            key = (dll.lower(), base)
            weight = overrides.get(base, default_weight)
            db[key] = FlaggedAPI(
                dll=dll,
                function=func,
                category=category,
                weight=weight,
                description=desc,
            )

    return db


def _normalize_func_name(name: str) -> str:
    """
    Normalize a Windows API function name for fuzzy matching.

    Many Windows APIs exist in multiple variants:
        - ANSI vs. Unicode: CreateFileA / CreateFileW
        - Extended versions: RegOpenKeyExA / RegOpenKeyExW

    This function strips common suffixes so "InternetOpenA",
    "InternetOpenW", and "InternetOpen" all map to "internetopen".

    Args:
        name: The raw function name from the PE import table.

    Returns:
        A lowercase, suffix-stripped version of the function name.
    """
    lower = name.lower().strip()

    # Strip trailing "A" or "W" (ANSI / Unicode suffix) but only if the
    # remaining base name is at least 4 chars to avoid false truncation
    # on short names like "send", "recv", "bind".
    if len(lower) > 4 and lower.endswith(("a", "w")):
        candidate = lower[:-1]
        # Only strip if it doesn't break known short names
        if candidate not in ("sen", "rec", "bin", "lis", "acce"):
            lower = candidate

    # Handle "ExA" / "ExW" -> strip "Ex" suffix as well when preceded by
    # at least 4 chars of base name.  Example: "RegOpenKeyExA" -> after
    # A-strip -> "regopenkeyex" -> strip "ex" -> "regopenkeyex".
    # We keep "ex" on since the base DB already includes the Ex variant.

    return lower


# Pre-built singleton database
_API_DB: dict[tuple[str, str], FlaggedAPI] = _build_api_database()


# ---------------------------------------------------------------------------
# Entropy Analysis Engine (YARA-Style Packing / Encryption Detection)
# ---------------------------------------------------------------------------
# Shannon entropy is calculated per PE section on a 0–8 bits-per-byte scale.
# Thresholds are derived from:
#   - Dragos YARA hunting rules (>= 7.0 suspicious, >= 7.4 high confidence)
#   - Academic research (Lyda & Hamrock, IEEE S&P 2007): packed >= 6.677 avg
#   - CAPA / Mandiant feature proposals: section entropy >= 6.8 packed
#   - Community YARA rules: math.entropy(...) >= 7 for packed detection

# Entropy thresholds (bits per byte, scale 0–8)
ENTROPY_PACKED_THRESHOLD = 7.0       # Section likely packed or compressed
ENTROPY_ENCRYPTED_THRESHOLD = 7.4    # Section likely encrypted
ENTROPY_FILE_PACKED_THRESHOLD = 6.85  # Whole-file entropy indicating packing

# Scoring weights for entropy-based detections
ENTROPY_WEIGHT_ENCRYPTED_SECTION = 8   # Per section with entropy >= 7.4
ENTROPY_WEIGHT_ENCRYPTED_RESOURCE = 3  # High entropy in .rsrc (icons/fonts), not code
ENTROPY_WEIGHT_PACKED_SECTION = 6      # Per section with entropy >= 7.0
ENTROPY_WEIGHT_RWX_SECTION = 8         # Section with Read-Write-Execute perms
ENTROPY_WEIGHT_PACKER_NAME = 8         # Known packer section name detected
ENTROPY_WEIGHT_SIZE_ANOMALY = 4        # VirtualSize >> RawSize ratio anomaly
ENTROPY_WEIGHT_SIZE_ANOMALY_DATA = 1   # Same, but only in non-exec .data (often benign)
ENTROPY_WEIGHT_FILE_ENTROPY = 5        # Whole-file entropy above threshold
ENTROPY_WEIGHT_ZERO_RAW_EXEC = 6       # Executable section with 0 raw size

# Total entropy points folded into triage (raw per-section scores may be higher).
ENTROPY_PACK_SCORE_CAP_HARD = 22       # When Process Injection APIs are present
ENTROPY_PACK_SCORE_CAP_SOFT = 14     # Typical plugins: packing without injection APIs

_VERDICT_SAFE_MAX = 10
_VERDICT_SUSPICIOUS_MAX = 35

# Per-category caps on summed import weights (reduces duplicate API inflation).
_IMPORT_CATEGORY_CAPS: dict[str, int] = {
    "Process Injection": 24,
    "Networking / C2": 18,
    "Registry Manipulation": 14,
    "Service Manipulation": 14,
    "Privilege Escalation": 14,
    "Credential Access": 12,
    "Keylogging / Surveillance": 14,
    "Anti-Analysis / Evasion": 10,
    "Suspicious File Operations": 8,
    "EXE / Dropper Behaviour": 14,
}

_HARD_SCORE_CATEGORIES: frozenset[str] = frozenset({
    "Process Injection",
    "Registry Manipulation",
    "Service Manipulation",
    "Privilege Escalation",
    "Credential Access",
    "EXE / Dropper Behaviour",
})

# Known packer / protector section names (lowercase for matching)
_KNOWN_PACKER_SECTIONS: set[str] = {
    # UPX
    "upx0", "upx1", "upx2", "upx!",
    # ASPack
    ".aspack", ".adata",
    # FSG
    ".fsg",
    # PECompact
    ".petite", "pecompact",
    # MPRESS
    ".mpress1", ".mpress2",
    # Themida / WinLicense
    ".themida", ".winlice",
    # VMProtect
    ".vmp0", ".vmp1", ".vmp2",
    # Obsidium
    ".obsidiu",
    # Enigma Protector
    ".enigma1", ".enigma2",
    # NSPack
    ".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1",
    # tElock
    ".telock",
    # PESpin
    ".pespin",
    # yoda's Protector
    ".yp",
    # Generic suspicious names
    ".packed", ".encrypt", ".crypt",
}

# Standard PE section names that are expected in legitimate binaries
_STANDARD_SECTIONS: set[str] = {
    ".text", ".code", ".rdata", ".data", ".bss", ".idata", ".edata",
    ".rsrc", ".reloc", ".tls", ".pdata", ".debug", ".didat",
    ".crt", ".xdata", ".voltbl", ".gfids", ".00cfg", ".retplne",
}


@dataclass
class SectionEntropy:
    """Entropy analysis result for a single PE section."""
    name: str                   # Section name (e.g., ".text")
    virtual_size: int = 0       # Virtual (in-memory) size
    raw_size: int = 0           # Raw (on-disk) size
    entropy: float = 0.0        # Shannon entropy (0–8 bits/byte)
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = False
    flags: list[str] = field(default_factory=list)  # Human-readable flags
    alerts: list[str] = field(default_factory=list)  # Specific risk alerts
    score_contribution: int = 0  # Points added to risk score


@dataclass
class EntropyAnalysis:
    """Complete entropy analysis for a PE file."""
    file_entropy: float = 0.0           # Whole-file Shannon entropy
    section_count: int = 0
    sections: list[SectionEntropy] = field(default_factory=list)
    high_entropy_sections: int = 0      # Sections >= 7.0
    encrypted_sections: int = 0         # Sections >= 7.4
    rwx_sections: int = 0               # Sections with RWX permissions
    packer_sections: int = 0            # Known packer section names
    total_entropy_score: int = 0        # Cumulative score from entropy checks
    is_likely_packed: bool = False      # Overall packing assessment
    packing_indicators: list[str] = field(default_factory=list)


def _calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    This implements the standard information entropy formula:
        H = -SUM(p(x) * log2(p(x))) for each unique byte value x

    The result is on a 0–8 bits-per-byte scale:
        0.0 = completely uniform (e.g., all zeros)
        8.0 = perfectly random (e.g., encrypted data)

    Typical ranges:
        Plain text / strings:   1.0 – 4.0
        Compiled code (.text):  4.5 – 6.5
        Compressed data:        6.8 – 7.4
        Encrypted data:         7.4 – 8.0

    Args:
        data: Raw bytes to analyze.

    Returns:
        Shannon entropy as a float (0.0 – 8.0).
        Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    length = len(data)
    # Count occurrences of each byte value (0x00 – 0xFF)
    byte_counts = collections.Counter(data)

    entropy = 0.0
    for count in byte_counts.values():
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _analyze_section_entropy(pe: pefile.PE, pe_data: bytes) -> EntropyAnalysis:
    """
    Perform YARA-style entropy analysis on all PE sections.

    This function examines each section for:
        1. High Shannon entropy (>= 7.0 packed, >= 7.4 encrypted)
        2. Known packer section names (UPX, ASPack, VMProtect, etc.)
        3. RWX (Read-Write-Execute) permissions — common in packed code
        4. VirtualSize >> RawSize anomalies — unpacking stubs
        5. Executable sections with zero raw data size

    It also calculates whole-file entropy to detect globally packed binaries
    (threshold >= 6.85, per Lyda & Hamrock research).

    Args:
        pe: A parsed pefile.PE object.
        pe_data: Raw bytes of the entire PE file.

    Returns:
        An EntropyAnalysis dataclass with all findings.
    """
    result = EntropyAnalysis()

    # --- Whole-file entropy ---
    result.file_entropy = _calculate_shannon_entropy(pe_data)

    if not hasattr(pe, "sections") or not pe.sections:
        return result

    result.section_count = len(pe.sections)
    total_score = 0

    for section in pe.sections:
        # Decode section name (strip null bytes)
        try:
            sec_name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            sec_name = "<unknown>"

        sec_name_lower = sec_name.lower().strip()

        # Extract section characteristics
        chars = section.Characteristics
        is_exec = bool(chars & 0x20000000)   # IMAGE_SCN_MEM_EXECUTE
        is_write = bool(chars & 0x80000000)  # IMAGE_SCN_MEM_WRITE
        is_read = bool(chars & 0x40000000)   # IMAGE_SCN_MEM_READ

        # Compute section entropy from raw data
        raw_offset = section.PointerToRawData
        raw_size = section.SizeOfRawData
        virtual_size = section.Misc_VirtualSize

        if raw_size > 0 and raw_offset + raw_size <= len(pe_data):
            section_data = pe_data[raw_offset:raw_offset + raw_size]
            sec_entropy = _calculate_shannon_entropy(section_data)
        else:
            section_data = b""
            sec_entropy = 0.0

        # Build human-readable permission flags
        flags = []
        if is_read:
            flags.append("R")
        if is_write:
            flags.append("W")
        if is_exec:
            flags.append("X")

        sec_result = SectionEntropy(
            name=sec_name,
            virtual_size=virtual_size,
            raw_size=raw_size,
            entropy=round(sec_entropy, 4),
            is_executable=is_exec,
            is_writable=is_write,
            is_readable=is_read,
            flags=flags,
        )

        # --- Check 1: High entropy (packed / encrypted) ---
        if sec_entropy >= ENTROPY_ENCRYPTED_THRESHOLD:
            sec_result.alerts.append(
                f"ENCRYPTED: Entropy {sec_entropy:.2f} >= {ENTROPY_ENCRYPTED_THRESHOLD} "
                f"(near-random data, likely encrypted or heavily packed)"
            )
            if sec_name_lower == ".rsrc":
                w = ENTROPY_WEIGHT_ENCRYPTED_RESOURCE
                sec_result.alerts.append(
                    "NOTE: High entropy in .rsrc is common (compressed icons/fonts)."
                )
            else:
                w = ENTROPY_WEIGHT_ENCRYPTED_SECTION
            sec_result.score_contribution += w
            result.encrypted_sections += 1
            result.high_entropy_sections += 1
        elif sec_entropy >= ENTROPY_PACKED_THRESHOLD:
            sec_result.alerts.append(
                f"PACKED: Entropy {sec_entropy:.2f} >= {ENTROPY_PACKED_THRESHOLD} "
                f"(likely compressed or packed)"
            )
            sec_result.score_contribution += ENTROPY_WEIGHT_PACKED_SECTION
            result.high_entropy_sections += 1

        # --- Check 2: RWX permissions (Read + Write + Execute) ---
        if is_exec and is_write:
            sec_result.alerts.append(
                "RWX: Section is both WRITABLE and EXECUTABLE — "
                "common in packed/self-modifying code, rare in legitimate DLLs."
            )
            sec_result.score_contribution += ENTROPY_WEIGHT_RWX_SECTION
            result.rwx_sections += 1

        # --- Check 3: Known packer section name ---
        if sec_name_lower in _KNOWN_PACKER_SECTIONS:
            sec_result.alerts.append(
                f"PACKER: Section name '{sec_name}' matches known packer signature "
                f"(UPX, ASPack, VMProtect, Themida, etc.)"
            )
            sec_result.score_contribution += ENTROPY_WEIGHT_PACKER_NAME
            result.packer_sections += 1

        # --- Check 4: VirtualSize >> RawSize anomaly ---
        # When virtual size is much larger than raw size, it suggests the
        # section will be unpacked/inflated in memory — classic packer behavior.
        if raw_size > 0 and virtual_size > raw_size * 3 and virtual_size > 0x1000:
            ratio = virtual_size / raw_size
            sec_result.alerts.append(
                f"SIZE ANOMALY: VirtualSize ({virtual_size:,}) is "
                f"{ratio:.1f}x larger than RawSize ({raw_size:,}) — "
                f"suggests in-memory unpacking."
            )
            if sec_name_lower == ".data" and not is_exec:
                sec_result.score_contribution += ENTROPY_WEIGHT_SIZE_ANOMALY_DATA
                sec_result.alerts.append(
                    "INFO: .data size mismatch alone is often benign (BSS-style padding)."
                )
            else:
                sec_result.score_contribution += ENTROPY_WEIGHT_SIZE_ANOMALY

        # --- Check 5: Executable section with zero raw size ---
        # An executable section with no on-disk data but nonzero virtual size
        # is a hallmark of packers (the unpacker fills it at runtime).
        if is_exec and raw_size == 0 and virtual_size > 0:
            sec_result.alerts.append(
                f"HOLLOW: Executable section with 0 bytes on disk but "
                f"{virtual_size:,} bytes allocated in memory — "
                f"unpacker will fill at runtime."
            )
            sec_result.score_contribution += ENTROPY_WEIGHT_ZERO_RAW_EXEC

        # --- Check 6: Non-standard section name (informational) ---
        if (sec_name_lower not in _STANDARD_SECTIONS
                and sec_name_lower not in _KNOWN_PACKER_SECTIONS
                and len(sec_name_lower) > 0):
            # Only flag as informational, no score impact
            sec_result.alerts.append(
                f"INFO: Non-standard section name '{sec_name}' — "
                f"may be custom or from a non-standard toolchain."
            )

        total_score += sec_result.score_contribution
        result.sections.append(sec_result)

    # --- Whole-file entropy check ---
    if result.file_entropy >= ENTROPY_FILE_PACKED_THRESHOLD:
        total_score += ENTROPY_WEIGHT_FILE_ENTROPY
        result.packing_indicators.append(
            f"Whole-file entropy {result.file_entropy:.2f} >= "
            f"{ENTROPY_FILE_PACKED_THRESHOLD} (file-level packing indicator)"
        )

    result.total_entropy_score = total_score

    # --- Overall packing assessment ---
    # A file is "likely packed" if any of these are true:
    packing_signals = (
        result.encrypted_sections > 0,
        result.high_entropy_sections >= 2,
        result.packer_sections > 0,
        result.rwx_sections > 0 and result.high_entropy_sections > 0,
        result.file_entropy >= ENTROPY_FILE_PACKED_THRESHOLD,
    )
    result.is_likely_packed = any(packing_signals)

    # Compile human-readable packing indicator summary
    if result.high_entropy_sections > 0:
        result.packing_indicators.append(
            f"{result.high_entropy_sections} section(s) with high entropy (>= 7.0)"
        )
    if result.encrypted_sections > 0:
        result.packing_indicators.append(
            f"{result.encrypted_sections} section(s) with near-random entropy (>= 7.4)"
        )
    if result.rwx_sections > 0:
        result.packing_indicators.append(
            f"{result.rwx_sections} section(s) with RWX (writable + executable) permissions"
        )
    if result.packer_sections > 0:
        result.packing_indicators.append(
            f"{result.packer_sections} section(s) with known packer names"
        )

    return result


# ---------------------------------------------------------------------------
# PE Analysis Functions
# ---------------------------------------------------------------------------

@dataclass
class ImportEntry:
    """A single imported function extracted from the PE IAT."""
    dll: str
    function: str
    flagged: bool = False
    flag_info: FlaggedAPI | None = None


@dataclass
class SignatureInfo:
    """Digital signature status of a PE file."""
    has_signature: bool = False
    is_valid: bool | None = None  # None = could not verify
    signer: str = "Unknown"
    status_message: str = "No signature data found."


@dataclass
class AnalysisResult:
    """Complete result of a VST-Sentry file analysis."""
    file_path: str = ""
    file_name: str = ""
    file_size_bytes: int = 0
    md5: str = ""
    sha256: str = ""
    pe_type: str = ""                       # DLL, EXE, or UNKNOWN
    architecture: str = ""                  # x86, x64, or UNKNOWN
    compile_timestamp: str = ""
    total_imports: int = 0
    flagged_imports: list[dict[str, Any]] = field(default_factory=list)
    flagged_count: int = 0
    categories_hit: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0
    hard_score: int = 0
    weak_score: int = 0
    verdict: str = "Safe"                   # Safe, Suspicious, High Risk
    signature: dict[str, Any] = field(default_factory=dict)
    entropy_analysis: dict[str, Any] = field(default_factory=dict)
    vt_lookup: dict[str, Any] = field(default_factory=dict)
    vt_behaviours: dict[str, Any] = field(default_factory=dict)
    analysis_timestamp: str = ""
    warnings: list[str] = field(default_factory=list)
    all_imports: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to a plain dictionary for JSON export."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize the result to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


def _compute_hashes(file_path: str) -> tuple[str, str]:
    """
    Compute MD5 and SHA-256 hashes of a file.

    Args:
        file_path: Absolute path to the file.

    Returns:
        Tuple of (md5_hex, sha256_hex).
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as fh:
        while chunk := fh.read(65536):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def _check_signature_pefile(pe: pefile.PE) -> SignatureInfo:
    """
    Check for the presence of a digital signature using pefile.

    This checks the PE's Security Directory (IMAGE_DIRECTORY_ENTRY_SECURITY)
    to determine if an Authenticode signature is embedded. Full cryptographic
    verification requires platform-specific tools (sigcheck on Windows).

    Args:
        pe: A parsed pefile.PE object.

    Returns:
        A SignatureInfo dataclass with the findings.
    """
    sig_info = SignatureInfo()

    # The Security Directory is at index 4 in the Data Directory array.
    security_dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]

    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_index]

        if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
            sig_info.has_signature = True
            sig_info.status_message = (
                "Authenticode signature is PRESENT in the PE file. "
                "Full cryptographic verification requires Windows sigcheck."
            )

            # Attempt to read the WIN_CERTIFICATE structure
            # to extract basic signer info.
            try:
                sig_offset = security_dir.VirtualAddress
                sig_size = security_dir.Size
                pe_data = pe.__data__

                if sig_offset + sig_size <= len(pe_data):
                    # WIN_CERTIFICATE header: dwLength (4), wRevision (2),
                    # wCertificateType (2), then bCertificate (PKCS#7 blob).
                    cert_data = pe_data[sig_offset:sig_offset + sig_size]
                    if len(cert_data) >= 8:
                        dw_length, w_revision, w_cert_type = struct.unpack(
                            "<IHH", cert_data[:8]
                        )
                        sig_info.status_message = (
                            f"Authenticode signature PRESENT "
                            f"(Revision: 0x{w_revision:04X}, "
                            f"Type: 0x{w_cert_type:04X}, "
                            f"Size: {dw_length} bytes). "
                            f"Run sigcheck for full verification."
                        )
            except Exception:
                pass  # Non-critical; we still know the signature exists.
        else:
            sig_info.has_signature = False
            sig_info.status_message = "NO digital signature found in PE file."
    except (IndexError, AttributeError):
        sig_info.has_signature = False
        sig_info.status_message = "Could not read Security Directory from PE."

    return sig_info


def _check_signature_sigcheck(file_path: str) -> SignatureInfo | None:
    """
    Attempt to verify a PE file's digital signature using Sysinternals
    sigcheck.exe (Windows only).

    This provides full cryptographic verification including certificate
    chain validation against the Windows certificate store.

    Args:
        file_path: Absolute path to the PE file.

    Returns:
        A SignatureInfo if sigcheck is available, or None if not on Windows
        or sigcheck is not installed.
    """
    if sys.platform != "win32":
        return None

    # Try to find sigcheck in common locations
    sigcheck_paths = [
        "sigcheck64.exe",
        "sigcheck.exe",
        r"C:\Tools\sigcheck64.exe",
        r"C:\SysinternalsSuite\sigcheck64.exe",
    ]

    sigcheck_bin = None
    for path in sigcheck_paths:
        try:
            result = subprocess.run(
                [path, "-nobanner", "-accepteula", file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode is not None:
                sigcheck_bin = path
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if sigcheck_bin is None:
        return None

    sig_info = SignatureInfo()
    try:
        result = subprocess.run(
            [sigcheck_bin, "-nobanner", "-accepteula", file_path],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.lower()

        if "signed" in output and "unsigned" not in output:
            sig_info.has_signature = True
            sig_info.is_valid = True
            sig_info.status_message = "VALID — Signature verified by sigcheck."
        elif "unsigned" in output:
            sig_info.has_signature = False
            sig_info.is_valid = False
            sig_info.status_message = "UNSIGNED — No valid signature found."
        else:
            sig_info.has_signature = True
            sig_info.is_valid = False
            sig_info.status_message = (
                "INVALID — Signature present but verification failed."
            )

        # Try to extract signer name
        for line in result.stdout.splitlines():
            if "publisher" in line.lower() or "company" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    sig_info.signer = parts[1].strip()
                    break

    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as exc:
        sig_info.status_message = f"sigcheck execution failed: {exc}"

    return sig_info


def _extract_imports(pe: pefile.PE) -> list[ImportEntry]:
    """
    Extract all imported functions from the PE Import Address Table.

    Each import is cross-referenced against the Red Flag API database.
    Matching is done on (dll_name, normalized_function_name) pairs.

    Args:
        pe: A parsed pefile.PE object.

    Returns:
        A list of ImportEntry objects for every imported function.
    """
    imports: list[ImportEntry] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="replace").lower()

        for imp in entry.imports:
            if imp.name is None:
                # Ordinal-only import (no name to analyze)
                continue

            func_name = imp.name.decode("utf-8", errors="replace")
            func_base = _normalize_func_name(func_name)

            # Look up in the Red Flag database
            key = (dll_name, func_base)
            flagged_api = _API_DB.get(key)

            imports.append(ImportEntry(
                dll=dll_name,
                function=func_name,
                flagged=flagged_api is not None,
                flag_info=flagged_api,
            ))

    return imports


def _aggregate_import_scores_from_flagged_dicts(
    flagged_dicts: list[dict[str, Any]],
) -> tuple[int, int, int, dict[str, int]]:
    """
    Sum red-flag import weights with per-category caps.

    Returns:
        (capped_total_import_score, hard_subtotal, weak_subtotal, category_counts)
        category_counts = number of flagged imports per category (for UI).
    """
    weights_by_category: dict[str, list[int]] = collections.defaultdict(list)
    bases_by_category: dict[str, set[str]] = collections.defaultdict(set)

    for item in flagged_dicts:
        cat = str(item["category"])
        weights_by_category[cat].append(int(item["weight"]))
        bases_by_category[cat].add(
            _normalize_func_name(str(item.get("function", "")))
        )

    kl_bases = bases_by_category.get("Keylogging / Surveillance", set())
    hook_without_keys = (
        "setwindowshookex" in kl_bases
        and "getasynckeystate" not in kl_bases
        and "getkeystate" not in kl_bases
    )

    category_scores: dict[str, int] = {}
    for cat, weights in weights_by_category.items():
        cap = _IMPORT_CATEGORY_CAPS.get(cat, 20)
        if cat == "Keylogging / Surveillance" and hook_without_keys:
            cap = min(cap, 8)
        category_scores[cat] = min(sum(weights), cap)

    hard = sum(
        sc for c, sc in category_scores.items() if c in _HARD_SCORE_CATEGORIES
    )
    weak = sum(
        sc for c, sc in category_scores.items() if c not in _HARD_SCORE_CATEGORIES
    )
    total_import = hard + weak
    cat_counts = {cat: len(ws) for cat, ws in weights_by_category.items()}
    return total_import, hard, weak, cat_counts


def _vt_positive_detection_score(malicious: int) -> int:
    """Score bump from VT engines when malicious count is 1+."""
    if malicious <= 0:
        return 0
    if malicious <= 4:
        return min(2, malicious)
    if malicious <= 14:
        return 12
    return 22


def _vt_full_reputation_score(found: bool, malicious: int) -> int:
    """VT contribution including a small bonus when the hash is known-clean."""
    if not found:
        return 0
    if malicious == 0:
        return -2
    return _vt_positive_detection_score(malicious)


def _compute_triage_scores(
    flagged_imports: list[dict[str, Any]],
    *,
    entropy_score: int = 0,
    entropy_result: EntropyAnalysis | None = None,
    has_valid_signature: bool = True,
    vt_malicious: int = 0,
    vt_total: int = 0,
    sandbox_has_network: bool = False,
    sandbox_has_injection: bool = False,
) -> tuple[int, int, int, int, str]:
    """
    Pure scoring helper for tests and what-if analysis.

    Returns:
        (hard_score, weak_score, capped_entropy_score, modifiers, verdict)
        ``modifiers`` bundles unsigned / VT / sandbox adjustments applied
        after the entropy cap (for debugging / UI).
    """
    _ = vt_total  # reserved for richer VT ratio heuristics
    tri_import, hard, weak, _counts = _aggregate_import_scores_from_flagged_dicts(
        flagged_imports
    )
    has_injection = any(
        i.get("category") == "Process Injection" for i in flagged_imports
    )

    pack_raw = int(entropy_score)
    if not has_injection:
        pack = min(pack_raw, ENTROPY_PACK_SCORE_CAP_SOFT)
    else:
        pack = min(pack_raw, ENTROPY_PACK_SCORE_CAP_HARD)

    modifiers = 0
    if not has_valid_signature and tri_import > 0:
        modifiers += 2

    modifiers += _vt_positive_detection_score(vt_malicious)

    if sandbox_has_network:
        modifiers += 4
    if sandbox_has_injection:
        modifiers += 10

    total = tri_import + pack + modifiers

    if (
        not has_injection
        and vt_malicious < 8
        and not sandbox_has_injection
    ):
        total = min(total, _VERDICT_SUSPICIOUS_MAX)

    if vt_malicious >= 10:
        total = max(total, _VERDICT_SUSPICIOUS_MAX + 1)

    verdict = _determine_verdict(total)
    return hard, weak, pack, modifiers, verdict


def _determine_verdict(score: int) -> str:
    """
    Map a numeric risk score to a human-readable verdict.

    Thresholds:
        Safe       :  0 – 10
        Suspicious : 11 – 35
        High Risk  : 36+

    Args:
        score: The cumulative triage risk score.

    Returns:
        One of "Safe", "Suspicious", or "High Risk".
    """
    if score <= _VERDICT_SAFE_MAX:
        return "Safe"
    elif score <= _VERDICT_SUSPICIOUS_MAX:
        return "Suspicious"
    else:
        return "High Risk"


def _get_pe_metadata(pe: pefile.PE) -> tuple[str, str, str]:
    """
    Extract PE type, architecture, and compile timestamp.

    Args:
        pe: A parsed pefile.PE object.

    Returns:
        Tuple of (pe_type, architecture, compile_timestamp).
    """
    # Determine PE type (DLL vs EXE)
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)  # IMAGE_FILE_DLL
    pe_type = "DLL" if is_dll else "EXE"

    # Architecture from Machine field
    machine = pe.FILE_HEADER.Machine
    arch_map = {
        0x14C: "x86 (i386)",
        0x8664: "x64 (AMD64)",
        0x1C0: "ARM",
        0xAA64: "ARM64",
    }
    architecture = arch_map.get(machine, f"Unknown (0x{machine:04X})")

    # Compile timestamp
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp)
        )
    except (OSError, ValueError, OverflowError):
        compile_time = "Invalid or unavailable"

    return pe_type, architecture, compile_time


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_file(
    file_path: str,
    include_all_imports: bool = False,
    vt_api_key: str = "",
) -> AnalysisResult:
    """
    Perform a full VST-Sentry static analysis on a PE file.

    This is the primary entry point for the analysis engine. It:
        1. Validates the file exists and is a valid PE.
        2. Computes file hashes (MD5, SHA-256).
        3. Extracts PE metadata (type, arch, compile time).
        4. Parses the Import Address Table (IAT).
        5. Cross-references imports against 70+ Red Flag APIs.
        6. Runs entropy / packing heuristics.
        7. Checks for a digital signature.
        8. Queries VirusTotal (if API key provided) by SHA-256 hash.
        9. Computes a weighted risk score.
       10. Returns a structured AnalysisResult.

    Args:
        file_path: Absolute or relative path to a .dll, .vst3, or .exe file.
        include_all_imports: If True, include ALL imports in the result
                            (not just flagged ones). Useful for debugging.
        vt_api_key: Optional VirusTotal API key. When provided, the file's
                    SHA-256 hash is looked up against VT's database and the
                    detection count is folded into the risk score.

    Returns:
        An AnalysisResult dataclass with all findings.

    Raises:
        FileNotFoundError: If the file does not exist.
        pefile.PEFormatError: If the file is not a valid PE.
        PermissionError: If the file cannot be read.
    """
    # --- Validate input ---
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    result = AnalysisResult(
        file_path=str(path),
        file_name=path.name,
        file_size_bytes=path.stat().st_size,
        analysis_timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )

    # --- File hashes ---
    result.md5, result.sha256 = _compute_hashes(str(path))

    # --- Parse PE ---
    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError as exc:
        result.verdict = "Error"
        result.warnings.append(f"Invalid PE file: {exc}")
        return result

    # --- PE metadata ---
    result.pe_type, result.architecture, result.compile_timestamp = (
        _get_pe_metadata(pe)
    )

    # --- PE warnings from pefile ---
    if pe.get_warnings():
        for warning in pe.get_warnings():
            result.warnings.append(f"PE Warning: {warning}")

    # --- Import analysis ---
    imports = _extract_imports(pe)
    result.total_imports = len(imports)

    flagged: list[ImportEntry] = [imp for imp in imports if imp.flagged]
    result.flagged_count = len(flagged)

    categories: dict[str, int] = {}
    flagged_dicts: list[dict[str, Any]] = []

    for imp in flagged:
        assert imp.flag_info is not None
        cat = imp.flag_info.category
        categories[cat] = categories.get(cat, 0) + 1
        entry = {
            "dll": imp.dll,
            "function": imp.function,
            "category": imp.flag_info.category,
            "weight": imp.flag_info.weight,
            "description": imp.flag_info.description,
        }
        flagged_dicts.append(entry)
        result.flagged_imports.append(entry)

    import_total, hard, weak, _ = _aggregate_import_scores_from_flagged_dicts(
        flagged_dicts
    )
    result.hard_score = hard
    result.weak_score = weak

    # Include all imports if requested (for detailed reports)
    if include_all_imports:
        result.all_imports = [
            {"dll": imp.dll, "function": imp.function}
            for imp in imports
        ]

    # --- Entropy / packing analysis ---
    pe_data = pe.__data__
    entropy_result = _analyze_section_entropy(pe, pe_data)

    has_inj = categories.get("Process Injection", 0) > 0
    pack_raw = entropy_result.total_entropy_score
    if has_inj:
        pack_score = min(pack_raw, ENTROPY_PACK_SCORE_CAP_HARD)
    else:
        pack_score = min(pack_raw, ENTROPY_PACK_SCORE_CAP_SOFT)

    # Track the "Packing / Encryption" category if entropy flagged anything
    if entropy_result.total_entropy_score > 0:
        categories["Packing / Encryption"] = (
            categories.get("Packing / Encryption", 0)
            + entropy_result.high_entropy_sections
            + entropy_result.rwx_sections
            + entropy_result.packer_sections
        )
        if categories["Packing / Encryption"] == 0:
            categories["Packing / Encryption"] = 1

    result.categories_hit = categories

    # Serialize entropy analysis into the result dict
    result.entropy_analysis = {
        "file_entropy": round(entropy_result.file_entropy, 4),
        "section_count": entropy_result.section_count,
        "high_entropy_sections": entropy_result.high_entropy_sections,
        "encrypted_sections": entropy_result.encrypted_sections,
        "rwx_sections": entropy_result.rwx_sections,
        "packer_sections": entropy_result.packer_sections,
        "total_entropy_score": entropy_result.total_entropy_score,
        "is_likely_packed": entropy_result.is_likely_packed,
        "packing_indicators": entropy_result.packing_indicators,
        "sections": [
            {
                "name": s.name,
                "entropy": s.entropy,
                "raw_size": s.raw_size,
                "virtual_size": s.virtual_size,
                "flags": "".join(s.flags),
                "alerts": s.alerts,
                "score_contribution": s.score_contribution,
            }
            for s in entropy_result.sections
        ],
    }

    # Add entropy warnings to the main warnings list
    if entropy_result.is_likely_packed:
        result.warnings.append(
            f"FILE IS LIKELY PACKED/ENCRYPTED — "
            f"{'; '.join(entropy_result.packing_indicators)}"
        )

    # --- Digital signature check ---
    sig_info = _check_signature_pefile(pe)

    # Attempt sigcheck verification on Windows
    sigcheck_info = _check_signature_sigcheck(str(path))
    if sigcheck_info is not None:
        sig_info = sigcheck_info

    result.signature = {
        "has_signature": sig_info.has_signature,
        "is_valid": sig_info.is_valid,
        "signer": sig_info.signer,
        "status_message": sig_info.status_message,
    }

    total = import_total + pack_score

    # --- EXE-specific scoring adjustment (mild; avoid blanket High Risk) ---
    if (
        result.pe_type == "EXE"
        and result.flagged_count >= 2
        and import_total >= 8
    ):
        total += 3
        result.warnings.append(
            "EXE file with multiple suspicious imports detected in plugin context — "
            "audio plugins are DLLs; standalone executables in VST directories "
            "are a primary malware delivery vector."
        )

    # Unsigned PE with static flags — small bump (large penalties caused FPs).
    if not sig_info.has_signature and import_total > 0:
        total += 2
        if result.pe_type == "DLL":
            result.warnings.append(
                "Unsigned PE with suspicious imports — elevated risk score."
            )
        else:
            result.warnings.append(
                "Unsigned EXE with suspicious imports — elevated risk score."
            )

    # --- VirusTotal hash lookup (optional) ---
    vt_result = VTResult()
    if vt_api_key:
        vt_result = _vt_lookup_hash(result.sha256, vt_api_key)
        vt_contrib = _vt_full_reputation_score(vt_result.found, vt_result.malicious)
        vt_result.score_contribution = vt_contrib
        total += vt_contrib

        if vt_result.found and vt_result.malicious > 0:
            categories["VirusTotal Detections"] = vt_result.malicious
            result.categories_hit = categories

        if vt_result.found and vt_result.malicious > 0:
            result.warnings.append(
                f"VirusTotal: {vt_result.malicious}/{vt_result.total_engines} "
                f"engines flagged this file as malicious"
            )
        elif vt_result.found and vt_result.malicious == 0:
            result.warnings.append(
                f"VirusTotal: Clean — 0/{vt_result.total_engines} detections"
            )
        elif vt_result.error:
            result.warnings.append(f"VirusTotal: {vt_result.error}")

    result.vt_lookup = vt_result.to_dict()

    # --- VirusTotal sandbox behaviour lookup ---
    beh_result = VTBehaviourResult()
    fetch_beh = (
        vt_api_key
        and vt_result.found
        and (
            total >= 25
            or vt_result.malicious > 0
            or result.flagged_count > 0
        )
    )
    if fetch_beh:
        beh_result = _vt_lookup_behaviours(result.sha256, vt_api_key)

        inj_like = beh_result.has_injection_like_sandbox_process_activity
        if beh_result.has_network_activity:
            total += 4
        if inj_like:
            total += 10

        if beh_result.found:
            if beh_result.has_network_activity:
                dns_count = len(beh_result.dns_lookups)
                ip_count = len(beh_result.ip_traffic)
                http_count = len(beh_result.http_conversations)
                result.warnings.append(
                    f"Sandbox: Network activity detected — "
                    f"{dns_count} DNS, {ip_count} IP, {http_count} HTTP"
                )
            if beh_result.has_file_system_activity:
                drop_count = len(beh_result.files_dropped)
                write_count = len(beh_result.files_written)
                result.warnings.append(
                    f"Sandbox: File-system activity — "
                    f"{drop_count} dropped, {write_count} written"
                )
            if inj_like:
                cmd_count = len(beh_result.command_executions)
                proc_count = len(beh_result.processes_created)
                result.warnings.append(
                    f"Sandbox: Suspicious process activity — "
                    f"{cmd_count} commands, {proc_count} processes"
                )
            elif beh_result.has_process_activity:
                result.warnings.append(
                    "Sandbox: Process harness activity (typical for plugin load tests)."
                )
            if beh_result.has_mitre_data:
                sev_counts: dict[str, int] = {}
                for tech in beh_result.mitre_attack_techniques:
                    sev = tech.get("severity", "UNKNOWN")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                sev_parts = [
                    f"{count} {sev}" for sev, count
                    in sorted(sev_counts.items(),
                              key=lambda x: {"HIGH": 0, "MEDIUM": 1,
                                             "LOW": 2, "INFO": 3}
                              .get(x[0], 4))
                ]
                result.warnings.append(
                    f"MITRE ATT&CK: {len(beh_result.mitre_attack_techniques)} "
                    f"techniques mapped ({', '.join(sev_parts)})"
                )
        elif beh_result.error:
            result.warnings.append(
                f"Sandbox behaviour lookup: {beh_result.error}"
            )

    # --- Plugin-style cap (no injection APIs, low VT, no sandbox injection) ---
    if (
        not has_inj
        and vt_result.malicious < 8
        and not (
            beh_result.found
            and beh_result.has_injection_like_sandbox_process_activity
        )
    ):
        total = min(total, _VERDICT_SUSPICIOUS_MAX)

    if vt_result.malicious >= 10:
        total = max(total, _VERDICT_SUSPICIOUS_MAX + 1)

    total = max(0, total)
    result.risk_score = total
    result.verdict = _determine_verdict(total)

    result.vt_behaviours = beh_result.to_dict()

    # Clean up
    pe.close()

    return result


def generate_report(result: AnalysisResult) -> str:
    """
    Generate a human-readable text report from an AnalysisResult.

    This is used by the GUI to display detailed findings when a file
    is flagged as Suspicious or High Risk.

    Args:
        result: A completed AnalysisResult from analyze_file().

    Returns:
        A formatted multi-line string report.
    """
    lines: list[str] = []
    divider = "=" * 68

    lines.append(divider)
    lines.append("  VST-SENTRY ANALYSIS REPORT")
    lines.append(divider)
    lines.append("")
    lines.append(f"  File:          {result.file_name}")
    lines.append(f"  Path:          {result.file_path}")
    lines.append(f"  Size:          {result.file_size_bytes:,} bytes")
    lines.append(f"  MD5:           {result.md5}")
    lines.append(f"  SHA-256:       {result.sha256}")
    lines.append(f"  PE Type:       {result.pe_type}")
    lines.append(f"  Architecture:  {result.architecture}")
    lines.append(f"  Compiled:      {result.compile_timestamp}")
    lines.append(f"  Analyzed:      {result.analysis_timestamp}")
    lines.append("")
    lines.append(divider)
    lines.append("  DIGITAL SIGNATURE")
    lines.append(divider)
    lines.append("")

    sig = result.signature
    if sig.get("has_signature"):
        lines.append("  Status:  SIGNED")
        if sig.get("is_valid") is True:
            lines.append("  Valid:   YES")
        elif sig.get("is_valid") is False:
            lines.append("  Valid:   NO \u2014 Verification failed")
        else:
            lines.append("  Valid:   UNKNOWN \u2014 Could not verify")
        lines.append(f"  Signer:  {sig.get('signer', 'Unknown')}")
    else:
        lines.append("  Status:  UNSIGNED \u2014 No digital signature found")

    lines.append(f"  Detail:  {sig.get('status_message', 'N/A')}")
    lines.append("")
    lines.append(divider)
    lines.append("  VERDICT")
    lines.append(divider)
    lines.append("")

    # Verdict with visual indicator
    verdict_icons = {
        "Safe": "[SAFE]",
        "Suspicious": "[WARNING]",
        "High Risk": "[DANGER]",
        "Error": "[ERROR]",
    }
    icon = verdict_icons.get(result.verdict, "[?]")
    lines.append(f"  {icon}  {result.verdict.upper()}")
    lines.append(f"  Risk Score:       {result.risk_score} points")
    lines.append(f"  Total Imports:    {result.total_imports}")
    lines.append(f"  Flagged Imports:  {result.flagged_count}")
    lines.append("")

    # --- Entropy / Packing Analysis section ---
    ea = result.entropy_analysis
    if ea:
        lines.append(divider)
        lines.append("  ENTROPY / PACKING ANALYSIS")
        lines.append(divider)
        lines.append("")
        lines.append(f"  File Entropy:     {ea.get('file_entropy', 0):.4f} / 8.0000 bits/byte")
        lines.append(f"  Sections:         {ea.get('section_count', 0)}")
        lines.append(f"  Likely Packed:    {'YES' if ea.get('is_likely_packed') else 'NO'}")
        lines.append(f"  Entropy Score:    +{ea.get('total_entropy_score', 0)} points")
        lines.append("")

        # Packing indicators summary
        indicators = ea.get("packing_indicators", [])
        if indicators:
            lines.append("  Packing Indicators:")
            for ind in indicators:
                lines.append(f"    - {ind}")
            lines.append("")

        # Per-section detail table
        sections = ea.get("sections", [])
        if sections:
            lines.append(f"  {'Section':<12s} {'Entropy':>8s} {'RawSize':>10s} "
                         f"{'VirtSize':>10s} {'Flags':>6s} {'Score':>6s}")
            lines.append(f"  {'-'*12:<12s} {'-'*8:>8s} {'-'*10:>10s} "
                         f"{'-'*10:>10s} {'-'*6:>6s} {'-'*6:>6s}")
            for sec in sections:
                score_str = f"+{sec['score_contribution']}" if sec['score_contribution'] > 0 else "0"
                lines.append(
                    f"  {sec['name']:<12s} {sec['entropy']:>8.4f} "
                    f"{sec['raw_size']:>10,d} {sec['virtual_size']:>10,d} "
                    f"{sec['flags']:>6s} {score_str:>6s}"
                )
            lines.append("")

            # Detail alerts per section (only for sections with alerts)
            for sec in sections:
                risk_alerts = [a for a in sec.get("alerts", []) if not a.startswith("INFO:")]
                if risk_alerts:
                    lines.append(f"  Section '{sec['name']}' alerts:")
                    for alert in risk_alerts:
                        lines.append(f"    >> {alert}")
                    lines.append("")

    if result.categories_hit:
        lines.append(divider)
        lines.append("  RISK CATEGORIES DETECTED")
        lines.append(divider)
        lines.append("")

        for cat, count in sorted(
            result.categories_hit.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            lines.append(f"    [{count:2d} hits]  {cat}")

        lines.append("")

    if result.flagged_imports:
        lines.append(divider)
        lines.append("  FLAGGED IMPORTS (DETAILED)")
        lines.append(divider)
        lines.append("")

        for i, imp in enumerate(result.flagged_imports, 1):
            lines.append(f"  {i:3d}. {imp['dll']}!{imp['function']}")
            lines.append(f"       Category: {imp['category']} "
                         f"(+{imp['weight']} pts)")
            lines.append(f"       Risk:     {imp['description']}")
            lines.append("")

    # --- VirusTotal Section ---
    vt = result.vt_lookup
    if vt and vt.get("queried"):
        lines.append(divider)
        lines.append("  VIRUSTOTAL LOOKUP")
        lines.append(divider)
        lines.append("")

        if vt.get("error"):
            lines.append(f"  Status:      ERROR — {vt['error']}")
        elif vt.get("found"):
            det_ratio = vt.get("detection_ratio", "N/A")
            lines.append(f"  Detection:   {det_ratio} engines flagged as malicious")
            lines.append(f"  Reputation:  {vt.get('reputation', 0)}")
            lines.append(f"  Submitted:   {vt.get('times_submitted', 0)} time(s)")

            threat_label = vt.get("threat_label", "")
            if threat_label:
                lines.append(f"  Threat:      {threat_label}")

            threat_names = vt.get("threat_names", [])
            if threat_names:
                lines.append(f"  Names:       {', '.join(threat_names)}")

            score_adj = vt.get("score_contribution", 0)
            if score_adj != 0:
                sign = "+" if score_adj > 0 else ""
                lines.append(f"  Score Adj:   {sign}{score_adj} pts")

            permalink = vt.get("permalink", "")
            if permalink:
                lines.append(f"  Details:     {permalink}")
        else:
            lines.append("  Status:      Hash not found in VirusTotal database")

        lines.append("")

    # --- Sandbox Behaviour Section ---
    beh = result.vt_behaviours
    if beh and beh.get("queried") and beh.get("found"):
        lines.append(divider)
        lines.append("  SANDBOX BEHAVIOUR (VirusTotal)")
        lines.append(divider)
        lines.append("")

        # Network activity
        dns = beh.get("dns_lookups", [])
        ip_traffic = beh.get("ip_traffic", [])
        http = beh.get("http_conversations", [])
        if dns or ip_traffic or http:
            lines.append("  Network Activity:")
            for entry in dns:
                hostname = entry.get("hostname", "")
                resolved = entry.get("resolved_ips", [])
                ips_str = ", ".join(resolved) if resolved else "unresolved"
                lines.append(f"    DNS:  {hostname} -> {ips_str}")
            for entry in ip_traffic:
                dest_ip = entry.get("destination_ip", "")
                dest_port = entry.get("destination_port", 0)
                proto = entry.get("protocol", "TCP")
                lines.append(f"    IP:   {dest_ip}:{dest_port} ({proto})")
            for entry in http:
                url = entry.get("url", "")
                method = entry.get("method", "GET")
                status = entry.get("status_code", 0)
                lines.append(f"    HTTP: {method} {url} [{status}]")
            lines.append("")

        # File-system activity
        dropped = beh.get("files_dropped", [])
        written = beh.get("files_written", [])
        if dropped or written:
            lines.append("  File-System Activity:")
            for entry in dropped:
                path = entry.get("path", "")
                sha = entry.get("sha256", "")
                sha_str = f"  (SHA-256: {sha[:16]}...)" if sha else ""
                lines.append(f"    DROPPED: {path}{sha_str}")
            for path in written:
                lines.append(f"    WRITTEN: {path}")
            lines.append("")

        # Process activity
        cmds = beh.get("command_executions", [])
        procs = beh.get("processes_created", [])
        if cmds or procs:
            lines.append("  Process Activity:")
            for cmd in cmds:
                lines.append(f"    CMD:  {cmd}")
            for proc in procs:
                lines.append(f"    PROC: {proc}")
            lines.append("")

        # Persistence
        reg = beh.get("registry_keys_set", [])
        mutex = beh.get("mutexes_created", [])
        svc = beh.get("services_created", [])
        if reg or mutex or svc:
            lines.append("  Persistence / System Modification:")
            for entry in reg:
                key = entry.get("key", "")
                val = entry.get("value", "")
                lines.append(f"    REG:     {key} = {val}")
            for m in mutex:
                lines.append(f"    MUTEX:   {m}")
            for s in svc:
                lines.append(f"    SERVICE: {s}")
            lines.append("")

        # Tags
        tags = beh.get("tags", [])
        if tags:
            lines.append(f"  Behaviour Tags: {', '.join(tags)}")
            lines.append("")

        # --- MITRE ATT&CK Technique Mapping ---
        mitre_techs = beh.get("mitre_attack_techniques", [])
        if mitre_techs:
            lines.append(divider)
            lines.append("  MITRE ATT&CK MAPPING")
            lines.append(divider)
            lines.append("")

            # Group by category for structured output
            _severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "UNKNOWN": 4}
            sorted_techs = sorted(
                mitre_techs,
                key=lambda t: (_severity_order.get(t.get("severity", "UNKNOWN"), 4),
                               t.get("id", "")),
            )

            for tech in sorted_techs:
                tid = tech.get("id", "?")
                sev = tech.get("severity", "?")
                name = tech.get("name", "")
                tactic = tech.get("tactic", "")
                desc = tech.get("description", "")
                url = tech.get("url", "")

                name_str = f" {name}" if name else ""
                tactic_str = f" [{tactic}]" if tactic else ""
                lines.append(f"  [{sev:<6s}] {tid}{name_str}{tactic_str}")
                if desc:
                    lines.append(f"           {desc}")
                if url:
                    lines.append(f"           {url}")
                lines.append("")

    if result.warnings:
        lines.append(divider)
        lines.append("  WARNINGS")
        lines.append(divider)
        lines.append("")
        for warn in result.warnings:
            lines.append(f"  - {warn}")
        lines.append("")

    lines.append(divider)
    lines.append("  END OF REPORT")
    lines.append(divider)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point (for standalone testing)
# ---------------------------------------------------------------------------

def main() -> None:
    """Command-line interface for standalone analysis."""
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path_to_pe_file> [--json] [--all-imports] [--vt-key KEY]")
        print()
        print("Options:")
        print("  --json          Output results as JSON instead of text report")
        print("  --all-imports   Include all imports in output (not just flagged)")
        print("  --vt-key KEY    VirusTotal API key for hash lookup")
        sys.exit(1)

    file_path = sys.argv[1]
    output_json = "--json" in sys.argv
    all_imports = "--all-imports" in sys.argv

    # Extract VT API key if provided
    vt_key = ""
    if "--vt-key" in sys.argv:
        idx = sys.argv.index("--vt-key")
        if idx + 1 < len(sys.argv):
            vt_key = sys.argv[idx + 1]
    # Also check environment variable as fallback
    if not vt_key:
        vt_key = os.environ.get("VT_API_KEY", "")

    try:
        result = analyze_file(
            file_path,
            include_all_imports=all_imports,
            vt_api_key=vt_key,
        )
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except pefile.PEFormatError as exc:
        print(f"Error: Not a valid PE file — {exc}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as exc:
        print(f"Error: Permission denied — {exc}", file=sys.stderr)
        sys.exit(1)

    if output_json:
        print(result.to_json())
    else:
        print(generate_report(result))


if __name__ == "__main__":
    main()