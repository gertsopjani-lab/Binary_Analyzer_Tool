"""Import behavior scoring and clustering.

This is deterministic scoring used for triage and confidence boosting.
"""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_SUSPICIOUS_IMPORTS: dict[str, int] = {
    # process injection / memory
    "VirtualAlloc": 5,
    "VirtualProtect": 6,
    "WriteProcessMemory": 9,
    "CreateRemoteThread": 10,
    "QueueUserAPC": 8,
    "NtWriteVirtualMemory": 9,
    "NtProtectVirtualMemory": 7,
    "RtlDecompressBuffer": 5,
    # dynamic loading / resolving
    "LoadLibraryA": 3,
    "LoadLibraryW": 3,
    "GetProcAddress": 4,
    "LdrLoadDll": 4,
    # execution
    "WinExec": 5,
    "ShellExecuteA": 5,
    "ShellExecuteW": 5,
    "CreateProcessA": 6,
    "CreateProcessW": 6,
    # anti-debugging
    "IsDebuggerPresent": 4,
    "CheckRemoteDebuggerPresent": 4,
    "NtQueryInformationProcess": 4,
    # networking
    "InternetOpenA": 3,
    "InternetOpenW": 3,
    "WinHttpOpen": 3,
    "WinHttpConnect": 4,
    "WSAStartup": 3,
    "socket": 3,
    "connect": 4,
    "send": 3,
    "recv": 3,
    # crypto
    "CryptEncrypt": 4,
    "CryptDecrypt": 4,
    "BCryptEncrypt": 4,
    "BCryptDecrypt": 4,
}


@dataclass(frozen=True)
class ImportScore:
    score: int
    hits: dict[str, int]
    clusters: dict[str, list[str]]


class ImportEngine:
    def __init__(self, weights: dict[str, int] | None = None):
        self.weights = weights or DEFAULT_SUSPICIOUS_IMPORTS

    def score_imports(self, imports: list[str]) -> ImportScore:
        hits: dict[str, int] = {}
        total = 0
        lower_map = {name.lower(): name for name in imports or []}
        for api, weight in self.weights.items():
            if api.lower() in lower_map:
                hits[lower_map[api.lower()]] = int(weight)
                total += int(weight)

        clusters: dict[str, list[str]] = {
            "process_injection": [],
            "dynamic_loading": [],
            "execution": [],
            "anti_debug": [],
            "networking": [],
            "crypto": [],
        }
        for name in hits:
            n = name.lower()
            if any(k in n for k in ("writeprocessmemory", "createremotethread", "queueuserapc", "virtualprotect", "virtualalloc", "ntwrite", "ntprotect")):
                clusters["process_injection"].append(name)
            elif any(k in n for k in ("loadlibrary", "getprocaddress", "ldrloaddll")):
                clusters["dynamic_loading"].append(name)
            elif any(k in n for k in ("winexec", "shellexecute", "createprocess")):
                clusters["execution"].append(name)
            elif "debug" in n or "ntqueryinformationprocess" in n:
                clusters["anti_debug"].append(name)
            elif any(k in n for k in ("winhttp", "internet", "socket", "connect", "recv", "send", "wsastartup")):
                clusters["networking"].append(name)
            elif "crypt" in n or "bcrypt" in n:
                clusters["crypto"].append(name)

        # drop empties
        clusters = {k: v for k, v in clusters.items() if v}
        return ImportScore(score=total, hits=hits, clusters=clusters)

