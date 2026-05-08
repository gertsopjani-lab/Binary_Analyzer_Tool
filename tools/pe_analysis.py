"""Windows PE static analysis helpers."""

import re


PE_DLLCHAR = {
    "HIGH_ENTROPY_VA": 0x0020,
    "DYNAMIC_BASE": 0x0040,
    "FORCE_INTEGRITY": 0x0080,
    "NX_COMPAT": 0x0100,
    "NO_SEH": 0x0400,
    "GUARD_CF": 0x4000,
}

PE_DANGEROUS = {
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "scanf",
    "sscanf",
    "wcscpy",
    "wcscat",
}

PE_REVIEW = {
    "memcpy",
    "memmove",
    "strncpy",
    "strncat",
    "snprintf",
    "printf",
    "readfile",
    "recv",
}

PE_WIN_HINTS = {"win", "flag", "shell", "backdoor", "secret", "give_shell", "spawn"}
PE_BEHAVIOR_IMPORTS = {
    "VirtualAlloc": "runtime code memory allocation",
    "VirtualProtect": "changes memory permissions",
    "WriteProcessMemory": "process memory modification",
    "CreateRemoteThread": "remote thread creation",
    "LoadLibraryA": "dynamic library loading",
    "LoadLibraryW": "dynamic library loading",
    "GetProcAddress": "dynamic API lookup",
    "IsDebuggerPresent": "anti-debugging check",
    "CheckRemoteDebuggerPresent": "anti-debugging check",
    "InternetOpenA": "network access",
    "InternetOpenW": "network access",
    "WinHttpOpen": "network access",
    "socket": "network access",
    "connect": "network access",
    "CryptDecrypt": "cryptographic operation",
    "BCryptDecrypt": "cryptographic operation",
}

PE_PATTERNS = {
    "flag_format": re.compile(r"flag\{|CTF\{|picoCTF\{", re.I),
    "shell_path": re.compile(r"/bin/sh|cmd\.exe|powershell", re.I),
    "password": re.compile(r"password|passwd|secret|key|license|serial", re.I),
    "network": re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|localhost|https?://", re.I),
}


def _decode_name(value: bytes | None) -> str:
    return value.decode(errors="ignore") if value else ""


def pe_scan(binary_path: str) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed. Run: pip install pefile"}

    try:
        pe = pefile.PE(binary_path, fast_load=False)
    except Exception as exc:
        return {"error": f"Cannot parse PE: {exc}"}

    char = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
    aslr = "enabled" if char & PE_DLLCHAR["DYNAMIC_BASE"] else "disabled"
    nx = "enabled" if char & PE_DLLCHAR["NX_COMPAT"] else "disabled"
    cfg = "enabled" if char & PE_DLLCHAR["GUARD_CF"] else "disabled"
    no_seh = bool(char & PE_DLLCHAR["NO_SEH"])

    canary = "disabled"
    if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        cookie = getattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, "SecurityCookie", 0)
        if cookie:
            canary = "enabled"

    machine = getattr(pe.FILE_HEADER, "Machine", 0)
    arch, bits = {
        0x014C: ("x86", 32),
        0x8664: ("x86_64", 64),
        0xAA64: ("arm64", 64),
        0x01C4: ("arm", 32),
    }.get(machine, ("unknown", 0))
    entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)

    dangerous_found = []
    review_found = []
    win_functions = {}
    all_imports = []
    behavioral_imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = _decode_name(entry.dll)
            for imp in entry.imports:
                fn = _decode_name(imp.name)
                if not fn:
                    continue
                all_imports.append(fn)
                normalized = fn.lower().rstrip("_")
                if normalized in PE_DANGEROUS:
                    dangerous_found.append(fn)
                if normalized in PE_REVIEW:
                    review_found.append(fn)
                if fn in PE_BEHAVIOR_IMPORTS:
                    behavioral_imports[fn] = {
                        "reason": PE_BEHAVIOR_IMPORTS[fn],
                        "dll": dll,
                        "address": hex(imp.address) if imp.address else "?",
                    }
                if any(hint in fn.lower() for hint in PE_WIN_HINTS):
                    win_functions[fn] = hex(imp.address) if imp.address else "?"

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            fn = _decode_name(exp.name)
            if fn and any(hint in fn.lower() for hint in PE_WIN_HINTS):
                win_functions[fn] = hex(exp.address + pe.OPTIONAL_HEADER.ImageBase)

    interesting = {}
    total = 0
    try:
        with open(binary_path, "rb") as f:
            raw = f.read()
        strings = re.findall(rb"[ -~]{6,}", raw)
        total = len(strings)
        for raw_string in strings:
            text = raw_string.decode(errors="ignore")
            for label, pattern in PE_PATTERNS.items():
                if pattern.search(text):
                    interesting.setdefault(label, []).append(text[:120])
    except Exception:
        pass

    sections = []
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode(errors="ignore")
        entropy = sec.get_entropy()
        executable = bool(sec.Characteristics & 0x20000000)
        writable = bool(sec.Characteristics & 0x80000000)
        sections.append(
            {
                "name": name,
                "entropy": round(entropy, 2),
                "executable": executable,
                "writable": writable,
                "note": "high entropy (packed?)" if entropy > 7.0 else "",
            }
        )

    pe.close()
    return {
        "format": "PE",
        "architecture": {"arch": arch, "bits": bits, "entry_point": entry_point},
        "protections": {
            "nx": nx,
            "pie": aslr,
            "canary": canary,
            "relro": "N/A",
            "aslr": aslr,
            "cfg": cfg,
            "seh": "disabled" if no_seh else "enabled",
            "source": "pefile",
        },
        "symbols": {
            "dangerous_functions": sorted(set(dangerous_found)),
            "review_functions": sorted(set(review_found)),
            "behavioral_imports": behavioral_imports,
            "win_functions": win_functions,
            "has_win": bool(win_functions),
            "imports": all_imports[:100],
        },
        "strings": {"total": total, "interesting": {k: v[:5] for k, v in interesting.items()}},
        "sections": sections,
    }
