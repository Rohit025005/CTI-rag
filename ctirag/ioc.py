"""Deterministic IOC extraction (regex). Used by Agent 1 so indicators are never invented by the LLM."""
from __future__ import annotations

import re

# Common TLDs. File-extension look-alikes (zip, mov, sh, py ...) are left out on purpose.
TLDS = set("""
com net org info biz io co me us uk de ru cn in jp fr it nl br au ca es pl ch se no fi dk be at cz gr hu ro pt ie
kr tw hk sg my id th vn ph ir tr ua by kz il ae sa za ng ke eg pk bd lk np
xyz top online site club live store tech space website fun icu cc tk ml ga cf gq pw su ws link click
cloud app dev page ai gov edu mil int example test invalid local onion
""".split())

_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}]+", re.I)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_FILE_EXT = ("exe|dll|sys|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|scr|lnk|docm|xlsm|pptm|doc|xls|iso|img|msi|"
             "jar|sh|elf|bin|zip|rar|7z|py|so")
_FILENAME = re.compile(r"(?<![\w.\\/-])[\w-]+(?:\.[\w-]+)*\.(?:%s)\b" % _FILE_EXT, re.I)
_WINPATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\\s\"'<>|*?]+\\)*[^\\\s\"'<>|*?,;]+")
_UNIXPATH = re.compile(r"(?<![\w.])/(?:tmp|etc|var|usr|opt|home|root|dev/shm)/[^\s\"'<>|;,]+")
_REGISTRY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)"
                       r"\\[^\s\"'<>|]+", re.I)

# Tools frequently abused in attacks; lines starting with them are kept as command lines.
LOLBIN_STARTS = ("powershell", "pwsh", "cmd ", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
                 "schtasks", "certutil", "bitsadmin", "wmic", "reg ", "reg.exe", "vssadmin", "bcdedit", "wevtutil",
                 "net ", "net.exe", "net1", "netsh", "msiexec", "curl ", "wget ", "chmod ", "crontab", "nohup ",
                 "bash ", "sh -c", "/bin/sh", "/bin/bash", "python ", "python3 ", "iex", "invoke-", "sc ", "sc.exe",
                 "taskkill", "whoami", "nltest", "procdump", "comsvcs", "echo ", "ssh ", "scp ", "systemctl ",
                 "start-process", "new-object")


def refang(text: str) -> str:
    text = re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", text)
    text = re.sub(r"(?i)\bfxp://", "ftp://", text)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", text, flags=re.I)
    return text.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@").replace("[/]", "/")


def _uniq(items) -> list[str]:
    seen, out = set(), []
    for item in items:
        key = item.lower()
        if item and key not in seen:
            seen.add(key)
            out.append(item)
    return out


_CRON_LINE = re.compile(r"^(?:[\d*/,-]+\s+){5}\S+")


def looks_like_command(line: str) -> bool:
    line = line.strip()
    return 6 <= len(line) <= 400 and (line.lower().startswith(LOLBIN_STARTS) or bool(_CRON_LINE.match(line)))


def extract_commands(text: str) -> list[str]:
    found = []
    for m in re.finditer(r"`([^`\n]{4,400})`", text):
        found.append(m.group(1).strip())
    for m in re.finditer(r"\"([^\"\n]{6,400})\"", text):
        if m.group(1).strip().lower().startswith(LOLBIN_STARTS):
            found.append(m.group(1).strip())
    for line in text.splitlines():
        line = line.strip().lstrip("-*•>$#").strip()
        if looks_like_command(line):
            found.append(line)
    return _uniq(found)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Return indicators grouped by type. Input may be defanged (hxxp, [.])."""
    t = refang(text)
    urls = [u.rstrip(".,;:)") for u in _URL.findall(t)]
    hashes256 = _SHA256.findall(t)
    hashes1 = _SHA1.findall(t)
    hashes5 = _MD5.findall(t)
    emails = _EMAIL.findall(t)
    filenames = [f for f in _FILENAME.findall(t)]
    file_like = {f.lower() for f in filenames}

    domains = []
    for m in _DOMAIN.finditer(t):
        dom, tld = m.group(0), m.group(1).lower()
        if tld in TLDS and dom.lower() not in file_like and not _IPV4.fullmatch(dom):
            domains.append(dom.lower())
    domains += [u.split("/")[2].split(":")[0].lower() for u in urls if len(u.split("/")) > 2]
    domains = [d for d in domains if not _IPV4.fullmatch(d)]

    return {
        "ipv4": _uniq(_IPV4.findall(t)),
        "domain": _uniq(domains),
        "url": _uniq(urls),
        "email": _uniq(emails),
        "md5": _uniq(h.lower() for h in hashes5),
        "sha1": _uniq(h.lower() for h in hashes1),
        "sha256": _uniq(h.lower() for h in hashes256),
        "cve": _uniq(c.upper() for c in _CVE.findall(t)),
        "filename": _uniq(filenames),
        "filepath": _uniq(p.rstrip(".") for p in _WINPATH.findall(t) + _UNIXPATH.findall(t)),
        "registry": _uniq(r.rstrip(".,;") for r in _REGISTRY.findall(t)),
        "command": extract_commands(t),
    }


def classify(value: str) -> str:
    """Best-effort type of a single indicator string (used to build fallback templates)."""
    v = refang(value.strip())
    if _URL.fullmatch(v):
        return "url"
    if _IPV4.fullmatch(v):
        return "ipv4"
    if _SHA256.fullmatch(v):
        return "sha256"
    if _SHA1.fullmatch(v):
        return "sha1"
    if _MD5.fullmatch(v):
        return "md5"
    if _REGISTRY.match(v):
        return "registry"
    if _WINPATH.match(v) or _UNIXPATH.match(v):
        return "filepath"
    if _FILENAME.fullmatch(v):
        return "filename"
    m = _DOMAIN.fullmatch(v)
    if m and m.group(1).lower() in TLDS:
        return "domain"
    return "other"


def count(iocs: dict) -> int:
    return sum(len(v) for k, v in iocs.items() if k != "command")
