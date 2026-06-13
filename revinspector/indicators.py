from __future__ import annotations

from .models import Finding, SectionInfo


NETWORK_TERMS = ("InternetOpen", "InternetOpenUrl", "URLDownloadToFile", "WinHttp", "WinInet", "socket", "connect")
PROCESS_TERMS = ("CreateProcess", "WinExec", "ShellExecute", "CreateRemoteThread", "OpenProcess")
INJECTION_TERMS = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx")
PERSISTENCE_TERMS = ("CurrentVersion\\Run", "schtasks", "LaunchAgents", "systemd", "crontab")
FILE_IO_TERMS = ("CreateFile", "WriteFile", "ReadFile", "/tmp/", "AppData")


def build_findings(
    imports: list[str],
    categorized_strings: dict[str, list[str]],
    sections: list[SectionInfo],
    file_entropy: float,
    yara_matches: list[str],
) -> list[Finding]:
    haystack = "\n".join(imports + [item for values in categorized_strings.values() for item in values])
    findings: list[Finding] = []

    if _contains_any(haystack, NETWORK_TERMS) or categorized_strings.get("urls") or categorized_strings.get("ips"):
        findings.append(Finding("capability", "network access", "medium", "Networking APIs, URLs, or IP addresses were found."))
    if _contains_any(haystack, PROCESS_TERMS) or categorized_strings.get("commands"):
        findings.append(Finding("capability", "process creation or command execution", "medium", "Process or command indicators were found."))
    if _contains_any(haystack, INJECTION_TERMS):
        findings.append(Finding("capability", "possible process injection", "high", "Memory allocation or remote thread APIs were found."))
    if _contains_any(haystack, PERSISTENCE_TERMS) or categorized_strings.get("registry_keys"):
        findings.append(Finding("persistence", "persistence-related string", "medium", "Startup or scheduled execution indicators were found."))
    if _contains_any(haystack, FILE_IO_TERMS) or categorized_strings.get("windows_paths") or categorized_strings.get("unix_paths"):
        findings.append(Finding("capability", "file I/O", "low", "File paths or file APIs were found."))

    high_entropy_sections = [section.name for section in sections if section.entropy >= 7.2 and section.size >= 512]
    if file_entropy >= 7.2 or high_entropy_sections:
        value = ", ".join(high_entropy_sections) if high_entropy_sections else "whole file"
        findings.append(Finding("packing", value, "medium", "High entropy may indicate compression, packing, or encrypted data."))

    for section in sections:
        if "execute" in section.flags and "write" in section.flags:
            findings.append(Finding("section", section.name, "medium", "Section is both writable and executable."))

    for match in yara_matches:
        findings.append(Finding("yara", match, "medium", "YARA rule matched."))

    return findings


def risk_from_findings(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    if "high" in severities:
        return "high"
    medium_count = sum(1 for finding in findings if finding.severity == "medium")
    if medium_count >= 2:
        return "high"
    if medium_count == 1:
        return "medium"
    return "low"


def summarize(findings: list[Finding]) -> str:
    capabilities = [finding.value for finding in findings if finding.category == "capability"]
    if not findings:
        return "No obvious suspicious static indicators were identified."
    if capabilities:
        return "This file appears to use " + ", ".join(capabilities) + " indicators."
    return "This file contains static indicators that may warrant manual review."


def _contains_any(value: str, terms: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(term.lower() in lowered for term in terms)
