rule Suspicious_Network_And_Process_Strings
{
  meta:
    description = "Educational static indicators for networking and process activity"
    scope = "defensive static analysis"

  strings:
    $url_http = "http://" nocase
    $url_https = "https://" nocase
    $cmd_powershell = "powershell" nocase
    $cmd_curl = "curl " nocase
    $cmd_wget = "wget " nocase
    $api_createprocess = "CreateProcess" nocase
    $api_virtualalloc = "VirtualAlloc" nocase
    $api_writeprocessmemory = "WriteProcessMemory" nocase
    $api_createremotethread = "CreateRemoteThread" nocase
    $registry_run = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase

  condition:
    any of them
}
