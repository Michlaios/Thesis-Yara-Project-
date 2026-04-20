rule Windows_Hacktool_WinPEAS_ng_413caa6b {
    meta:
        author = "Elastic Security"
        id = "413caa6b-90b7-4763-97b3-49aeb5a97cf6"
        fingerprint = "80b32022a69be8fc1d7e146c3c03623b51e2ee4206eb5f70be753477d68800d5"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, event module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Interesting Events information" ascii wide
        $win_1 = "PowerShell events" ascii wide
        $win_2 = "Created (UTC)" ascii wide
        $win_3 = "Printing Account Logon Events" ascii wide
        $win_4 = "Subject User Name" ascii wide
        $win_5 = "Target User Name" ascii wide
        $win_6 = "NTLM relay might be possible" ascii wide
        $win_7 = "You can obtain NetNTLMv2" ascii wide
        $win_8 = "The following users have authenticated" ascii wide
        $win_9 = "You must be an administrator" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_23fee092 {
    meta:
        author = "Elastic Security"
        id = "23fee092-f1ff-4d9e-9873-0a68360efb42"
        fingerprint = "4420faa4da440a9e2b1d8eadef2a1864c078fccf391ac3d7872abe1d738c926e"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, File analysis module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "File Analysis" ascii wide
        $win_1 = "apache*" ascii wide
        $win_2 = "tomcat*" ascii wide
        $win_3 = "had a timeout (ReDoS avoided but regex" ascii wide
        $win_4 = "Error looking for regex" ascii wide
        $win_5 = "Looking for secrets inside" ascii wide
        $win_6 = "files with ext" ascii wide
        $win_7 = "(limited to" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_861d3264 {
    meta:
        author = "Elastic Security"
        id = "861d3264-34c3-4ff0-bdd3-44cb5ecce2c8"
        fingerprint = "03803621b6c9856443809889a14f1d2fa217812007878dd6cf9c3dc9e5f78f65"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, File Info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "ConsoleHost_history.txt" ascii wide
        $win_1 = "Interesting files and registry" ascii wide
        $win_2 = "Cloud Credentials" ascii wide
        $win_3 = "Accessed:{2} -- Size:{3}" ascii wide
        $win_4 = "Unattend Files" ascii wide
        $win_5 = "Looking for common SAM" ascii wide
        $win_6 = "Found installed WSL distribution" ascii wide
        $win_7 = "Check skipped, if you want to run it" ascii wide
        $win_8 = "Cached GPP Passwords" ascii wide
        $win_9 = "[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[pP][aA][sS][sS][wW][oO]" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_cae025b1 {
    meta:
        author = "Elastic Security"
        id = "cae025b1-bc2a-4eea-a1c1-c82d6e4fd71f"
        fingerprint = "3e407824b258ef66ac6883d4c5dd3efeb0f744f8f64b099313cf83e96f9e968a"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, Process info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Processes Information" ascii wide
        $win_1 = "Interesting Processes -non Microsoft-" ascii wide
        $win_2 = "Permissions:.*" ascii wide
        $win_3 = "Possible DLL Hijacking.*" ascii wide
        $win_4 = "ExecutablePath" ascii wide
        $win_5 = "Vulnerable Leaked Handlers" ascii wide
        $win_6 = "Possible DLL Hijacking folder:" ascii wide
        $win_7 = "Command Line:" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_4db2c852 {
    meta:
        author = "Elastic Security"
        id = "4db2c852-6c03-4672-9250-f80671b93e1b"
        fingerprint = "f05862b7b74cb4741aa953d725336005cdb9b1d50a92ce8bb295114e27f81b2a"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, System info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "No prompting|PromptForNonWindowsBinaries" ascii wide
        $win_1 = "System Information" ascii wide
        $win_2 = "Showing All Microsoft Updates" ascii wide
        $win_3 = "GetTotalHistoryCount" ascii wide
        $win_4 = "PS history size:" ascii wide
        $win_5 = "powershell_transcript*" ascii wide
        $win_6 = "Check what is being logged" ascii wide
        $win_7 = "WEF Settings" ascii wide
        $win_8 = "CredentialGuard is active" ascii wide
        $win_9 = "cachedlogonscount is" ascii wide
    condition:
        5 of them
}