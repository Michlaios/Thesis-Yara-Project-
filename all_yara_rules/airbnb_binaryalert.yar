rule MachO
{
    meta:
        description = "Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}

rule hacktool_macos_exploit_tpwn
{
    meta:
        description = "tpwn exploits a null pointer dereference in XNU to escalate privileges to root."
        reference = "https://www.rapid7.com/db/modules/exploit/osx/local/tpwn"
        author = "@mimeframe"
    strings:
        $a1 = "[-] Couldn't find a ROP gadget, aborting." wide ascii
        $a2 = "leaked kaslr slide," wide ascii
        $a3 = "didn't get root, but this system is vulnerable." wide ascii
        $a4 = "Escalating privileges! -qwertyoruiop" wide ascii
    condition:
        2 of ($a*)
}

rule hacktool_macos_juuso_keychaindump
{
    meta:
        description = "For reading OS X keychain passwords as root."
        reference = "https://github.com/juuso/keychaindump"
        author = "@mimeframe"
    strings:
        $a1 = "[-] Too many candidate keys to fit in memory" wide ascii
        $a2 = "[-] Could not allocate memory for key search" wide ascii
        $a3 = "[-] Too many credentials to fit in memory" wide ascii
        $a4 = "[-] The target file is not a keychain file" wide ascii
        $a5 = "[-] Could not find the securityd process" wide ascii
        $a6 = "[-] No root privileges, please run with sudo" wide ascii
    condition:
        4 of ($a*)
}

rule hacktool_macos_keylogger_roxlu_ofxkeylogger
{
    meta:
        description = "ofxKeylogger keylogger."
        reference = "https://github.com/roxlu/ofxKeylogger"
        author = "@mimeframe"
    strings:
        $a1 = "keylogger_init" wide ascii
        $a2 = "install_keylogger_hook function not found in dll." wide ascii
        $a3 = "keylogger_set_callback" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_macos_manwhoami_mmetokendecrypt
{
    meta:
        description = "This program decrypts / extracts all authorization tokens on macOS / OS X / OSX."
        reference = "https://github.com/manwhoami/MMeTokenDecrypt"
        author = "@mimeframe"
    strings:
        $a1 = "security find-generic-password -ws 'iCloud'" wide ascii
        $a2 = "ERROR getting iCloud Decryption Key" wide ascii
        $a3 = "Could not find MMeTokenFile. You can specify the file manually." wide ascii
        $a4 = "Decrypting token plist ->" wide ascii
        $a5 = "Successfully decrypted token plist!" wide ascii
    condition:
        3 of ($a*)
}

rule hacktool_macos_manwhoami_osxchromedecrypt
{
    meta:
        description = "Decrypt Google Chrome / Chromium passwords and credit cards on macOS / OS X."
        reference = "https://github.com/manwhoami/OSXChromeDecrypt"
        author = "@mimeframe"
    strings:
        $a1 = "Credit Cards for Chrome Profile" wide ascii
        $a2 = "Passwords for Chrome Profile" wide ascii
        $a3 = "Unknown Card Issuer" wide ascii
        $a4 = "ERROR getting Chrome Safe Storage Key" wide ascii
        $b1 = "select name_on_card, card_number_encrypted, expiration_month, expiration_year from credit_cards" wide ascii
        $b2 = "select username_value, password_value, origin_url, submit_element from logins" wide ascii
    condition:
        3 of ($a*) or all of ($b*)
}

rule hacktool_macos_n0fate_chainbreaker
{
    meta:
        description = "chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner."
        reference = "https://github.com/n0fate/chainbreaker"
        author = "@mimeframe"
    strings:
        $a1 = "[!] Private Key Table is not available" wide ascii
        $a2 = "[!] Public Key Table is not available" wide ascii
        $a3 = "[-] Decrypted Private Key" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_multi_ntlmrelayx
{
    meta:
        description = "https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/"
        reference = "https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py"
        author = "@mimeframe"
    strings:
        $a1 = "Started interactive SMB client shell via TCP" wide ascii
        $a2 = "Service Installed.. CONNECT!" wide ascii
        $a3 = "Done dumping SAM hashes for host:" wide ascii
        $a4 = "DA already added. Refusing to add another" wide ascii
        $a5 = "Domain info dumped into lootdir!" wide ascii
    condition:
        any of ($a*)
}

rule hacktool_multi_pyrasite_py
{
    meta:
        description = "A tool for injecting arbitrary code into running Python processes."
        reference = "https://github.com/lmacken/pyrasite"
        author = "@fusionrace"
    strings:
        $s1 = "WARNING: ptrace is disabled. Injection will not work." fullword ascii wide
        $s2 = "A payload that connects to a given host:port and receives commands" fullword ascii wide
        $s3 = "A reverse Python connection payload." fullword ascii wide
        $s4 = "pyrasite - inject code into a running python process" fullword ascii wide
        $s5 = "The ID of the process to inject code into" fullword ascii wide
        $s6 = "This file is part of pyrasite." fullword ascii wide
        $s7 = "https://github.com/lmacken/pyrasite" fullword ascii wide
        $s8 = "Setup a communication socket with the process by injecting" fullword ascii wide
        $s9 = "a reverse subshell and having it connect back to us." fullword ascii wide
        $s10 = "Write out a reverse python connection payload with a custom port" fullword ascii wide
        $s11 = "Wait for the injected payload to connect back to us" fullword ascii wide
        $s12 = "PyrasiteIPC" fullword ascii wide
        $s13 = "A reverse Python shell that behaves like Python interactive interpreter." fullword ascii wide
        $s14 = "pyrasite cannot establish reverse" fullword ascii wide
    condition:
        any of them
}

rule hacktool_windows_ncc_wmicmd : FILE {
    meta:
        description = "Command shell wrapper for WMI"
        reference = "https://github.com/nccgroup/WMIcmd"
        author = "@mimeframe"
    strings:
        $a1 = "Need to specify a username, domain and password for non local connections" wide ascii
        $a2 = "WS-Management is running on the remote host" wide ascii
        $a3 = "firewall (if enabled) allows connections" wide ascii
        $a4 = "WARNING: Didn't see stdout output finished marker - output may be truncated" wide ascii
        $a5 = "Command sleep in milliseconds - increase if getting truncated output" wide ascii
        $b1 = "0x800706BA" wide ascii
        $b2 = "NTLMDOMAIN:" wide ascii
        $b3 = "cimv2" wide ascii
    condition:
        any of ($a*) or all of ($b*)
}

rule hacktool_windows_wmi_implant
{
    meta:
        description = "A PowerShell based tool that is designed to act like a RAT"
        reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
        author = "@fusionrace"
    strings:
        $s1 = "This really isn't applicable unless you are using WMImplant interactively." fullword ascii wide
        $s2 = "What command do you want to run on the remote system? >" fullword ascii wide
        $s3 = "Do you want to [create] or [delete] a string registry value? >" fullword ascii wide
        $s4 = "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >" fullword ascii wide
        $s5 = "What is the name of the service you are targeting? >" fullword ascii wide
        $s6 = "This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine" fullword ascii wide
        $s7 = "gen_cli - Generate the CLI command to execute a command via WMImplant" fullword ascii wide
        $s8 = "exit - Exit WMImplant" fullword ascii wide
        $s9 = "Lateral Movement Facilitation" fullword ascii wide
        $s10 = "vacant_system - Determine if a user is away from the system." fullword ascii wide
        $s11 = "Please provide the ProcessID or ProcessName flag to specify the process to kill!" fullword ascii wide
    condition:
        any of them
}

rule hacktool_windows_mimikatz_errors
{
    meta:
        description = "Mimikatz credential dump tool: Error messages"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
        $s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
        $s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
        $s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide
    condition:
        all of them
}

rule hacktool_windows_mimikatz_modules
{
    meta:
        description = "Mimikatz credential dump tool: Modules"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        modified = "2023-07-26"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
    strings:
        $s1 = "mimilib" fullword ascii wide
        $s2 = "mimidrv" fullword ascii wide
        $s3 = "mimilove" fullword ascii wide

        $fp1 = "SgrmEnclave" wide
        $fp2 = "Kaspersky Lab Anti-Rootkit Monitor Driver" wide
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and /* Added by Florian Roth to avoid false positives */
        1 of ($s*) and 
        not 1 of ($fp*)
}