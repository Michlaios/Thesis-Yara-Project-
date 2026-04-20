rule Windows_Trojan_Trickbot_01365e46 {
    meta:
        author = "Elastic Security"
        id = "01365e46-c769-4c6e-913a-4d1e42948af2"
        fingerprint = "98505c3418945c10bf4f50a183aa49bdbc7c1c306e98132ae3d0fc36e216f191"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "5c450d4be39caef1d9ec943f5dfeb6517047175fec166a52970c08cd1558e172"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B 43 28 4C 8B 53 18 4C 8B 5B 10 4C 8B 03 4C 8B 4B 08 89 44 24 38 48 89 4C 24 30 4C }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_06fd4ac4 {
    meta:
        author = "Elastic Security"
        id = "06fd4ac4-1155-4068-ae63-4d83db2bd942"
        fingerprint = "ece49004ed1d27ef92b3b1ec040d06e90687d4ac5a89451e2ae487d92cb24ddd"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        description = "Identifies Trickbot unpacker"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5F 33 C0 68 ?? ?? 00 00 59 50 E2 FD 8B C7 57 8B EC 05 ?? ?? ?? 00 89 45 04 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_ce4305d1 {
    meta:
        author = "Elastic Security"
        id = "ce4305d1-8a6f-4797-afaf-57e88f3d38e6"
        fingerprint = "ae606e758b02ccf2a9a313aebb10773961121f79a94c447e745289ee045cf4ee"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { F9 8B 45 F4 89 5D E4 85 D2 74 39 83 C0 02 03 C6 89 45 F4 8B }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_1e56fad7 {
    meta:
        author = "Elastic Security"
        id = "1e56fad7-383f-4ee0-9f8f-a0b3dcceb691"
        fingerprint = "a0916134f47df384bbdacff994970f60d3613baa03c0a581b7d1dd476af3121b"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5B C9 C2 18 00 43 C1 02 10 7C C2 02 10 54 C1 02 10 67 C1 02 10 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_93c9a2a4 {
    meta:
        author = "Elastic Security"
        id = "93c9a2a4-a07a-4ed4-a899-b160d235bf50"
        fingerprint = "0ff82bf9e70304868ff033f0d96e2a140af6e40c09045d12499447ffb94ab838"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 6A 01 8B CF FF 50 5C 8B 4F 58 49 89 4F 64 8B 4D F4 8B 45 E4 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_5340afa3 {
    meta:
        author = "Elastic Security"
        id = "5340afa3-ff90-4f61-a1ac-aba1f32dd375"
        fingerprint = "7da4726ccda6a76d2da773d41f012763802d586f64a313c1c37733905ae9da81"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { E8 0C 89 5D F4 0F B7 DB 03 5D 08 66 83 F8 03 75 0A 8B 45 14 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_e7932501 {
    meta:
        author = "Elastic Security"
        id = "e7932501-66bf-4713-b10e-bcda29f4b901"
        fingerprint = "ae31b49266386a6cf42289a08da4a20fc1330096be1dae793de7b7230225bfc7"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 0C 01 00 00 00 85 C0 7C 2F 3B 46 24 7D 2A 8B 4E 20 8D 04 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_cd0868d5 {
    meta:
        author = "Elastic Security"
        id = "cd0868d5-42d8-437f-8c1a-303526c08442"
        fingerprint = "2f777285a90fce20cd4eab203f3ec7ed1c62e09fc2dfdce09b57e0802f49628f"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8D 1C 01 89 54 24 10 8B 54 24 1C 33 C9 66 8B 0B 8D 3C 8A 8B 4C }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_515504e2 {
    meta:
        author = "Elastic Security"
        id = "515504e2-6b7f-4398-b89b-3af2b46c78a7"
        fingerprint = "8eb741e1b3bd760e2cf511ad6609ac6f1f510958a05fb093eae26462f16ee1d0"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 6A 00 6A 00 8D 4D E0 51 FF D6 85 C0 74 29 83 F8 FF 74 0C 8D }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_a0fc8f35 {
    meta:
        author = "Elastic Security"
        id = "a0fc8f35-cbeb-43a8-b00d-7a0f981e84e4"
        fingerprint = "033ff4f47fece45dfa7e3ba185df84a767691e56f0081f4ed96f9e2455a563cb"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 18 33 DB 53 6A 01 53 53 8D 4C 24 34 51 8B F0 89 5C 24 38 FF D7 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_cb95dc06 {
    meta:
        author = "Elastic Security"
        id = "cb95dc06-6383-4487-bf10-7fd68d61e37a"
        fingerprint = "0d28f570db007a1b91fe48aba18be7541531cceb7f11a6a4471e92abd55b3b90"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 08 5F 5E 33 C0 5B 5D C3 8B 55 14 89 02 8B 45 18 5F 89 30 B9 01 00 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_9d4d3fa4 {
    meta:
        author = "Elastic Security"
        id = "9d4d3fa4-4e37-40d7-8399-a49130b7ef49"
        fingerprint = "b06c3c7ba1f5823ce381971ed29554e5ddbe327b197de312738165ee8bf6e194"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 89 44 24 18 33 C9 89 44 24 1C 8D 54 24 38 89 44 24 20 33 F6 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_34f00046 {
    meta:
        author = "Elastic Security"
        id = "34f00046-8938-4103-91ec-4a745a627d4a"
        fingerprint = "5c6f11e2a040ae32336f4b4c4717e0f10c73359899302b77e1803f3a609309c0"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 30 FF FF FF 03 08 8B 95 30 FF FF FF 2B D1 89 95 30 FF FF FF }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_f2a18b09 {
    meta:
        author = "Elastic Security"
        id = "f2a18b09-f7b3-4d1a-87ab-3018f520b69c"
        fingerprint = "3e4474205efe22ea0185c49052e259bc08de8da7c924372f6eb984ae36b91a1c"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 04 39 45 08 75 08 8B 4D F8 8B 41 18 EB 0F 8B 55 F8 8B 02 89 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_d916ae65 {
    meta:
        author = "Elastic Security"
        id = "d916ae65-c97b-495c-89c2-4f1ec90081d2"
        fingerprint = "2e109ed59a1e759ef089e04c21016482bf70228da30d8b350fc370b4e4d120e0"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5F 24 01 10 CF 22 01 10 EC 22 01 10 38 23 01 10 79 23 01 10 82 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_52722678 {
    meta:
        author = "Elastic Security"
        id = "52722678-afbe-43ec-a39b-6848b7d49488"
        fingerprint = "e67dda5227be74424656957843777ea533b6800576fd85f978fd8fb50504209c"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 2B 5D 0C 89 5D EC EB 03 8B 5D EC 8A 1C 3B 84 DB 74 0D 38 1F }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_28a60148 {
    meta:
        author = "Elastic Security"
        id = "28a60148-2efb-4cd2-ada1-dd2ae2699adf"
        fingerprint = "c857aa792ef247bfcf81e75fb696498b1ba25c09fc04049223a6dfc09cc064b1"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C0 31 E8 83 7D 0C 00 89 44 24 38 0F 29 44 24 20 0F 29 44 24 10 0F 29 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_997b25a0 {
    meta:
        author = "Elastic Security"
        id = "997b25a0-aeac-4f74-aa87-232c4f8329b6"
        fingerprint = "0bba1c5284ed0548f51fdfd6fb96e24f92f7f4132caefbf0704efb0b1a64b7c4"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 85 D2 74 F0 C6 45 E1 20 8D 4D E1 C6 45 E2 4A C6 45 E3 4A C6 45 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_b17b33a1 {
    meta:
        author = "Elastic Security"
        id = "b17b33a1-1021-4980-8ffd-2e7aa4ca2ae4"
        fingerprint = "753d15c1ff0cc4cf75250761360bb35280ff0a1a4d34320df354e0329dd35211"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 08 53 55 56 57 64 A1 30 00 00 00 89 44 24 10 8B 44 24 10 8B }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_2d89e9cd {
    meta:
        author = "Elastic Security"
        id = "2d89e9cd-2941-4b20-ab4e-a487d329ff76"
        fingerprint = "e6eea38858cfbbe5441b1f69c5029ff9279e7affa51615f6c91981fe656294fc"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets tabDll64.dll module containing functionality using SMB for lateral movement"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "3963649ebfabe8f6277190be4300ecdb68d4b497ac5f81f38231d3e6c862a0a8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" ascii fullword
        $a2 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" ascii fullword
        $a3 = "%SystemRoot%\\system32\\stsvc.exe" ascii fullword
        $a4 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p" ascii fullword
        $a5 = "DLL and target process must be same architecture" ascii fullword
        $a6 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" ascii fullword
        $a7 = "%SystemDrive%\\stsvc.exe" ascii fullword
        $a8 = "Wrote shellcode to 0x%x" ascii fullword
        $a9 = "ERROR: %d, line - %d" wide fullword
        $a10 = "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08p" ascii fullword
        $a11 = "GetProcessPEB:EXCEPT" wide fullword
        $a12 = "Checked count - %i, connected count %i" wide fullword
        $a13 = "C:\\%s\\%s C:\\%s\\%s" ascii fullword
        $a14 = "C:\\%s\\%s" ascii fullword
        $a15 = "%s\\ADMIN$\\stsvc.exe" wide fullword
        $a16 = "%s\\C$\\stsvc.exe" wide fullword
        $a17 = "Size - %d kB" ascii fullword
        $a18 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
        $a19 = "%s - FAIL" wide fullword
        $a20 = "%s - SUCCESS" wide fullword
        $a21 = "CmainSpreader::init() CreateEvent, error code %i" wide fullword
        $a22 = "Incorrect ModuleHandle %i, expect %i" wide fullword
        $a23 = "My interface is \"%i.%i.%i.%i\", mask \"%i.%i.%i.%i\"" wide fullword
        $a24 = "WormShare" ascii fullword
        $a25 = "ModuleHandle 0x%08X, call Control: error create thread %i" wide fullword
        $a26 = "Enter to Control: moduleHandle 0x%08X, unknown Ctl = \"%S\"" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_9c0fa8fe {
    meta:
        author = "Elastic Security"
        id = "9c0fa8fe-8d5f-4581-87a0-92a4ed1b32b3"
        fingerprint = "bd49ed2ee65ff0cfa95efc9887ed24de3882c5b5740d0efc6b9690454ca3f5dc"
        creation_date = "2021-07-13"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "f528c3ea7138df7c661d88fafe56d118b6ee1d639868212378232ca09dc9bfad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 74 19 48 85 FF 74 60 8B 46 08 39 47 08 76 6A 33 ED B1 01 B0 01 }
    condition:
        all of them
}