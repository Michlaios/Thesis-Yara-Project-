rule Trojan_Raw_Generic_4
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "f41074be5b423afb02a74bc74222e35d"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}

rule HackTool_Win32_AndrewSpecial_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "e89efa88e3fda86be48c0cc8f2ef7230"
        rev = 4
        author = "FireEye"
    strings:
        $dump = { 6A 00 68 FF FF 1F 00 FF 15 [4] 89 45 ?? 83 [2] 00 [1-50] 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 10 68 [4] FF 15 [4] 89 45 [10-70] 6A 00 6A 00 6A 00 6A 02 8B [2-4] 5? 8B [2-4] 5? 8B [2-4] 5? E8 [4-20] FF 15 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
        $shellcode_x86_inline = { C6 45 ?? B8 C6 45 ?? 3C C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 33 C6 45 ?? C9 C6 45 ?? 8D C6 45 ?? 54 C6 45 ?? 24 C6 45 ?? 04 C6 45 ?? 64 C6 45 ?? FF C6 45 ?? 15 C6 45 ?? C0 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 00 C6 45 ?? 83 C6 45 ?? C4 C6 45 ?? 04 C6 45 ?? C2 C6 45 ?? 14 C6 45 ?? 00 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and $dump and any of ($shellcode*)
}

rule looks for the binary signature of the 'Inject' method found in the main Excavator PE."
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        rev = 4
        author = "FireEye"
    strings:
        $bytes1 = { 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 E0 48 81 EC 20 01 00 00 48 8B 05 75 BF 01 00 48 33 C4 48 89 45 10 0F 57 C0 45 33 F6 8B F1 4C 89 74 24 60 48 8D 0D 12 A1 01 00 4C 89 74 24 68 0F 11 45 A0 41 8B FE 4C 89 74 24 70 0F 11 45 B0 0F 11 45 C0 0F 11 45 D0 0F 11 45 E0 0F 11 45 F0 0F 11 45 00 FF 15 CB 1F 01 00 48 85 C0 75 1B FF 15 80 1F 01 00 8B D0 48 8D 0D DF A0 01 00 E8 1A FF FF FF 33 C0 E9 B4 02 00 00 48 8D 15 D4 A0 01 00 48 89 9C 24 30 01 00 00 48 8B C8 FF 15 4B 1F 01 00 48 8B D8 48 85 C0 75 19 FF 15 45 1F 01 00 8B D0 48 8D 0D A4 A0 01 00 E8 DF FE FF FF E9 71 02 00 00 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 45 66 66 0F 1F 84 00 00 00 00 00 48 8B 4C 24 60 FF 15 4D 1F 01 00 3B C6 74 22 48 8B 4C 24 60 48 8D 44 24 60 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 D1 EB 0A 48 8B 44 24 60 48 89 44 24 70 66 0F 6F 15 6D A0 01 00 48 8D 05 A6 C8 01 00 B9 C8 05 00 00 90 F3 0F 6F 40 F0 48 8D 40 40 66 0F 6F CA 66 0F EF C8 F3 0F 7F 48 B0 66 0F 6F CA F3 0F 6F 40 C0 66 0F EF C8 F3 0F 7F 48 C0 66 0F 6F CA F3 0F 6F 40 D0 66 0F EF C8 F3 0F 7F 48 D0 F3 0F 6F 40 E0 66 0F EF C2 F3 0F 7F 40 E0 48 83 E9 01 75 B2 FF 15 CC 1E 01 00 4C 8D 44 24 78 BA 0A 00 00 00 48 8B C8 FF 15 01 1E 01 00 85 C0 0F 84 66 01 00 00 48 8B 4C 24 78 48 8D 45 80 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 D8 1D 01 00 85 C0 0F 84 35 01 00 00 45 33 C0 4C 8D 4C 24 68 33 C9 41 8D 50 01 FF 15 5C 1E 01 00 FF 15 06 1E 01 00 4C 8B 44 24 68 33 D2 48 8B C8 FF 15 DE 1D 01 00 48 8B F8 48 85 C0 0F 84 FF 00 00 00 45 33 C0 4C 8D 4C 24 68 48 8B C8 41 8D 50 01 FF 15 25 1E 01 00 85 C0 0F 84 E2 00 00 00 4C 89 74 24 30 4C 8D 4C 24 70 4C 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 6C 1D 01 00 85 C0 0F 84 B1 00 00 00 48 8B 4D 80 48 8D 45 88 48 89 44 24 50 4C 8D 05 58 39 03 00 48 8D 45 A0 48 89 7D 08 48 89 44 24 48 45 33 C9 4C 89 74 24 40 33 D2 4C 89 74 24 38 C7 44 24 30 04 00 08 00 44 89 74 24 28 4C 89 74 24 20 FF 15 0C 1D 01 00 85 C0 74 65 48 8B 4C 24 70 8B 5D 98 FF 15 1A 1D 01 00 48 8B 4D 88 FF 15 10 1D 01 00 48 8B 4D 90 FF 15 06 1D 01 00 44 8B C3 33 D2 B9 3A 04 00 00 FF 15 4E 1D 01 00 48 8B D8 48 85 C0 74 2B 48 8B C8 E8 4E 06 00 00 48 85 C0 74 1E BA FF FF FF FF 48 8B C8 FF 15 3B 1D 01 00 48 8B CB FF 15 CA 1C 01 00 B8 01 00 00 00 EB 24 FF 15 DD 1C 01 00 8B D0 48 8D 0D 58 9E 01 00 E8 77 FC FF FF 48 85 FF 74 09 48 8B CF FF 15 A9 1C 01 00 33 C0 48 8B 9C 24 30 01 00 00 48 8B 4D 10 48 33 CC E8 03 07 00 00 4C 8D 9C 24 20 01 00 00 49 8B 73 18 49 8B 7B 20 4D 8B 73 28 49 8B E3 5D C3 }

rule APT_Loader_Win64_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "f20824fa6e5c81e3804419f108445368"
        rev = 1
        author = "FireEye"
    strings:
        $alloc_n_load = { 41 B9 40 00 00 00 41 B8 00 30 00 00 33 C9 [1-10] FF 50 [4-80] F3 A4 [30-120] 48 6B C9 28 [3-20] 48 6B C9 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Loader_Raw64_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
        rev = 1
        author = "FireEye"
    strings:
        $load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}

rule APT_Trojan_Win_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d,4e7e90c7147ee8aa01275894734f4492"
        rev = 3
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "runCommand" fullword
        $3 = "stop" fullword
        $4 = "fini" fullword
        $5 = "VirtualAllocEx" fullword
        $6 = "WriteProcessMemory" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Dropper_Win64_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_dropper.rs"
        md5 = "edcd58ba5b1b87705e95089002312281"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 8D 8D [4] E8 [4] 49 89 D0 C6 [2-6] 01 C6 [2-6] 01 [0-8] C7 44 24 ?? 0E 00 00 00 4C 8D 0D [4] 48 8D 8D [4] 48 89 C2 E8 [4] C6 [2-6] 01 C6 [2-6] 01 48 89 E9 48 8D 95 [4] E8 [4] 83 [2] 01 0F 8? [4] 48 01 F3 48 29 F7 48 [2] 08 48 89 85 [4] C6 [2-6] 01 C6 [2-6] 01 C6 [2-6] 01 48 8D 8D [4] 48 89 DA 49 89 F8 E8 }
        $sb2 = { 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 68 00 00 00 48 8B [2] 48 8D [2] 48 89 [3] 48 89 [3] 0F 11 44 24 ?? C7 44 24 ?? 08 00 00 0C C7 44 24 ?? 00 00 00 00 31 ?? 48 89 ?? 31 ?? 45 31 ?? 45 31 ?? E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule Loader_Win_Generic_20
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "5125979110847d35a338caac6bff2aa8"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Loader_Win32_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "04eb45f8546e052fe348fda2425b058c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A ?? FF 15 [4-16] 8A ?? 04 [0-16] 8B ?? 1C [0-64] 0F 10 ?? 66 0F EF C8 0F 11 [0-32] 30 [2] 8D [2] 4? 83 [2] 7? }
        $sb2 = { 8B ?? 08 [0-16] 6A 40 68 00 30 00 00 5? 6A 00 [0-32] FF 15 [4-32] 5? [0-16] E8 [4-64] C1 ?? 04 [0-32] 8A [2] 3? [2] 4? 3? ?? 24 ?? 7? }
        $sb3 = { 8B ?? 3C [0-16] 03 [1-64] 0F B? ?? 14 [0-32] 83 ?? 18 [0-32] 66 3? ?? 06 [4-32] 68 [4] 5? FF 15 [4-16] 85 C0 [2-32] 83 ?? 28 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Trojan_Win_REDFLARE_7
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "NamedPipe"
        $named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Trojan_Win_REDFLARE_8
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "PSRunner.PSRunner" fullword
        $2 = "CorBindToRuntime" fullword
        $3 = "ReportEventW" fullword
        $4 = "InvokePS" fullword wide
        $5 = "runCommand" fullword
        $6 = "initialize" fullword
        $trap = { 03 40 00 80 E8 [4] CC }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Trojan_Win_REDFLARE_4
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "LogonUserW" fullword
        $s2 = "ImpersonateLoggedOnUser" fullword
        $s3 = "runCommand" fullword
        $user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_HackTool_MSIL_TITOSPECIAL_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 5
        author = "FireEye"
    strings:
        $ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
        $ind_s1 = "NtReadVirtualMemory" fullword wide
        $ind_s2 = "WriteProcessMemory" fullword
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($ind*) and any of ($shellcode* )
}

rule Dropper_LNK_LNKSmasher_1
{
    meta:
        description = "The LNKSmasher project contains a prebuilt LNK file that has pieces added based on various configuration items. Because of this, several artifacts are present in every single LNK file generated by LNKSmasher, including the Drive Serial #, the File Droid GUID, and the GUID CLSID."
        md5 = "0a86d64c3b25aa45428e94b6e0be3e08"
        rev = 6
        author = "FireEye"
    strings:
        $drive_serial = { 12 F7 26 BE }
        $file_droid_guid = { BC 96 28 4F 0A 46 54 42 81 B8 9F 48 64 D7 E9 A5 }
        $guid_clsid = { E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D }
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        $header at 0 and all of them
}

rule APT_HackTool_MSIL_WMISPY_2
{
    meta:
        description = "wql searches"
        md5 = "3651f252d53d2f46040652788499d65a"
        rev = 4
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $str1 = "root\\cimv2" wide
        $str2 = "root\\standardcimv2" wide
        $str3 = "from MSFT_NetNeighbor" wide
        $str4 = "from Win32_NetworkLoginProfile" wide
        $str5 = "from Win32_IP4RouteTable" wide
        $str6 = "from Win32_DCOMApplication" wide
        $str7 = "from Win32_SystemDriver" wide
        $str8 = "from Win32_Share" wide
        $str9 = "from Win32_Process" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of ($str*)
}

rule APT_Loader_Win_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "ZwQueryInformationProcess" fullword
        $s2 = "WriteProcessMemory" fullword
        $s3 = "CreateProcessW" fullword
        $s4 = "WriteProcessMemory" fullword
        $s5 = "\x00Invalid NT Signature!\x00"
        $s6 = "\x00Error while creating and mapping section. NTStatus: "
        $s7 = "\x00Error no process information - NTSTATUS:"
        $s8 = "\x00Error while erasing pe header. NTStatus: "
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Loader_MSIL_WILDCHILD_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "6f04a93753ae3ae043203437832363c4"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "\x00QueueUserAPC\x00"
        $s2 = "\x00WriteProcessMemory\x00"
        $sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Loader_Win_Generic_18
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "c74ebb6c238bbfaefd5b32d2bf7c7fcc"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Loader_MSIL_TRIMBISHOP_1
{
    meta:
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}

rule CredTheft_MSIL_ADPassHunt_2
{
    meta:
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1
        author = "FireEye"
    strings:
        $pdb1 = "\\ADPassHunt\\"
        $pdb2 = "\\ADPassHunt.pdb"
        $s1 = "Usage: .\\ADPassHunt.exe"
        $s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
        $s3 = "[ADA] Searching for accounts with userpassword attribute"
        $s4 = "[GPP] Searching for passwords now"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ((@pdb2[1] < @pdb1[1] + 50) or 2 of ($s*))
}

rule APT_Loader_Win64_PGF_4
{
    meta:
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
        $sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Loader_Win32_PGF_4
{
    meta:
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "4414953fa397a41156f6fa4f9462d207"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
        $sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule HackTool_MSIL_SharPivot_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $s2 = { 73 ?? 00 00 0A 0A 06 1F ?? 1F ?? 6F ?? 00 00 0A 0B 73 ?? 00 00 0A 0C 16 13 04 2B 5E 23 [8] 06 6F ?? 00 00 0A 5A 23 [8] 58 28 ?? 00 00 0A 28 ?? 00 00 0A 28 ?? 00 00 0A }
        $s3 = "cmd_rpc" wide
        $s4 = "costura"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule based on symfunc/c02594972dbab6d489b46c5dee059e66. Identifies dllmain_hook x86 payloads."
        md5 = "4414953fa397a41156f6fa4f9462d207"
        rev = 4
        author = "FireEye"
    strings:
        $cond1 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF 90 EE 01 6D C7 85 30 F9 FF FF 6C FE 01 6D 8D 85 34 F9 FF FF 89 28 BA CC 19 00 6D 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BB A6 00 00 A1 48 A1 05 6D C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B8 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 56 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 DF B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 52 0B 01 00 A1 4C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 51 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 EF AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 82 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 84 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 2C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 0C 40 05 6D A1 5C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 18 40 05 6D 89 04 24 A1 60 A1 05 6D FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 54 A1 05 6D FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 9C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 00 6D 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 00 6D 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 5D BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 48 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A0 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 FD BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 75 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 76 A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }

rule APT_Loader_Win32_REDFLARE_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4e7e90c7147ee8aa01275894734f4492"
        rev = 1
        author = "FireEye"
    strings:
        $inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_HackTool_MSIL_SHARPSTOMP_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "83ed748cd94576700268d35666bf3e01"
        rev = 3
        author = "FireEye"
    strings:
        $f0 = "mscoree.dll" fullword nocase
        $s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
        $s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
        $s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
        $s3 = "SetCreationTime" fullword
        $s4 = "GetLastAccessTime" fullword
        $s5 = "SetLastAccessTime" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Loader_Win64_PGF_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "2b686a8b83f8e1d8b455976ae70dab6e"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
        $sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
        $sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Trojan_Win_REDFLARE_5
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "AdjustTokenPrivileges" fullword
        $s2 = "LookupPrivilegeValueW" fullword
        $s3 = "ImpersonateLoggedOnUser" fullword
        $s4 = "runCommand" fullword
        $steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Loader_Win32_DShell_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "590d98bb74879b52b97d8a158af912af"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
        $ss4 = "C:\\Users\\config.ini" fullword
        $ss5 = "Invalid config file" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_HackTool_MSIL_FLUFFY_1
{
    meta:
        date_created = "2020-12-04"
        date_modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
        $sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
        $ss1 = "\x00Fluffy\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Loader_MSIL_RURALBISHOP_1
{
    meta:
        date_created = "2020-12-03"
        date_modified = "2020-12-03"
        md5 = "e91670423930cbbd3dbf5eac1f1a7cb6"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
        $sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $tb1 = "\x00SharpSploit.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@sb1[1] < @sb2[1]) and (all of ($ss*)) and (all of ($tb*))
}

rule APT_Downloader_Win32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "05b99d438dac63a5a993cea37c036673"
        rev = 1
        author = "FireEye"
    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [1-10] 6A 00 8B [1-8] 5? 6A 00 6A 00 6A 00 8B [1-8] 5? 68 [4] 8B [1-8] 5? FF 15 [4-40] 6A 14 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Loader_Win32_DShell_3
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Trojan_Linux_REDFLARE_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "find_applet_by_name" fullword
        $s2 = "bb_basename" fullword
        $s3 = "hk_printf_chk" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint32(0) == 0x464c457f) and all of them
}

rule APT_Loader_Win64_REDFLARE_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "100d73b35f23b2fe84bf7cd37140bf4d"
        rev = 1
        author = "FireEye"
    strings:
        $alloc = { 45 8B C0 33 D2 [2-6] 00 10 00 00 [2-6] 04 00 00 00 [1-6] FF 15 [4-60] FF 15 [4] 85 C0 [4-40] 20 00 00 00 [4-40] FF 15 [4] 85 C0 }
        $inject = { 83 F8 01 [2-20] 33 C0 45 33 C9 [3-10] 45 33 C0 [3-10] 33 D2 [30-100] FF 15 [4] 85 C0 [20-100] 01 00 10 00 [0-10] FF 15 [4] 85 C0 [4-30] FF 15 [4] 85 C0 [2-20] FF 15 [4] 83 F8 FF }
        $s1 = "ResumeThread" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Loader_Win32_DShell_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Loader_Win32_PGF_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "383161e4deaf7eb2ebeda2c5e9c3204c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A ?? FF 15 [4-32] 8A ?? 04 [0-32] 8B ?? 89 ?? 8B [2] 89 [2] 8B [2] 89 ?? 08 8B [2] 89 [2] 8B [2] 89 [2-64] 8B [5] 83 ?? 01 89 [5] 83 [5-32] 0F B6 [1-2] 0F B6 [1-2] 33 [1-16] 88 ?? EB }
        $sb2 = { 6A 40 [0-32] 68 00 30 00 00 [0-32] 6A 00 [0-16] FF 15 [4-32] 89 45 [4-64] E8 [4-32] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [2-64] FF ( D? | 55 ) }
        $sb3 = { 8B ?? 08 03 ?? 3C [2-32] 0F B? ?? 14 [0-32] 8D [2] 18 [2-64] 0F B? ?? 06 [3-64] 6B ?? 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Downloader_Win64_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1"
        rev = 2
        author = "FireEye"
    strings:
        $const = "Cookie: SID1=%s" fullword
        $http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Loader_Win64_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
        $sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
        $sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Trojan_Win_REDFLARE_3
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
        rev = 1
        author = "FireEye"
    strings:
        $calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
        $str1 = "CreateCompatibleBitmap" fullword
        $str2 = "BitBlt" fullword
        $str3 = "runCommand" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Loader_Win_PGF_1
{
    meta:
        description = "PDB string used in some PGF DLL samples"
        md5 = "013c7708f1343d684e3571453261b586"
        rev = 6
        author = "FireEye"
    strings:
        $pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
        $pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\Release\\DllSource\.pdb\x00/ nocase
        $pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and any of them
}

rule Loader_Win_Generic_17
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "562ecbba043552d59a0f23f61cea0983"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = { 89 [1-16] FF 15 [4-16] 89 [1-24] E8 [4-16] 89 C6 [4-24] 8D [1-8] 89 [1-4] 89 [1-4] E8 [4-16] 89 [1-8] E8 [4-24] 01 00 00 00 [1-8] 89 [1-8] E8 [4-64] 8A [1-8] 88 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "fread" fullword
        $si2 = "fwrite" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule based on symfunc/8a2f2236fdfaa3583ab89076025c6269. Identifies dllmain_hook x64 payloads."
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        rev = 4
        author = "FireEye"
    strings:
        $cond1 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 80 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 5A B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 E9 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AC 96 01 00 48 8D 45 AF 48 89 C1 E8 F0 FE 00 00 48 8B 05 25 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6B B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 AA B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 61 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 4F B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 20 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 0E C8 05 00 48 8B 05 69 8A 06 00 FF D0 48 8D 15 0A C8 05 00 48 89 C1 48 8B 05 5E 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 19 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 01 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 E0 F9 FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 87 F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CB 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 37 FC 00 00 48 89 D8 48 89 C1 E8 4C AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9A 9C 01 00 48 89 D8 48 89 C1 E8 2F AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }

rule HackTool_PY_ImpacketObfuscation_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        description = "smbexec"
        md5 = "0b1e512afe24c31531d6db6b47bac8ee"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "class CMDEXEC" nocase
        $s2 = "class RemoteShell" nocase
        $s3 = "self.services_names"
        $s4 = "import random"
        $s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
        $s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/
    condition:
        all of them
}

rule APT_HackTool_Win64_EXCAVATOR_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "4fd62068e591cbd6f413e1c2b8f75442"
        rev = 1
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { C7 [2-5] FD 03 00 AC 4C 8D 4D ?? 41 B8 1F 00 10 00 8B [2-5] 48 8B 4D ?? E8 [4] 89 [2-5] 83 [2-5] 00 74 ?? 48 8B 4D ?? FF 15 [4] 33 C0 E9 [4] 41 B8 10 00 00 00 33 D2 48 8D 8D [4] E8 [4] 48 8D 05 [4] 48 89 85 [4] 48 C7 85 [8] 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 C7 44 24 20 01 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4] 48 89 85 [4] 48 83 BD [4] FF 75 ?? 48 8B 4D ?? FF 15 [4] 33 C0 EB [0-17] 48 8D [5] 48 89 ?? 24 30 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 41 B9 02 00 00 00 4C 8B 85 [4] 8B [1-5] 48 8B 4D ?? E8 }
        $enable_dbg_pri = { 4C 8D 45 ?? 48 8D 15 [4] 33 C9 FF 15 [4] 85 C0 0F 84 [4] C7 45 ?? 01 00 00 00 B8 0C 00 00 00 48 6B C0 00 48 8B 4D ?? 48 89 4C 05 ?? B8 0C 00 00 00 48 6B C0 00 C7 44 05 ?? 02 00 00 00 FF 15 [4] 4C 8D 45 ?? BA 20 00 00 00 48 8B C8 FF 15 [4] 85 C0 74 ?? 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 45 ?? 33 D2 48 8B 4D ?? FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}

rule APT_Loader_Raw32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4022baddfda3858a57c9cbb0d49f6f86"
        rev = 1
        author = "FireEye"
    strings:
        $load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}

rule APT_Loader_Win64_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "4326a7e863928ffbb5f6bdf63bb9126e"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
        $sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
        $sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule based on symfunc/a86b004b5005c0bcdbd48177b5bac7b8"
        md5 = "8c91a27bbdbe9fb0877daccd28bd7bb5"
        rev = 3
        author = "FireEye"
    strings:
        $cond1 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 10 30 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 5C 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 00 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }

rule APT_Loader_Win32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "01d68343ac46db6065f888a094edfe4f"
        rev = 1
        author = "FireEye"
    strings:
        $alloc_n_load = { 6A 40 68 00 30 00 00 [0-20] 6A 00 [0-20] FF D0 [4-60] F3 A4 [30-100] 6B C0 28 8B 4D ?? 8B 4C 01 10 8B 55 ?? 6B D2 28 }
        $const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Loader_MSIL_PGF_1
{
    meta:
        date_created = "2020-11-24"
        date_modified = "2020-11-24"
        description = "base.cs"
        md5 = "a495c6d11ff3f525915345fb762f8047"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule looks for the binary signature of the routine that calls PssFreeSnapshot found in the Excavator-Reflector DLL."
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3
        author = "FireEye"
    strings:
        $bytes1 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A0 01 00 00 48 8B 05 4C 4A 01 00 48 33 C4 48 89 85 90 00 00 00 BA 50 00 00 00 C7 05 CB 65 01 00 43 00 3A 00 66 89 15 EC 65 01 00 4C 8D 44 24 68 48 8D 15 D8 68 01 00 C7 05 B2 65 01 00 5C 00 57 00 33 C9 C7 05 AA 65 01 00 69 00 6E 00 C7 05 A4 65 01 00 64 00 6F 00 C7 05 9E 65 01 00 77 00 73 00 C7 05 98 65 01 00 5C 00 4D 00 C7 05 92 65 01 00 45 00 4D 00 C7 05 8C 65 01 00 4F 00 52 00 C7 05 86 65 01 00 59 00 2E 00 C7 05 80 65 01 00 44 00 4D 00 C7 05 72 68 01 00 53 00 65 00 C7 05 6C 68 01 00 44 00 65 00 C7 05 66 68 01 00 42 00 75 00 C7 05 60 68 01 00 47 00 50 00 C7 05 5A 68 01 00 72 00 69 00 C7 05 54 68 01 00 56 00 69 00 C7 05 4E 68 01 00 4C 00 45 00 C7 05 48 68 01 00 67 00 65 00 C7 05 12 67 01 00 6C 73 61 73 C7 05 0C 67 01 00 73 2E 65 78 C6 05 09 67 01 00 65 FF 15 63 B9 00 00 45 33 F6 85 C0 74 66 48 8B 44 24 68 48 89 44 24 74 C7 44 24 70 01 00 00 00 C7 44 24 7C 02 00 00 00 FF 15 A4 B9 00 00 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF 15 1A B9 00 00 85 C0 74 30 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF 15 EF B8 00 00 FF 15 11 B9 00 00 48 8B 4C 24 48 FF 15 16 B9 00 00 48 89 9C 24 B0 01 00 00 48 8D 0D BF 2E 01 00 48 89 B4 24 B8 01 00 00 4C 89 74 24 40 FF 15 1C B9 00 00 48 85 C0 0F 84 B0 00 00 00 48 8D 15 AC 2E 01 00 48 8B C8 FF 15 1B B9 00 00 48 8B D8 48 85 C0 0F 84 94 00 00 00 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 06 15 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 63 66 0F 1F 44 00 00 48 8B 4C 24 40 4C 8D 45 80 41 B9 04 01 00 00 33 D2 FF 15 89 B8 00 00 48 8D 15 F2 65 01 00 48 8D 4D 80 E8 49 0F 00 00 48 85 C0 75 38 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 A3 14 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 A3 33 C0 E9 F5 00 00 00 48 8B 5C 24 40 48 8B CB FF 15 5E B8 00 00 8B F0 48 85 DB 74 E4 85 C0 74 E0 4C 8D 4C 24 50 48 89 BC 24 C0 01 00 00 BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 12 B8 00 00 85 C0 0F 85 A0 00 00 00 48 8D 05 43 FD FF FF 4C 89 74 24 30 C7 44 24 28 80 00 00 00 48 8D 0D 3F 63 01 00 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 4C 89 74 24 60 FF 15 E4 B7 00 00 48 8B F8 48 83 F8 FF 74 59 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 00 00 00 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF 15 B1 B9 00 00 48 8B CB FF 15 78 B7 00 00 48 8B CF FF 15 6F B7 00 00 FF 15 B1 B7 00 00 48 8B 54 24 50 48 8B C8 FF 15 53 B7 00 00 33 C9 FF 15 63 B7 00 00 CC 48 8B CB FF 15 49 B7 00 00 48 8B BC 24 C0 01 00 00 33 C0 48 8B B4 24 B8 01 00 00 48 8B 9C 24 B0 01 00 00 48 8B 8D 90 00 00 00 48 33 CC E8 28 00 00 00 4C 8B B4 24 C8 01 00 00 48 81 C4 A0 01 00 00 5D C3 }

rule APT_Trojan_Win_REDFLARE_6
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "RevertToSelf" fullword
        $s2 = "Unsuccessful" fullword
        $s3 = "Successful" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HackTool_Win64_AndrewSpecial_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "4456e52f6f8543c3ba76cb25ea3e9bd2"
        rev = 5
        author = "FireEye"
    strings:
        $dump = { 33 D2 B9 FF FF 1F 00 FF 15 [10-90] 00 00 00 00 [2-6] 80 00 00 00 [2-6] 02 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4-120] 00 00 00 00 [2-6] 00 00 00 00 [2-6] 00 00 00 00 41 B9 02 00 00 00 [6-15] E8 [4-20] FF 15 }
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x64_inline = { C6 44 24 ?? 4C C6 44 24 ?? 8B C6 44 24 ?? D1 C6 44 24 ?? B8 C6 44 24 ?? 3C C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 00 C6 44 24 ?? 0F C6 44 24 ?? 05 C6 44 24 ?? C3 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and $dump and any of ($shellcode*)
}

rule Loader_MSIL_Generic_1
{
    meta:
        md5 = "b8415b4056c10c15da5bba4826a44ffd"
        rev = 5
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
        $str1 = "DllImportAttribute"
        $str2 = "FromBase64String"
        $str3 = "ResumeThread"
        $str4 = "OpenThread"
        $str5 = "SuspendThread"
        $str6 = "QueueUserAPC"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of them
}

rule APT_Keylogger_Win32_REDFLARE_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "d7cfb9fbcf19ce881180f757aeec77dd"
        rev = 2
        author = "FireEye"
    strings:
        $create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
        $keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}

rule APT_Loader_Win_PGF_2
{
    meta:
        description = "PE rich header matches PGF backdoor"
        md5 = "226b1ac427eb5a4dc2a00cc72c163214"
        md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
        md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
        md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
        rev = 4
        author = "FireEye"
    strings:
        $rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
        $rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
        $rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
        $rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and (($rich1 at 128) or ($rich2 at 128) or ($rich3 at 128) or ($rich4 at 128))
}

rule Trojan_Win_Generic_101
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        md5 = "2e67c62bd0307c04af469ee8dcb220f2"
        rev = 3
        author = "FireEye"
    strings:
        $s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
        $s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
        $s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
        $si1 = "PeekMessageA" fullword
        $si2 = "PostThreadMessageA" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and @s0[1] < @s1[1] and @s1[1] < @s2[1] and all of them
}

rule Trojan_Win64_Generic_22
{
    meta:
        date_created = "2020-11-26"
        date_modified = "2020-11-26"
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        rev = 2
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
        $process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
        $token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}

rule Loader_Win_Generic_19
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "3fb9341fb11eca439b50121c6f7c59c7"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s1 = { 83 EC [1-16] 04 00 00 00 [1-24] 00 30 00 00 [1-24] FF 15 [4-16] EB [16-64] 20 00 00 00 [0-8] FF 15 [4-32] C7 44 24 ?? 00 00 00 00 [0-8] C7 44 24 ?? 00 00 00 00 [0-16] FF 15 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Builder_PY_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "d0a830403e56ebaa4bfbe87dbfdee44f"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "LOAD_OFFSET_32 = 0x612"
        $2 = "LOAD_OFFSET_64 = 0x611"
        $3 = "class RC4:"
        $4 = "struct.pack('<Q' if is64b else '<L'"
        $5 = "stagerConfig['comms']['config']"
        $6 = "_x86.dll"
        $7 = "_x64.dll"
    condition:
        all of them and @1[1] < @2[1] and @2[1] < @3[1] and @3[1] < @4[1] and @4[1] < @5[1]
}

rule HackTool_PY_ImpacketObfuscation_2
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        description = "wmiexec"
        md5 = "f3dd8aa567a01098a8a610529d892485"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "import random"
        $s2 = "class WMIEXEC" nocase
        $s3 = "class RemoteShell" nocase
        $s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
        $s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
    condition:
        all of them
}

rule APT_Loader_MSIL_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
        md5 = "7c2a06ceb29cdb25f24c06f2a8892fba"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "\x00ScriptObjectStackTop\x00"
        $ss3 = "\x00Microsoft.JScript\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Methodology_OLE_CHARENCODING_2
{
    meta:
        description = "Looking for suspicious char encoding"
        md5 = "41b70737fa8dda75d5e95c82699c2e9b"
        rev = 4
        author = "FireEye"
    strings:
        $echo1 = "101;99;104;111;32;111;102;102;" ascii wide
        $echo2 = "101:99:104:111:32:111:102:102:" ascii wide
        $echo3 = "101x99x104x111x32x111x102x102x" ascii wide
        $pe1 = "77;90;144;" ascii wide
        $pe2 = "77:90:144:" ascii wide
        $pe3 = "77x90x144x" ascii wide
        $pk1 = "80;75;3;4;" ascii wide
        $pk2 = "80:75:3:4:" ascii wide
        $pk3 = "80x75x3x4x" ascii wide
    condition:
        (uint32(0) == 0xe011cfd0) and filesize < 10MB and any of them
}

rule APT_Builder_Win64_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_pe_to_shellcode.rs"
        md5 = "8d949c34def898f0f32544e43117c057"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
        $ss1 = "\x00Stub Size: "
        $ss2 = "\x00Executable Size: "
        $ss3 = "\x00[+] Writing out to file"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule Trojan_Win64_Generic_23
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "b66347ef110e60b064474ae746701d4a"
        rev = 1
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { 8B 85 [4] C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 44 8B C0 33 D2 48 8B 8D [4] FF 15 [4] 48 89 45 ?? 48 83 7D ?? 00 75 ?? 48 8B 45 ?? E9 [4] 8B 85 [4] 48 C7 44 24 20 00 00 00 00 44 8B C8 4C 8B 85 [4] 48 8B 55 ?? 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? 48 8B 45 ?? EB ?? 8B 85 [4] 48 8B 4D ?? 48 03 C8 48 8B C1 48 89 45 48 48 8D 85 [4] 48 89 44 24 30 C7 44 24 28 00 00 00 00 48 8B 85 [4] 48 89 44 24 20 4C 8B 4D ?? 41 B8 00 00 10 00 33 D2 48 8B 8D [4] FF 15 }
        $process = { 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 08 00 00 00 4C 8D 8D [4] 41 B8 00 00 02 00 33 D2 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? E9 [4] 48 8B 85 [4] 48 89 85 [4] 48 8D 85 [4] 48 89 44 24 50 48 8D 85 [4] 48 89 44 24 48 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 C7 44 24 30 04 00 08 00 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 [4] 33 D2 48 8B [2-5] FF 15 }
        $token = { FF 15 [4] 4C 8D 45 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 75 ?? E9 [4] 48 8D [2-5] 48 89 44 24 28 C7 44 24 20 02 00 00 00 41 B9 02 00 00 00 45 33 C0 BA 0B 00 00 00 48 8B 4D ?? FF 15 [4] 85 C0 75 ?? E9 [4] 4C 8D 8D [4] 45 33 C0 BA 01 00 00 00 33 C9 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}

rule HackTool_MSIL_PuppyHound_1
{
    meta:
        description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 6
        author = "FireEye"
    strings:
        $1 = "PuppyHound"
        $2 = "UserDomainKey"
        $3 = "LdapBuilder"
        $init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
        $msil = /\x00_Cor(Exe|Dll)Main\x00/
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_HackTool_MSIL_ADPassHunt_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { 73 [2] 00 0A 0A 02 6F [2] 00 0A 0B 38 [4] 12 ?? 28 [2] 00 0A 0? 73 [2] 00 0A 0? 0? 0? 6F [2] 00 0A 1? 13 ?? 72 [4] 13 ?? 0? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 1? 3B [4] 11 ?? 72 [4] 28 [2] 00 0A 13 ?? 0? 72 [4] 6F [2] 00 0A 6F [2] 00 0A 13 ?? 38 [4] 11 ?? 6F [2] 00 0A 74 [2] 00 01 13 ?? 11 ?? 72 [4] 6F [2] 00 0A 2C ?? 11 ?? 72 [4] 11 ?? 6F [2] 00 0A 72 [4] 6F [2] 00 0A 6F [2] 00 0A 72 [4] 28 [2] 00 0A }
        $sb2 = { 02 1? 8D [2] 00 01 [0-32] 1? 1F 2E 9D 6F [2] 00 0A 72 [4] 0A 0B 1? 0? 2B 2E 0? 0? 9A 0? 0? 72 [4] 6F [2] 00 0A 2D ?? 06 72 [4] 28 [2] 00 0A 0A 06 72 [4] 0? 28 [2] 00 0A 0A 0? 1? 58 0? 0? 0? 8E 69 32 CC 06 2A }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule based on symfunc/8167a6d94baca72bac554299d7c7f83c"
        md5 = "150224a0ccabce79f963795bf29ec75b"
        rev = 3
        author = "FireEye"
    strings:
        $cond1 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 13 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 66 23 00 00 48 8B 4C 24 40 FF 15 EB F9 FF FF B8 01 00 00 00 48 83 C4 38 C3 }

rule APT_Trojan_Win_REDFLARE_2
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
        rev = 2
        author = "FireEye"
    strings:
        $1 = "initialize" fullword
        $2 = "getData" fullword
        $3 = "putData" fullword
        $4 = "fini" fullword
        $5 = "Cookie: SID1=%s" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule HackTool_MSIL_SharPivot_2
{
    meta:
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "costura"
        $s2 = "cmd_schtask" wide
        $s3 = "cmd_wmi" wide
        $s4 = "cmd_rpc" wide
        $s5 = "GoogleUpdateTaskMachineUA" wide
        $s6 = "servicehijack" wide
        $s7 = "poisonhandler" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Keylogger_Win64_REDFLARE_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "fbefb4074f1672a3c29c1a47595ea261"
        rev = 1
        author = "FireEye"
    strings:
        $create_window = { 41 B9 00 00 CF 00 [4-40] 33 C9 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 FF 15 }
        $keys_check = { B9 14 00 00 00 FF 15 [4-8] B9 10 00 00 00 FF 15 [4] BE 00 80 FF FF 66 85 C6 75 ?? B9 A0 00 00 00 FF 15 [4] 66 85 C6 75 ?? B9 A1 00 00 00 FF 15 [4] 66 85 C6 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_HackTool_Win64_EXCAVATOR_1
{
    meta:
        date_created = "2020-11-30"
        date_modified = "2020-11-30"
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
        $lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}

rule APT_Loader_Win64_MATRYOSHKA_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka.rs"
        md5 = "7f8102b789303b7861a03290c79feba0"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
        $sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
        $si1 = "CreateToolhelp32Snapshot" fullword
        $si2 = "Process32Next" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}

rule APT_Loader_MSIL_LUALOADER_1
{
    meta:
        author = "FireEye"
    strings:
        $sb1 = { 1? 72 [4] 14 D0 [2] 00 02 28 [2] 00 0A 1? 8D [2] 00 01 13 ?? 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 1? 1? 14 28 [2] 00 0A A2 11 ?? 28 [2] 00 0A 28 [2] 00 0A 80 [2] 00 04 7E [2] 00 04 7B [2] 00 0A 7E [2] 00 04 11 ?? 11 ?? 6F [2] 00 0A 6F [2] 00 0A }
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule APT_Loader_MSIL_LUALOADER_2
{
    meta:
        author = "FireEye"
    strings:
        $ss1 = "\x3bN\x00e\x00o\x00.\x00I\x00r\x00o\x00n\x00L\x00u\x00a\x00.\x00L\x00u\x00a\x00C\x00o\x00m\x00p\x00i\x00l\x00e\x00O\x00p\x00t\x00i\x00o\x00n\x00s\x00"
        $ss2 = "\x19C\x00o\x00m\x00p\x00i\x00l\x00e\x00C\x00h\x00u\x00n\x00k\x00"
        $ss3 = "\x0fd\x00o\x00c\x00h\x00u\x00n\x00k\x00"
        $ss4 = /.Reflection.Assembly:Load\(\w{1,64}\);?\s{0,245}\w{1,64}\.EntryPoint:Invoke\(nil/ wide
        $ss5 = "1F 8B 08 00 00 00 00 00" wide
        $ss6 = "\x00LoadLibrary\x00"
        $ss7 = "\x00GetProcAddress\x00"
        $ss8 = "\x00VirtualProtect\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule FE_APT_Loader_MSIL_REVOLVER_1
{
    meta:
        author = "FireEye"
    strings:
        $inject = { 28 [2] 00 06 0? 0? 7B [2] 00 04 7E [2] 00 0A 28 [2] 00 0A [2-40] 7E [2] 00 0A 0? 20 00 10 00 00 28 [2] 00 0A 0? 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? ?? 20 00 30 00 00 1F 40 28 [2] 00 06 [2-40] 28 [2] 00 0A 1? 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 1? ?? FE 15 [2] 00 02 1? ?? 72 [2] 00 70 28 [2] 00 06 1? ?? FE 15 [2] 00 02 1? ?? 1? ?? 1? 28 [2] 00 06 2? 7E [2] 00 0A 1? ?? 0? 7B [2] 00 04 1? ?? 1? 1? ?? 28 [2] 00 06 2? ?? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-10] 7E [2] 00 0A 1? ?? 1? ?? 20 [2] 1F 00 7E [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? 1? 20 [2] 00 00 20 [2] 00 00 7E [2] 00 0A 28 [2] 00 06 2? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-40] 1? ?? 0? 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 2? ?? 2? 1? 1? ?? 1? ?? 1? ?? 28 [2] 00 06 }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Loader_MSIL_DUEDLLIGENCE_1
{
    meta:
        author = "FireEye"
    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Loader_MSIL_DUEDLLIGENCE_2
{
    meta:
        author = "FireEye"
    strings:
        $1 = "DueDLLigence" fullword
        $2 = "CPlApplet" fullword
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule Loader_MSIL_DUEDLLIGENCE_3
{
    meta:
        author = "FireEye"
    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $rc4 = { 20 00 01 00 00 8D [2] 00 01 1? ?? 20 00 01 00 00 8D [2] 00 01 1? ?? 03 8E 69 8D [2] 00 01 1? ?? 16 0B 2B ?? 1? ?? 07 02 07 02 8E 69 5D 91 9E 1? ?? 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 }
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}