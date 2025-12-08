rule APT_Thrip_Sample_Jun18_1 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "59509a17d516813350fe1683ca6b9727bd96dd81ce3435484a5a53b472ff4ae9"
      id = "5b506069-8185-5dc0-bf64-90646f6bab6b"
   strings:
      $s1 = "idocback.dll" fullword ascii
      $s2 = "constructor or from DllMain." fullword ascii
      $s3 = "appmgmt" fullword ascii
      $s4 = "chksrv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule APT_Thrip_Sample_Jun18_2 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "1fc9f7065856cd8dc99b6f46cf0953adf90e2c42a3b65374bf7b50274fb200cc"
      id = "bc1cfcc8-64a0-5da0-8ff7-147da8a3af0b"
   strings:
      $s1 = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" fullword ascii
      $s2 = "ProbeScriptFint" fullword wide
      $s3 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule APT_Thrip_Sample_Jun18_3 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "0d2abdcaad99e102fdf6574b3dc90f17cb9d060c20e6ac4ff378875d3b91a840"
      id = "67ea7ed1-954f-5b3e-b058-452be3b6fdfa"
   strings:
      $s1 = "C:\\Windows\\SysNative\\cmd.exe" fullword ascii
      $s2 = "C:\\Windows\\SysNative\\sysprep\\cryptbase.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule APT_Thrip_Sample_Jun18_4 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "6b236d3fc54d36e6dc2a26299f6ded597058fed7c9099f1a37716c5e4b162abc"
      id = "9dcfcdbd-d18f-5eba-a10c-95686f010f23"
   strings:
      $s1 = "\\system32\\wbem\\tmf\\caches_version.db" ascii
      $s2 = "ProcessName No Access" fullword ascii
      $s3 = "Hwnd of Process NULL" fullword ascii
      $s4 = "*********The new session is be opening:(%d)**********" fullword ascii
      $s5 = "[EXECUTE]" fullword ascii
      $s6 = "/------------------------------------------------------------------------" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "Time:%d-%d-%d %d:%d:%d" fullword ascii
      $s9 = "\\info.config" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 5 of them
}

rule APT_Thrip_Sample_Jun18_6 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "44f58496578e55623713c4290abb256d03103e78e99939daeec059776bd79ee2"
      id = "a1c65bc1-371e-509f-a01c-2d58c1773f95"
   strings:
      $s1 = "C:\\Windows\\system32\\Instell.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule APT_Thrip_Sample_Jun18_10 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "350d2a6f8e6a4969ffbf75d9f9aae99e7b3a8cd8708fd66f977e07d7fbf842e3"
      id = "3307ca18-59fb-5400-b51e-c4f4aa99e592"
   strings:
      $x1 = "!This Program cannot be run in DOS mode." fullword ascii
      $x2 = "!this program cannot be run in dos mode." fullword ascii

      $s1 = "svchost.dll" fullword ascii
      $s2 = "constructor or from DllMain." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and ( $x1 or 2 of them )
}

rule APT_Thrip_Sample_Jun18_16 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "2b1c1c6d82837dbbccd171a0413c1d761b1f7c3668a21c63ca06143e731f030e"
      id = "58be9a1b-2228-5d7a-97c9-198cacbe1a66"
   strings:
      $s1 = "[%d] Failed, %08X" fullword ascii
      $s2 = "woqunimalegebi" fullword ascii
      $s3 = "[%d] Offset can not fetched." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB
      and ( all of them or pe.imphash() == "c6a4c95d868a3327a62c9c45f5e15bbf" )
}

rule APT_Thrip_Sample_Jun18_17 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "05036de73c695f59adf818d3c669c48ce8626139d463b8a7e869d8155e5c0d85"
      hash2 = "08d8c610e1ec4a02364cb53ba44e3ca5d46e8a177a0ecd50a1ef7b5db252701d"
      hash3 = "14535607d9a7853f13e8bf63b629e3a19246ed9db6b4d2de2ca85ec7a7bee140"
      id = "e314a893-1ef5-5d5f-b056-af25765c0b70"
   strings:
      $x1 = "c:\\users\\administrator\\desktop\\code\\skeyman2\\" ascii
      $x2 = "\\SkeyMan2.pdb" ascii
      $x3 = "\\\\.\\Pnpkb" fullword ascii

      $s1 = "\\DosDevices\\Pnpkb" wide
      $s2 = "\\DosDevices\\PnpKb" wide
      $s3 = "\\Driver\\kbdhid" wide
      $s4 = "\\Device\\PnpKb" wide
      $s5 = "Microsoft  Windows Operating System" fullword wide
      $s6 = "hDevice == INVALID_HANDLE_VALUE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) and 1 of ($s*) )
}

rule APT_Thrip_Sample_Jun18_18 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "33029f5364209e05481cfb2a4172c6dc157b0070f51c05dd34485b8e8da6e820"
      hash2 = "263c01a3b822722dc288a5ac138d953630d8c548a0bee080ae3979b7d364cecb"
      hash3 = "52d190a8d20b4845551b8765cbd12cfbe04cf23e6812e238e5a5023c34ee9b37"
      hash4 = "1f019e3c30a02b7b65f7984903af11d561d02b2666cc16463c274a2a0e62145d"
      hash5 = "43904ea071d4dce62a21c69b8d6efb47bcb24c467c6f6b3a6a6ed6cd2158bfe5"
      hash6 = "00d9da2b665070d674acdbb7c8f25a01086b7ca39d482d55f08717f7383ee26a"
      id = "20642526-5a4d-5dca-a6f5-29f19a9b5271"
   strings:
      $s1 = "Windows 95/98/Me, Windows NT 4.0, Windows 2000/XP: IME PROCESS key" fullword ascii
      $s2 = "Windows 2000/XP: Either the angle bracket key or the backslash key on the RT 102-key keyboard" fullword ascii
      $s3 = "LoadLibraryA() failed in KbdGetProcAddressByName()" fullword ascii
      $s5 = "Unknown Virtual-Key Code" fullword ascii
      $s6 = "Computer Sleep key" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them
}