rule TA17_293A_energetic_bear_api_hashing_tool {
   meta:
      description = "Energetic Bear API Hashing Tool"
      assoc_report = "DHS Report TA17-293A"
      author = "CERT RE Team"
      version = "2"
      id = "4e58800a-9618-5d8b-954c-e843be6002c2"
   strings:
      $api_hash_func_v1 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
      $api_hash_func_v2 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 44 24 14 EB EC }
      $api_hash_func_x64 = { 8A 08 84 C9 74 ?? 80 C9 60 48 01 CB 48 C1 E3 01 48 03 45 20 EB EA }

      $http_push = "X-mode: push" nocase
      $http_pop = "X-mode: pop" nocase
   condition:
      $api_hash_func_v1 or $api_hash_func_v2 or $api_hash_func_x64 and (uint16(0) == 0x5a4d or $http_push or $http_pop)
}

rule TA17_293A_Query_XML_Code_MAL_DOC_PT_2 {
    meta:
        name= "Query_XML_Code_MAL_DOC_PT_2"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"
    strings:
        $dir1 = "word/_rels/settings.xml.rels"
        $bytes = {8c 90 cd 4e eb 30 10 85 d7}
    condition:
        uint32(0) == 0x04034b50 and $dir1 and $bytes
}

rule TA17_293A_Query_Javascript_Decode_Function {
    meta:
        name= "Query_Javascript_Decode_Function"
        author = "other (modified by Florian Roth)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
        id = "bc206ab3-a86b-5abe-ae84-15abab838d4e"
    strings:
        $decode1 = {72 65 70 6C 61 63 65 28 2F 5B 5E 41 2D 5A 61 2D 7A 30 2D 39 5C 2B 5C 2F 5C 3D 5D 2F 67 2C 22 22 29 3B}
        $decode2 = {22 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F 3D 22 2E 69 6E 64 65 78 4F 66 28 ?? 2E 63 68 61 72 41 74 28 ?? 2B 2B 29 29}
        $decode3 = {3D ?? 3C 3C 32 7C ?? 3E 3E 34 2C ?? 3D 28 ?? 26 31 35 29 3C 3C 34 7C ?? 3E 3E 32 2C ?? 3D 28 ?? 26 33 29 3C 3C 36 7C ?? 2C ?? 2B 3D [1-2] 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29 2C 36 34 21 3D ?? 26 26 28 ?? 2B 3D 53 74 72 69 6E 67 2E 66 72 6F 6D 43 68 61 72 43 6F 64 65 28 ?? 29}
        $decode4 = {73 75 62 73 74 72 69 6E 67 28 34 2C ?? 2E 6C 65 6E 67 74 68 29}
        /* Only 3 characters atom - this is bad for performance - we're trying to leave this out
        $func_call="a(\""
        */
    condition:
        filesize < 20KB and
        /* #func_call > 20 and */
        all of ($decode*)
}

rule TA17_293A_Hacktool_Touch_MAC_modification {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
      id = "69240cc0-a04e-544a-b7e3-c5a08c062055"
   strings:
      $s1 = "-t time - use the time specified to update the access and modification times" fullword ascii
      $s2 = "Failed to set file times for %s. Error: %x" fullword ascii
      $s3 = "touch [-acm][ -r ref_file | -t time] file..." fullword ascii
      $s4 = "-m - change the modification time only" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule TA17_293A_Hacktool_Exploit_MS16_032 {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21"
      hash1 = "9b97290300abb68fb48480718e6318ee2cdd4f099aa6438010fb2f44803e0b58"
      id = "4c5838d7-9956-564e-a25c-f2ba5641ac03"
   strings:
      $x1 = "[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread)))" ascii
      $x2 = "0x00000002, \"C:\\Windows\\System32\\cmd.exe\", \"\"," fullword ascii
      $x3 = "PowerShell implementation of MS16-032. The exploit targets all vulnerable" fullword ascii
      $x4 = "If we can't open the process token it's a SYSTEM shell!" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them )
}