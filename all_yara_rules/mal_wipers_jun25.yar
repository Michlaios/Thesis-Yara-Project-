rule MAL_WIPER_Unknown_Jun25 {
   meta:
      description = "Detects unknown disk wiper first spotted in June 2025 and uploaded from Israel"
      author = "Florian Roth"
      reference = "https://x.com/cyb3rops/status/1935707307805134975"
      date = "2025-06-19"
      score = 75
      hash1 = "12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721"
   strings:
      $x1 = "\\CWipeNew\\Release\\" ascii fullword

      $s1 = "Failed to get disk geometry: " wide fullword
      $s2 = "--- Working on " wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}

rule SUSP_LNX_SH_Disk_Wiper_Script_Jun25 {
   meta:
      description = "Detects unknown disk wiper script for Linux systems"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-06-19"
      score = 65
      hash1 = "f662f69fc7f4240cd8c00661db9484e76b5d02f903590140b4086fefcf9d9331"
   strings:
      $s1 = "THIS SCRIPT IS LIVE AND ARMED!" ascii fullword
      $s2 = "FAIR WARNING!" ascii fullword
      $s3 = "lists devices" ascii fullword
   condition:
      uint16(0) == 0x2123
      and filesize < 2KB
      and all of them
}

rule APT_MAL_IR_DruidFly_Wiper_Jun25 {
   meta:
      description = "Detects Wiper used by the Iranian DruidFly group"
      author = "Florian Roth"
      reference = "https://x.com/threatintel/status/1936049254432231444"
      date = "2025-06-21"
      score = 80
      hash1 = "81eb22828306f3197b35fef2035cef2c548f587f8511902852964850023389d7"
   strings:
      $xc1 = { 2E 62 61 63 6B 75 70 00 2E 63 6F 6E 66 69 67 00   // .backup .config
               2E 64 62 00 00 00 00 00 2E 73 71 6C 69 74 65 00 } // // .db.... .sqlite
      $xc2 = { 00 5C 5C 2E 5C 25 63 3A 00 25 63 3A 5C 00 00 00
               00 4E 54 46 53 00 00 00 00 5C }  // \\.\%c: %c:\0\0\0 NTFS\0\0\0\

      $x1 = "%s:%d:%s(): [+] Overwriting \"%s\" \"..." ascii

      $s1 = "C:\\Windows\\System32\\drivers\\beep.sys" ascii fullword
      $s2 = "\\DosDevices\\sectorio" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 2000KB
      and ( 
         1 of ($x*)
         or 2 of them
      )
      or 3 of them
}