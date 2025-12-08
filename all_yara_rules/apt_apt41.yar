rule APT_APT41_POISONPLUG {
   meta:
      description = "Detects APT41 malware POISONPLUG"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 80
      hash1 = "2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd"
      hash2 = "5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90"
      hash3 = "f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661"
      hash4 = "3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f"
      id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
   strings:
      $s1 = "TSMSISrv.DLL" fullword wide
      $s2 = "[-]write failed[%d]" fullword ascii
      $s3 = "[-]load failed" fullword ascii
      $s4 = "Remote Desktop Services" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and (
         pe.imphash() == "1b074ef7a1c0888ef31337c8ad2f2e0a" or
         2 of them
      )
}

rule APT_APT41_HIGHNOON_BIN {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 90
      hash1 = "490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994"
      hash2 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
      id = "c8bd62b4-b882-5c04-aace-76dd4a21a784"
   strings:
      $s1 = "PlusDll.dll" fullword ascii
      $s2 = "\\Device\\PORTLESS_DeviceName" wide
      $s3 = "%s%s\\Security" fullword ascii
      $s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
      $s5 = "%s%s\\Enum" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "b70358b00dd0138566ac940d0da26a03" or
         3 of them
      )
}

rule APT_APT41_HIGHNOON_BIN_2 {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 85
      hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
      hash2 = "c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d"
      id = "37d6a44d-7811-5e87-84e2-b2a8b3da3124"
   strings:
      $x1 = "\\Double\\Door_wh\\" ascii
      $x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
      $x3 = "\\RbDoorX64.pdb" ascii
      $x4 = "RbDoor, Version 1.0" fullword wide
      $x5 = "About RbDoor" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule APT_APT41_CN_ELF_Speculoos_Backdoor {
   meta:
      description = "Detects Speculoos Backdoor used by APT41"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
      date = "2020-04-14"
      score = 90
      hash1 = "6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167"
      hash2 = "99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28"
      id = "efe2b368-33af-5382-a5f0-0e7dd7f4dea4"
   strings:
      $xc1 = { 2F 70 72 69 76 61 74 65 2F 76 61 72 00 68 77 2E
               70 68 79 73 6D 65 6D 00 68 77 2E 75 73 65 72 6D
               65 6D 00 4E 41 2D 4E 41 2D 4E 41 2D 4E 41 2D 4E
               41 2D 4E 41 00 6C 6F 30 00 00 00 00 25 30 32 78
               2D 25 30 32 78 2D 25 30 32 78 2D 25 30 32 78 2D
               25 30 32 78 2D 25 30 32 78 0A 00 72 00 4E 41 00
               75 6E 61 6D 65 20 2D 76 }
      
      $s1 = "badshell" ascii fullword
      $s2 = "hw.physmem" ascii fullword
      $s3 = "uname -v" ascii fullword
      $s4 = "uname -s" ascii fullword
      $s5 = "machdep.tsc_freq" ascii fullword
      $s6 = "/usr/sbin/config.bak" ascii fullword
      $s7 = "enter MessageLoop..." ascii fullword
      $s8 = "exit StartCBProcess..." ascii fullword

      $sc1 = { 72 6D 20 2D 72 66 20 22 25 73 22 00 2F 70 72 6F
               63 2F }
   condition:
      uint16(0) == 0x457f and
      filesize < 600KB and
      1 of ($x*) or 4 of them
}