rule Industroyer_Malware_1 {
   meta:
      description = "Detects Industroyer related malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "ad23c7930dae02de1ea3c6836091b5fb3c62a89bf2bcfb83b4b39ede15904910"
      hash2 = "018eb62e174efdcdb3af011d34b0bf2284ed1a803718fba6edffe5bc0b446b81"
      id = "f5ab571c-03a7-538a-ada1-0930d15af5cf"
   strings:
      $s1 = "haslo.exe" fullword ascii
      $s2 = "SYSTEM\\CurrentControlSet\\Services\\%ls" fullword wide
      $s3 = "SYS_BASCON.COM" fullword wide
      $s4 = "*.pcmt" fullword wide
      $s5 = "*.pcmi" fullword wide

      $x1 = { 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73
         00 5C 00 25 00 6C 00 73 00 00 00 49 00 6D 00 61
         00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 43
         00 3A 00 5C 00 00 00 44 00 3A 00 5C 00 00 00 45
         00 3A 00 5C 00 00 00 }
      $x2 = "haslo.dat\x00Crash"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) or 2 of them )
}

rule Industroyer_Portscan_3 {
   meta:
      description = "Detects Industroyer related custom port scaner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "893e4cca7fe58191d2f6722b383b5e8009d3885b5913dcd2e3577e5a763cdb3f"
      id = "f6675466-d469-562b-9fb6-7b72bce8a726"
   strings:
      $s1 = "!ZBfamily" fullword ascii
      $s2 = ":g/outddomo;" fullword ascii
      $s3 = "GHIJKLMNOTST" fullword ascii
      /* Decompressed File */
      $d1 = "Error params Arguments!!!" fullword wide
      $d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
      $d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
      $d4 = "Error IP Range %ls - %ls" fullword wide
      $d5 = "Can't closesocket." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) or 2 of ($d*) )
}

rule Industroyer_Malware_4 {
   meta:
      description = "Detects Industroyer related malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "21c1fdd6cfd8ec3ffe3e922f944424b543643dbdab99fa731556f8805b0d5561"
      id = "f197d2a5-eecb-51ed-b991-7643efb3f749"
   strings:
      $s1 = "haslo.dat" fullword wide
      $s2 = "defragsvc" fullword ascii

      /* .dat\x00\x00Crash */
      $a1 = { 00 2E 00 64 00 61 00 74 00 00 00 43 72 61 73 68 00 00 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or $a1 )
}