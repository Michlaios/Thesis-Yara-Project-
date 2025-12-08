rule StoneDrill_main_sub {
   meta:
      author = "Kaspersky Lab"
      description = "Rule to detect StoneDrill (decrypted) samples"
      hash1 = "d01781f1246fd1b64e09170bd6600fe1"
      hash2 = "ac3c25534c076623192b9381f926ba0d"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      version = "1.0"
      id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
   strings:
      $code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF 30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}
   condition:
      uint16(0) == 0x5A4D and $code and filesize < 5000000
}

rule StoneDrill_BAT_1 {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      description = "Rule to detect Batch file from StoneDrill report"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
   strings:
      $s1 = "set u100=" ascii
      $s2 = "set u200=service" ascii fullword
      $s3 = "set u800=%~dp0" ascii fullword
      $s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
      $s5 = "%\" start /b %systemroot%\\system32\\%" ascii
   condition:
      uint32(0) == 0x68636540 and 2 of them and filesize < 500
}

rule StoneDrill_ntssrvr32 {
   meta:
      description = "Detects malware from StoneDrill threat report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07"
      modified = "2023-01-27"
      hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
      id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
   strings:
      $s1 = "g\\system32\\" wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii

      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 3 of them )
}