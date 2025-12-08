rule Bytes_used_in_AES_key_generation {
   meta:
      author = "NCSC"
      description = "Detects Backdoor.goodor"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
      id = "26a549dd-cbd2-5abc-8d9d-5ea354d0ece8"
   strings:
      $a1 = {35 34 36 35 4B 4A 55 54 5E 49 55 5F 29 7B 68 36 35 67 34 36 64 66 35 68}
      /* $a2 = {fb ff ff ff 00 00}  disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of ($a*)
}

rule Partial_Implant_ID {
   meta:
      author = "NCSC"
      description = "Detects implant from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
      id = "15144f4a-2c96-57f0-b7e9-adbac477c38a"
   strings:
      $a1 = {38 38 31 34 35 36 46 43}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}

rule Sleep_Timer_Choice {
   meta:
      author = "NCSC"
      description = "Detects malware from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
      id = "c64db0dd-2858-5508-ac51-d3318113a060"
   strings:
      $a1 = {8b0424b90f00000083f9ff743499f7f98d420f}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}

rule generic_shellcode_downloader_specific {
  meta:
    author = "NCSC"
    description = "Detects Doorshell from NCSC report"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    date = "2018/04/06"
    hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
    id = "ddd25add-ff84-5106-ac3c-5d5b4c1ef2a9"
  strings:
    $push1 = {68 6C 6C 6F 63}
    $push2 = {68 75 61 6C 41}
    $push3 = {68 56 69 72 74}
    $a = {BA 90 02 00 00 46 C1 C6 19 03 DD 2B F4 33 DE}
    $b = {87 C0 81 F2 D1 19 89 14 C1 C8 1F FF E0}
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3C)) == 0x4550) and ($a or $b) and @push1 < @push2 and @push2 < @push3
}

rule lnk_detect {
   meta:
      author = "NCSC"
      description = "Detects malicious LNK file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      id = "76d382f3-b2f2-5ede-94b2-5ae8b766c194"
   strings:
      $lnk_magic = {4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46}
      $lnk_target = {41 00 55 00 54 00 4F 00 45 00 58 00 45 00 43 00 2E 00 42 00 41 00 54}
      $s1 = {5C 00 5C 00 31 00}
      $s2 = {5C 00 5C 00 32 00}
      $s3 = {5C 00 5C 00 33 00}
      $s4 = {5C 00 5C 00 34 00}
      $s5 = {5C 00 5C 00 35 00}
      $s6 = {5C 00 5C 00 36 00}
      $s7 = {5C 00 5C 00 37 00}
      $s8 = {5C 00 5C 00 38 00}
      $s9 = {5C 00 5C 00 39 00}
   condition:
      uint32be(0) == 0x4c000000 and
      uint32be(4) == 0x01140200 and
      (($lnk_magic at 0) and $lnk_target) and 1 of ($s*)
}

rule WEBSHELL_Z_WebShell_1 {
   meta:
      author = "NCSC"
      description = "Detects Z Webshell from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      old_rule_name = "Z_WebShell"
      hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
      id = "f4b50760-bd3a-5e1f-bf32-50f16a42c381"
   strings:
      $ = "Z_PostBackJS" ascii wide
      $ = "z_file_download" ascii wide
      $ = "z_WebShell" ascii wide
      $ = "1367948c7859d6533226042549228228" ascii wide
   condition:
      3 of them
}