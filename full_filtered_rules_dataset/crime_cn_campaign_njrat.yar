rule CN_disclosed_20180208_lsls {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "94c6a92984df9ed255f4c644261b01c4e255acbe32ddfd0debe38b558f29a6c9"
      id = "c6c4aa72-1a84-552f-bea0-38b332a74233"
   strings:
      $x1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and $x1
}

rule CN_disclosed_20180208_System3 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"
      id = "097f4506-295d-5066-8895-2148436731c1"
   strings:
      $a1 = "WmiPrvSE.exe" fullword wide

      $s1 = "C:\\Users\\sgl\\AppData\\Local\\" ascii
      $s2 = "Temporary Projects\\WmiPrvSE\\" ascii
      $s3 = "$15a32a5d-4906-458a-8f57-402311afc1c1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and $a1 and 1 of ($s*)
}

rule CN_disclosed_20180208_KeyLogger_1 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "c492889e1d271a98e15264acbb21bfca9795466882520d55dc714c4899ed2fcf"
      id = "12eff9b6-1a65-5efc-b39c-88297bdae9c3"
   strings:
      $x2 = "Process already elevated." fullword wide
      $x3 = "GetKeyloggErLogsResponse" fullword ascii
      $x4 = "get_encryptedPassword" fullword ascii
      $x5 = "DoDownloadAndExecute" fullword ascii
      $x6 = "GetKeyloggeRLogs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}