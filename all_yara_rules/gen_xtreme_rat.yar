rule Xtreme_Sep17_1 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "93c89044e8850721d39e935acd3fb693de154b7580d62ed460256cabb75599a6"
      id = "7517e237-9cad-5619-9028-4c7ab5463040"
   strings:
      $x1 = "ServerKeyloggerU" fullword ascii
      $x2 = "TServerKeylogger" fullword ascii
      $x3 = "XtremeKeylogger" fullword wide
      $x4 = "XTREMEBINDER" fullword wide

      $s1 = "shellexecute=" fullword wide
      $s2 = "[Execute]" fullword wide
      $s3 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and (
         pe.imphash() == "735af2a144f62c50ba8e89c1c59764eb" or
         ( 1 of ($x*) or 3 of them )
      )
}

rule Xtreme_Sep17_3 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
      id = "160673ea-b263-520a-a1c1-da0f3e920f12"
   strings:
      $s2 = "Keylogg" fullword ascii
      $s4 = "XTREME" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and all of them )
}