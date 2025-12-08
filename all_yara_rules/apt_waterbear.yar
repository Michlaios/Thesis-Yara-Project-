rule Waterbear_8_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      modified = "2023-01-07"
      hash1 = "bd06f6117a0abf1442826179f6f5e1932047b4a6c14add9149e8288ab4a902c3"
      hash1 = "5dba8ddf05cb204ef320a72a0c031e55285202570d7883f2ff65135ec35b3dd0"
      id = "5ebeda22-ad67-5715-b42f-9b4bb5dcde94"
   strings:
      $s1 = "Update.dll" fullword ascii
      $s2 = "ADVPACK32.DLL" fullword wide
      $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ascii
      $s4 = "\\drivers\\sftst.sys" ascii
      $s5 = "\\\\.\\SFilter" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule Waterbear_12_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "15d9db2c90f56cd02be38e7088db8ec00fc603508ec888b4b85d60d970966585"
      id = "cc0a071c-c409-57a2-80c5-dd93ca7db339"
   strings:
      $s1 = "O_PROXY" fullword ascii
      $s2 = "XMODIFY" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}