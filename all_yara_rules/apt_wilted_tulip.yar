rule WiltedTulip_WindowsTask {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip - Windows Tasks"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "c3cbe88b82cd0ea46868fb4f2e8ed226f3419fc6d4d6b5f7561e70f4cd33822c"
      hash2 = "340cbbffbb7685133fc318fa20e4620ddf15e56c0e65d4cf1b2d606790d4425d"
      hash3 = "b6f515b3f713b70b808fc6578232901ffdeadeb419c9c4219fbfba417bba9f01"
      hash4 = "5046e7c28f5f2781ed7a63b0871f4a2b3065b70d62de7254491339e8fe2fa14a"
      hash5 = "984c7e1f76c21daf214b3f7e131ceb60c14abf1b0f4066eae563e9c184372a34"
      id = "ad8193f0-e664-50a8-ab05-38027a2e33cd"
   strings:
      $x1 = "<Command>C:\\Windows\\svchost.exe</Command>" fullword wide
      $x2 = "<Arguments>-nop -w hidden -encodedcommand" wide
      $x3 = "-encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"
   condition:
      1 of them
}

rule WiltedTulip_tdtess {
   meta:
      description = "Detects malicious service used in Operation Wilted Tulip"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"
      id = "0ecb391b-a4f9-5362-bb65-73801ae497de"
   strings:
      $x1 = "d2lubG9naW4k" fullword wide /* base64 encoded string 'winlogin$' */
      $x2 = "C:\\Users\\admin\\Documents\\visual studio 2015\\Projects\\Export\\TDTESS_ShortOne\\WinService Template\\" ascii

      $s1 = "\\WinService Template\\obj\\x64\\x64\\winlogin" ascii
      $s2 = "winlogin.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 2 of them ) )
}

rule WiltedTulip_Zpp {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23"
      modified = "2022-12-21"
      hash1 = "10ec585dc1304436821a11e35473c0710e844ba18727b302c6bd7f8ebac574bb"
      hash2 = "7d046a3ed15035ea197235980a72d133863c372cc27545af652e1b2389c23918"
      hash3 = "6d6816e0b9c24e904bc7c5fea5951d53465c478cc159ab900d975baf8a0921cf"
      id = "7d833cb2-485e-5a26-be2f-aaebde7fdef2"
   strings:
      $x1 = "[ERROR] Error Main -i -s -d -gt -lt -mb" fullword wide
      $x2 = "[ERROR] Error Main -i(with.) -s -d -gt -lt -mb -o -e" fullword wide

      $s1 = "LT Time invalid" fullword wide
      $s2 = "doCompressInNetWorkDirectory" fullword ascii
      $s3 = "files remaining ,total file save = " fullword wide
      $s4 = "$ec996350-79a4-477b-87ae-2d5b9dbe20fd" fullword ascii
      $s5 = "Destinition Directory Not Found" fullword wide
      $s6 = "\\obj\\Release\\ZPP.pdb" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( 1 of ($x*) or 3 of them )
}