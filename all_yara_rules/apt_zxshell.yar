rule ZxShell_Related_Malware_CN_Group_Jul17_1 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "ef56c2609bc1b90f3e04745890235e6052a4be94e35e38b6f69b64fb17a7064e"
      id = "a91e39bb-1bb3-54a8-b684-d673c445375c"
   strings:
      $x1 = "CMD.EXE /C NET USER GUEST /ACTIVE:yes && NET USER GUEST ++++++" ascii
      $x2 = "system\\cURRENTcONTROLSET\\sERVICES\\tERMSERVICE" fullword ascii
      $x3 = "\\secivreS\\teSlortnoCtnerruC\\METSYS" ascii /* reversed goodware string 'SYSTEM\\CurrentControlSet\\Services\\' */
      $x4 = "system\\cURRENTCONTROLSET\\cONTROL\\tERMINAL sERVER" fullword ascii
      $x5 = "sOFTWARE\\mICROSOFT\\iNTERNET eXPLORER\\mAIN" fullword ascii
      $x6 = "eNABLEaDMINtsREMOTE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_3 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "2e5cf8c785dc081e5c2b43a4a785713c0ae032c5f86ccbc7abf5c109b8854ed7"
      id = "1900b861-b4a2-50b5-a639-3eb442072139"
   strings:
      $s1 = "%s\\nt%s.dll" fullword ascii
      $s2 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}