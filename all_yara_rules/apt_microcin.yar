rule Microcin_Sample_2 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
      id = "8718ef84-be2b-55a6-a4bb-41161548a2b4"
   strings:
      $s2 = "[Pause]" fullword ascii
      $s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_3 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
      id = "daecdfe3-e78c-55ee-83a3-3cee8cb9bb5f"
   strings:
      $x1 = "C:\\Users\\Lenovo\\Desktop\\test\\Release\\test.pdb" fullword ascii
      $s2 = "test, Version 1.0" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_5 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"
      id = "cd06f9f7-0ba3-52c9-a814-be1cd53e2e42"
   strings:
      $x1 = "Sorry, you are not fortuante ^_^, Please try other password dictionary " fullword ascii
      $x2 = "DomCrack <IP> <UserName> <Password_Dic file path> <option>" fullword ascii
      $x3 = "The password is \"%s\"         Time: %d(s)" fullword ascii
      $x4 = "The password is \" %s \"         Time: %d(s)" fullword ascii
      $x5 = "No password found!" fullword ascii
      $x7 = "Can not found the Password Dictoonary file! " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them ) or 2 of them
}

rule Microcin_Sample_6 {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26"
      hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
      hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
      id = "9988723f-a7ca-598f-9a6c-9f3915732117"
   strings:
      $s1 = "** ERROR ** %s: %s" fullword ascii
      $s2 = "TEMPDATA" fullword wide
      $s3 = "Bruntime error " fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}