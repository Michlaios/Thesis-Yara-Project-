rule Impacket_Tools_wmiexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
      id = "3c2c7edf-da71-53dc-9ddf-dfbf10838a27"
   strings:
      $s1 = "bwmiexec.exe.manifest" fullword ascii
      $s2 = "swmiexec" fullword ascii
      $s3 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}

rule Impacket_Tools_mmcexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "263a1655a94b7920531e123a8c9737428f2988bf58156c62408e192d4b2a63fc"
      id = "cca2082f-72a4-50c8-80b8-a9bed430dc4e"
   strings:
      $s1 = "smmcexec" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and all of them )
}

rule Impacket_Tools_smbexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
      id = "02208817-2eab-54e2-90cf-44dbf5474607"
   strings:
      $s1 = "logging.config(" ascii
      $s2 = "ssmbexec" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_smbtorture {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
      id = "4f9b55e2-93ce-5d08-a228-73233fb0a2c6"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "ssmbtorture" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_mimikatz {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
      id = "0b1f5ad0-7070-58d5-946f-157dcb9627ab"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "smimikatz" fullword ascii
      $s3 = "otwsdlc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_wmipersist {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
      id = "29bda652-28f0-5ab6-9bc2-411f20ab0dda"
   strings:
      $s1 = "swmipersist" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}

rule Impacket_Tools_wmiquery {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
      id = "e8bdf27a-9763-5947-854f-162f74ff53be"
   strings:
      $s1 = "swmiquery" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}