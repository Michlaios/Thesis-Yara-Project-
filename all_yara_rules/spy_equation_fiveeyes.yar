rule apt_equation_exploitlib_mutexes {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        version = "1.0"
		date = "2016-02-15"
        modified = "2023-01-27"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        id = "d060bfd7-fb16-55d3-8a39-1197fdd8e759"
    strings:
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"
    condition:
        uint16(0) == 0x5A4D and any of ($a*)
}

rule apt_equation_doublefantasy_genericresource {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}

rule apt_equation_cryptotable {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the crypto library used in Equation group malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "https://securelist.com/blog/"
	    id = "e7f313a3-8ef8-5363-898a-836a96aaa2ff"
	strings:
	    $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}
	condition:
	    $a
}

rule Equation_Kaspersky_EquationDrugInstaller {
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		id = "fa549e6e-f0d8-55ea-9ec9-c8ec53b55dec"
	strings:
		$s0 = "\\system32\\win32k.sys" wide
		$s1 = "ALL_FIREWALLS" fullword ascii

		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EOP_Package {
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		id = "2eb97873-a415-57be-a8fb-70ef86a99c9b"
	strings:
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100000 and all of ($s*)
}

rule EquationDrug_Keylogger {
	meta:
		description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"
		id = "57b6af34-577b-58ec-9a9e-91911c32270b"
	strings:
		$s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
		$s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
		$s3 = "\\DosDevices\\Gk" wide
		$s5 = "\\Device\\Gk0" wide
	condition:
		all of them
}

rule EquationDrug_NetworkSniffer4 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"
      id = "12bb1eb3-a14e-5616-bc7c-249c83f97035"
   strings:
      $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
      $s1 = "\\systemroot\\" ascii
      $s2 = "RAVISENT Technologies Inc." fullword wide
      $s3 = "Created by VIONA Development" fullword wide
      $s4 = "\\Registry\\User\\CurrentUser\\" wide
      $s5 = "\\device\\harddiskvolume" wide
      $s7 = "ATMDKDRV.SYS" fullword wide
      $s8 = "\\Device\\%ws_%ws" wide
      $s9 = "\\DosDevices\\%ws" wide
      $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
      $s11 = "\\Device\\%ws" wide
      $s13 = "CineMaster C 1.1 WDM" fullword wide
   condition:
      all of them
}

rule EquationDrug_NetworkSniffer5 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "09399b9bd600d4516db37307a457bc55eedcbd17"
      id = "9eac2c51-3ad7-5346-a985-39733bc204c2"
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "atmdkdrv.sys" fullword wide
      $s4 = "\\Device\\%ws_%ws" wide
      $s5 = "\\DosDevices\\%ws" wide
      $s6 = "\\Device\\%ws" wide
   condition:
      all of them
}

rule apt_equation_keyword {
    meta:
        description = "Rule to detect Equation group's keyword in executable file"
        last_modified = "2015-09-26"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        id = "a7d4eda5-f390-5099-9c46-bf74a878b4f0"
    strings:
         $a1 = "Backsnarf_AB25" wide
         $a2 = "Backsnarf_AB25" ascii
    condition:
         uint16(0) == 0x5a4d and 1 of ($a*)
}