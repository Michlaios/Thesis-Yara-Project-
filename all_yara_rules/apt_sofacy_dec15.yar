rule Sofacy_Malware_StrangeSpaces {
	meta:
		description = "Detetcs strange strings from Sofacy malware with many spaces"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		id = "60f99b88-f256-5289-852c-c0bf27f1cbd4"
	strings:
		$s2 = "Delete Temp Folder Service                                  " fullword wide
		$s3 = " Operating System                        " fullword wide
		$s4 = "Microsoft Corporation                                       " fullword wide
		$s5 = " Microsoft Corporation. All rights reserved.               " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and 3 of them
}

rule Sofacy_Malware_AZZY_Backdoor_1 {
	meta:
		description = "AZZY Backdoor - Sample 1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "a9dc96d45702538c2086a749ba2fb467ba8d8b603e513bdef62a024dfeb124cb"
		id = "184dc45e-8014-5dcf-a033-d77586c60fdf"
	strings:
		$s0 = "advstorshell.dll" fullword wide
		$s1 = "advshellstore.dll" fullword ascii
		$s2 = "Windows Advanced Storage Shell Extension DLL" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}