rule Shifu_Banking_Trojan_0 : banking {
	meta:
		description = "Detects Shifu Banking Trojan"
		author = "Florian Roth"
		reference = "https://securityintelligence.com/shifu-masterful-new-banking-trojan-is-attacking-14-japanese-banks/"
		date = "2015-09-01"
		hash1 = "4ff1ebea2096f318a2252ebe1726bcf3bbc295da9204b6c720b5bbf14de14bb2"
		hash2 = "4881c7d89c2b5e934d4741a653fbdaf87cc5e7571b68c723504069d519d8a737"
	strings:
		$x1 = "c:\\oil\\feet\\Seven\\Send\\Gather\\Dividerail.pdb" fullword ascii

		$s1 = "listen above" fullword wide
		$s2 = "familycould cost" fullword wide
		$s3 = "SetSystemTimeAdjustment" fullword ascii /* Goodware String - occured 33 times */
		$s4 = "PeekNamedPipe" fullword ascii /* Goodware String - occured 347 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and ($x1 or all of ($s*))
}

rule Shifu : banking {
	meta:
		reference = "https://blogs.mcafee.com/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools/"
		author = "McAfee Labs"
	strings:
		$b = "RegCreateKeyA"
		$a = "CryptCreateHash"
		$c = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 25 00 73 00 00 00 00 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 00 72 00 75 00 6E}
		$d = {53 00 6E 00 64 00 56 00 6F 00 6C 00 2E 00 65 00 78 00 65}
		$e = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45}
	condition:
		all of them
}