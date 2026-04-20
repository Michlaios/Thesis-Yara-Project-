rule Nanocore_RAT_Gen_1 {
	meta:
		description = "Detetcs the Nanocore RAT and similar malware"
		author = "Florian Roth"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		score = 70
		hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"
	strings:
		$x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
		$x2 = "RunPE1" fullword ascii
		$x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
		$x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
		$x5 = "Monitorinjection" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}

rule Nanocore_RAT_Sample_2 {
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		author = "Florian Roth"
		score = 75
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		date = "2016-04-22"
		hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
	strings:
		$s1 = "U4tSOtmpM" fullword ascii
		$s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" fullword wide
		$s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*)
}