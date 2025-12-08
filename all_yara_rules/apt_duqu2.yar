rule Duqu2_Sample2 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
		hash2 = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
		hash3 = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
		hash4 = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
		hash5 = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
		hash6 = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
		id = "a32f54a3-8656-5592-ac40-17330bfca319"
	strings:
		$s1 = "=<=Q=W=a=g=p=v=|=" fullword ascii
		$s2 = ">#>(>.>3>=>]>d>p>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of ($s*)
}

rule Duqu2_Sample3 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		id = "c558445f-fbe3-57db-80f7-09a87b097921"
	strings:
		$s1 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and $s1 )
}

rule Duqu2_Sample4 {
	meta:
		description = "Detects Duqu2 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
		id = "8c5ca68d-762c-5d2e-8d37-f58dc66bcae2"
	strings:
		$x1 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s2 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s4 = "ProcessUserAccounts" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) ) or ( all of them )
}