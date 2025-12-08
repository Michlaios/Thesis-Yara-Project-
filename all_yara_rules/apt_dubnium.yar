rule Dubnium_Sample_1 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
		id = "377ecbaa-9324-562e-a973-0276d44f3feb"
	strings:
		$key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
		$key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule Dubnium_Sample_2 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		id = "894dc893-25fc-5fdc-9f69-8085b94e1af1"
	strings:
		$x1 = ":*:::D:\\:c:~:" fullword ascii
		$s2 = "SPMUVR" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Dubnium_Sample_3 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "caefcdf2b4e5a928cdf9360b70960337f751ec4a5ab8c0b75851fc9a1ab507a8"
		hash2 = "e0362d319a8d0e13eda782a0d8da960dd96043e6cc3500faeae521d1747576e5"
		hash3 = "a77d1c452291a6f2f6ed89a4bac88dd03d38acde709b0061efd9f50e6d9f3827"
		id = "66f66139-88df-5ba9-a3fc-ba4fc98ce3f9"
	strings:
		$x1 = "copy /y \"%s\" \"%s\" " fullword ascii
		$x2 = "del /f \"%s\" " fullword ascii
		$s1 = "del /f /ah \"%s\" " fullword ascii
		$s2 = "if exist \"%s\" goto Rept " fullword ascii
		$s3 = "\\*.*.lnk" ascii
		$s4 = "Dropped" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 5 of them
}