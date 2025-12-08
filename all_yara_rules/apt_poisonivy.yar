rule PoisonIvy_Sample_7 {
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "9480cf544beeeb63ffd07442233eb5c5f0cf03b3"
		id = "01224053-d95e-5144-981b-76cd7e57e1c3"
	strings:
		$s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
		$s2 = "pidll.dll" fullword ascii /* score: '11.02' */
		$s10 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
		$s11 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
		$s12 = "Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3 times */
		$s13 = "Microsoft(R) Windows(R) Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 128 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule PoisonIvy_RAT_ssMUIDLL {
	meta:
		description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
		author = "Florian Roth (Nextron Systems) (with the help of yarGen and Binarly)"
		reference = "http://goo.gl/WiwtYT"
		date = "2016-04-22"
		hash1 = "7a424ad3f3106b87e8e82c7125834d7d8af8730a2a97485a639928f66d5f6bf4"
		hash2 = "6eb7657603edb2b75ed01c004d88087abe24df9527b272605b8517a423557fe6"
		hash3 = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		hash4 = "8b805f508879ecdc9bba711cfbdd570740c4825b969c1b4db980c134ac8fef1c"
		hash5 = "ac99d4197e41802ff9f8852577955950332947534d8e2a0e3b6c1dd1715490d4"
		id = "f2535b70-cf17-5435-9fc8-2dfdf70d95ac"
	strings:
		$s1 = "ssMUIDLL.dll" fullword ascii

		 // 0x10001f81 6a 00	push	0
		 // 0x10001f83 c6 07 e9	mov	byte ptr [edi], 0xe9
		 // 0x10001f86 ff d6	call	esi
		 $op1 = { 6a 00 c6 07 e9 ff d6 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x10001f81
		 // 0x100012a9 02 cb	add	cl, bl
		 // 0x100012ab 6a 00	push	0
		 // 0x100012ad 88 0f	mov	byte ptr [edi], cl
		 // 0x100012af ff d6	call	esi
		 // 0x100012b1 47	inc	edi
		 // 0x100012b2 ff 4d fc	dec	dword ptr [ebp - 4]
		 // 0x100012b5 75 ??	jne	0x10001290
		 $op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x100012a9
		 // 0x10001f93 6a 00	push	0
		 // 0x10001f95 88 7f 02	mov	byte ptr [edi + 2], bh
		 // 0x10001f98 ff d6	call	esi
		 $op3 = { 6a 00 88 7f 02 ff d6 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x10001f93

	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and ( all of ($op*) ) ) or ( all of them )
}