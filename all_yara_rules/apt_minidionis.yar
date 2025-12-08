rule MiniDionis_readerView {
	meta:
		description = "MiniDionis Malware - file readerView.exe / adobe.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		/* Original Hash */
		hash1 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
		/* Derived Samples */
		hash2 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
		hash3 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
		hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
		hash5 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
		hash6 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"
		id = "dc8d4311-2a87-5c9b-95ff-52708f293f01"
	strings:
		$s1 = "%ws_out%ws" fullword wide /* score: '8.00' */
		$s2 = "dnlibsh" fullword ascii /* score: '7.00' */

		$op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b } /* Opcode */
		$op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f } /* Opcode */
		$op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) and 1 of ($op*)
}

rule Malicious_SFX1 {
	meta:
		description = "SFX with voicemail content"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"
		id = "7c29dfb0-bbed-5017-80b4-a5c44024cd70"
	strings:
		$s0 = "voicemail" ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s1 = ".exe" ascii
	condition:
		uint16(0) == 0x4b50 and filesize < 1000KB and $s0 in (3..80) and $s1 in (3..80) 
}