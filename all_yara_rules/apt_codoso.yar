rule Codoso_CustomTCP_3 {
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"
	strings:
		$s1 = "DnsApi.dll" fullword ascii
		$s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
		$s3 = "CONNECT %s:%d hTTP/1.1" ascii
		$s4 = "CONNECT %s:%d HTTp/1.1" ascii
		$s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
		$s6 = "iphlpapi.dll" ascii
		$s7 = "%systemroot%\\Web\\" ascii
		$s8 = "Proxy-Authorization: Negotiate %s" ascii
		$s9 = "CLSID\\{%s}\\InprocServer32" ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 5 of them ) or 7 of them
}

rule Codoso_PGV_PVID_6 {
	meta:
		description = "Detects Codoso APT PGV_PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"
		id = "6d1d8490-fdcb-5263-ae00-0b436e822fc3"
	strings:
		$s0 = "rundll32 \"%s\",%s" fullword ascii
		$s1 = "/c ping 127.%d & del \"%s\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}

rule Codoso_CustomTCP {
	meta:
		description = "Codoso CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"
	strings:
		$s4 = "wnyglw" fullword ascii
		$s5 = "WorkerRun" fullword ascii
		$s7 = "boazdcd" fullword ascii
		$s8 = "wayflw" fullword ascii
		$s9 = "CODETABL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 405KB and all of them
}

rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash3 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash4 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash5 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		id = "c1c753a6-77b6-5bfb-89f9-16127c264fd0"
	strings:
		$x1 = "dropper, Version 1.0" fullword wide
		$x2 = "dropper" fullword wide
		$x3 = "DROPPER" fullword wide
		$x4 = "About dropper" fullword wide

		$s1 = "Microsoft Windows Manager Utility" fullword wide
		$s2 = "SYSTEM\\CurrentControlSet\\Services\\" ascii /* Goodware String - occured 9 times */
		$s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" fullword ascii /* Goodware String - occured 10 times */
		$s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* Goodware String - occured 46 times */
		$s5 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}