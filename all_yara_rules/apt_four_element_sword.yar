rule FourElementSword_Keyainst_EXE {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		id = "175fe2b0-3c76-5464-9a1a-218a09b25a5a"
	strings:
		$x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii

		$s1 = "ShellExecuteA" fullword ascii /* Goodware String - occured 266 times */
		$s2 = "GetStartupInfoA" fullword ascii /* Goodware String - occured 2573 times */
		$s3 = "SHELL32.dll" fullword ascii /* Goodware String - occured 3233 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}

rule FourElementSword_PowerShell_Start {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
		id = "62affc03-a408-5d8f-99da-58dead8646c5"
	strings:
		$s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
		$s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
	condition:
		1 of them
}