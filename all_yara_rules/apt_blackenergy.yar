rule BlackEnergy_BE_2 {
   meta:
      description = "Detects BlackEnergy 2 Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/DThzLz"
      date = "2015/02/19"
      hash = "983cfcf3aaaeff1ad82eb70f77088ad6ccedee77"
      id = "c93991b9-77e8-5a73-80ef-e21df770c3a5"
   strings:
      $s0 = "<description> Windows system utility service  </description>" fullword ascii
      $s1 = "WindowsSysUtility - Unicode" fullword wide
      $s2 = "msiexec.exe" fullword wide
      $s3 = "WinHelpW" fullword ascii
      $s4 = "ReadProcessMemory" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and all of ($s*)
}

rule BlackEnergy_BackdoorPass_DropBear_SSH {
	meta:
		description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
		id = "60db00dd-72b3-5a28-90de-2a397b1e007b"
	strings:
		$s1 = "passDs5Bu9Te7" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $s1
}