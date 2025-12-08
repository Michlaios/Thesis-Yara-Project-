rule Rombertik_CarbonGrabber {
	meta:
		description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
		hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
		hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c" 
		hash4 = "98223d4ec272d3a631498b621618d875dd32161d" 	
		id = "b3aee336-9f3b-5fae-928d-8357408a7b69"
	strings:
		$x1 = "ZwGetWriteWatch" fullword ascii
		$x2 = "OutputDebugStringA" fullword ascii
		$x3 = "malwar" fullword ascii
		$x4 = "sampl" fullword ascii
		$x5 = "viru" fullword ascii
		$x6 = "sandb" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5MB and all of them
}

rule Rombertik_CarbonGrabber_Panel_InstallScript {
	meta:
		description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"
		id = "f6c04e27-bbab-5012-a4f9-71d49d252b83"
	strings:
		$s0 = "$insert = \"INSERT INTO `logs` (`id`, `ip`, `name`, `host`, `post`, `time`, `bro" ascii
		$s3 = "`post` text NOT NULL," fullword ascii
		$s4 = "`host` text NOT NULL," fullword ascii
		$s5 = ") ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;\" ;" fullword ascii
		$s6 = "$db->exec($columns); //or die(print_r($db->errorInfo(), true));;" fullword ascii
		$s9 = "$db->exec($insert);" fullword ascii
		$s10 = "`browser` text NOT NULL," fullword ascii
		$s13 = "`ip` text NOT NULL," fullword ascii
	condition:
		filesize < 3KB and all of them
}