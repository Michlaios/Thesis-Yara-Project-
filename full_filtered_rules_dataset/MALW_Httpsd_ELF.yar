rule Linux_Httpsd_malware_ARM {
  
	meta:
		description = "Detects Linux/Httpsd ARMv5"
		date = "2017-12-31"

	strings:
		$hexsts01 = { f0 4f 2d e9 1e db 4d e2 ec d0 4d e2 01 40 a0 e1 } // main
		$hexsts02 = { f0 45 2d e9 0b db 4d e2 04 d0 4d e2 3c 01 9f e5 } // self-rclocal
		$hexsts03 = { f0 45 2d e9 01 db 4d e2 04 d0 4d e2 bc 01 9f e5 } // copy-self

	condition:
		all of them
        	and is__elf
		and is__LinuxHttpsdStrings
		and filesize < 200KB 
}

rule Linux_Httpsd_malware_i686 {

	meta:
		description = "Detects ELF Linux/Httpsd i686"
		date = "2018-01-02"

	
	strings:
		$hexsts01 = { 8d 4c 24 04 83 e4 f0 ff 71 fc 55 89 e5 57 56 53 } // main
		$hexsts02 = { 55 89 e5 57 56 53 81 ec 14 2c 00 00 68 7a 83 05 } // self-rclocal
		$hexsts03 = { 55 89 e5 57 56 53 81 ec 10 04 00 00 68 00 04 00 } // copy-self

	condition:
		all of them
        	and is__elf
		and is__LinuxHttpsdStrings
		and filesize < 200KB 
}