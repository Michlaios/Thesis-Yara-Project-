rule EQGRP_teflondoor {
	meta:
		description = "Detects tool from EQGRP toolset - file teflondoor.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "188f9ef1-5524-50be-ac62-91cb9726b155"
	strings:
		$x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
		$x2 = "%s: %li b (%li%%)" fullword ascii

		$s1 = "no winsock" fullword ascii
		$s2 = "%s: %s file '%s'" fullword ascii
		$s3 = "peer: connect" fullword ascii
		$s4 = "read: write" fullword ascii
		$s5 = "%s: done!" fullword ascii
		$s6 = "%s: %li b" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) and 3 of them
}

rule EQGRP_durablenapkin_solaris_2_0_1 {
	meta:
		description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "7b49a26d-9ee3-5aff-93fc-509239daef28"
	strings:
		$s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
		$s2 = "send_request: putmsg \"%s\": %s" fullword ascii
		$s3 = "port undefined" fullword ascii
		$s4 = "recv_ack: %s getmsg: %s" fullword ascii
		$s5 = ">> %d -- %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 2 of them )
}

rule EQGRP_teflonhandle {
	meta:
		description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "4d82cc41-3777-5f8c-9392-aca69e6ed781"
	strings:
		$s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
		$s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
		$s3 = "Random Key : 0x" fullword ascii
		$s4 = "done (%i bytes written)." fullword ascii
		$s5 = "%s --> %s..." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and 2 of them
}

rule EQGRP_false {
	meta:
		description = "Detects tool from EQGRP toolset - file false.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "3a68790b-38fc-570b-8b19-c5478cdd2842"
	strings:
		$s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
			2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
			0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
			0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
			00 25 64 20 2D 20 25 64 }
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and $s1
}

rule EQGRP_dn_1_0_2_1 {
	meta:
		description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "24b5fb51-2463-56ef-818a-949b4b3bbf5b"
	strings:
		$s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
		$s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
		$s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
		$s4 = "Not everything is set yet" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 2 of them )
}

rule EQGRP_morel {
	meta:
		description = "Detects tool from EQGRP toolset - file morel.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"
		id = "e741b727-0e41-53d0-832c-df7f4ea7964a"
	strings:
		$s1 = "%d - %d, %d" fullword ascii
		$s2 = "%d - %lu.%lu %d.%lu" fullword ascii
		$s3 = "%d - %d %d" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}

rule EQGRP_bc_parser {
	meta:
		description = "Detects tool from EQGRP toolset - file bc-parser"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"
		id = "ed4523de-b126-503a-83bd-aafd8533b0e5"
	strings:
		$s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
		$s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
	condition:
		uint16(0) == 0x457f and 1 of them
}

rule EQGRP_1212 {
	meta:
		description = "Detects tool from EQGRP toolset - file 1212.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "428fed4f-df5c-5fc2-ac4b-4dea69ea4f2d"
	strings:
		$s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
		$s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
		$s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
		$s4 = "$dstport=hextoPort($dstport);" fullword ascii
		$s5 = "sub hextoPort" fullword ascii
		$s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
	condition:
		filesize < 6KB and 4 of them
}

rule EQGRP_1212_dehex {
	meta:
		description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "2cc375e6-2bff-5623-b86c-a6413f736c42"
	strings:
		$s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
		$s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
		$s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
		$s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
		$s5 = "print hextoIP($ARGV[0]);" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 6KB and ( 5 of ($s*) ) ) or ( all of them )
}

rule install_get_persistent_filenames {
	meta:
		description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"
		id = "cf74b479-4b78-537a-878c-2f3ce004b775"
	strings:
		$s1 = "Generates the persistence file name and prints it out." fullword ascii
	condition:
		( uint16(0) == 0x457f and all of them )
}

rule EQGRP_payload {
	meta:
		description = "EQGRP Toolset Firewall - file payload.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
		id = "949cb68b-e384-578c-a906-a4d9234dc668"
	strings:
		$s1 = "can't find target version module!" fullword ascii
		$s2 = "class Payload:" fullword ascii
	condition:
		all of them
}

rule EQGRP_BUSURPER_2211_724 {
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"
		id = "d109210e-14df-5b90-a496-fa8a2454126b"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "_start_text" ascii
		$s3 = "IMPLANT" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "upgrade_implant" fullword ascii
	condition:
		all of them
}

rule EQGRP_epicbanana_2_1_0_1 {
	meta:
		description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"
		id = "cc3346bd-0347-5cf3-b946-5c017d68d93e"
	strings:
		$s1 = "failed to create version-specific payload" fullword ascii
		$s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
	condition:
		1 of them
}

rule EQGRP_BananaAid {
	meta:
		description = "EQGRP Toolset Firewall - file BananaAid"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"
		id = "bdd3ce51-1809-5b2f-9c7e-6c0b056d022b"
	strings:
		$x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
		$x2 = "scp BGLEE-" ascii
		$x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
		$x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
	condition:
		1 of them
}

rule EQGRP_bo {
	meta:
		description = "EQGRP Toolset Firewall - file bo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"
		id = "6aa71528-3ce6-5597-bb1a-e44cff3856d6"
	strings:
		$s1 = "ERROR: failed to open %s: %d" fullword ascii
		$s2 = "__libc_start_main@@GLIBC_2.0" ascii
		$s3 = "serial number: %s" fullword ascii
		$s4 = "strerror@@GLIBC_2.0" fullword ascii
		$s5 = "ERROR: mmap failed: %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 20KB and all of them )
}

rule EQGRP_SecondDate_2211 {
	meta:
		description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"
		id = "00951270-6189-58b6-8b64-422c4ab15ebe"
	strings:
		$s1 = "SD_processControlPacket" fullword ascii
		$s2 = "Encryption_rc4SetKey" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EQGRP_BBALL_M50FW08_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "pageTable.c" fullword ascii
		$s4 = "_start_text" ascii
		$s5 = "handler_readBIOS" fullword ascii
		$s6 = "KEEPGOING" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 5 of ($s*) )
}

rule EQGRP_BUSURPER_3001_724 {
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"
		id = "006877e9-1e73-5a27-8b3a-bca3513a2035"
	strings:
		$s1 = "IMPLANT" fullword ascii
		$s2 = "KEEPGOING" fullword ascii
		$s3 = "upgrade_implant" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}

rule EQGRP_shellcode {
	meta:
		description = "EQGRP Toolset Firewall - file shellcode.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ac9decb971dd44127a6ca0d35ac153951f0735bb4df422733046098eca8f8b7f"
		id = "d923c1de-c6eb-511f-ae1f-bf3ac6e0eae8"
	strings:
		$s1 = "execute_post = '\\xe8\\x00\\x00\\x00\\x00\\x5d\\xbe\\xef\\xbe\\xad\\xde\\x89\\xf7\\x89\\xec\\x29\\xf4\\xb8\\x03\\x00\\x00\\x00" ascii
		$s2 = "tiny_exec = '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00\\x01\\x00\\x00" ascii
		$s3 = "auth_id = '\\x31\\xc0\\xb0\\x03\\x31\\xdb\\x89\\xe1\\x31\\xd2\\xb6\\xf0\\xb2\\x0d\\xcd\\x80\\x3d\\xff\\xff\\xff\\xff\\x75\\x07" ascii

		$c1 = { e8 00 00 00 00 5d be ef be ad de 89 f7 89 ec 29 f4 b8 03 00 00 00 }
		/* $c2 = { 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 02 00 03 00 01 00 00 }  too many fps */
		$c3 = { 31 c0 b0 03 31 db 89 e1 31 d2 b6 f0 b2 0d cd 80 3d ff ff ff ff 75 07 }
	condition:
		1 of them
}

rule EQGRP_BPIE {
	meta:
		description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"
		id = "a73f0216-3994-5ee6-8a8c-cbcc1279898e"
	strings:
		$s1 = "profProcessPacket" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "getTimeSlotCmdHandler" fullword ascii
		$s4 = "getIpIpCmdHandler" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "profStartScan" fullword ascii
		$s7 = "tmpData.1" fullword ascii
		$s8 = "resetCmdHandler" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 70KB and 6 of ($s*) )
}

rule EQGRP_BBANJO {
	meta:
		description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"
		id = "81af4769-7007-51f1-9569-bc370618b4ff"
	strings:
		$s1 = "get_lsl_interfaces" fullword ascii
		$s2 = "encryptFC4Payload" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "beacon_getconfig" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "FormBeaconPacket" fullword ascii
		$s7 = "beacon_reconfigure" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 50KB and all of them )
}

rule EQGRP_BPATROL_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"
		id = "864a346c-e8aa-5c66-9867-faccb14b8bee"
	strings:
		$s1 = "dumpConfig" fullword ascii
		$s2 = "getstatusHandler" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "xtractdata" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and all of them )
}

rule EQGRP_extrabacon {
	meta:
		description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"
		id = "79b998ef-e548-5038-b8ad-da1abf362e7f"
	strings:
		$x1 = "To disable password checking on target:" fullword ascii
		$x2 = "[-] target is running" fullword ascii
		$x3 = "[-] problem importing version-specific shellcode from" fullword ascii
		$x4 = "[+] importing version-specific shellcode" fullword ascii
		$s5 = "[-] unsupported target version, abort" fullword ascii
	condition:
		1 of them
}

rule EQGRP_sploit_py {
	meta:
		description = "EQGRP Toolset Firewall - file sploit.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		id = "9f403965-5fb1-55b2-bef6-65c18e08e58f"
	strings:
		$x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
		$x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
		$x3 = "[-] no response from health check - target may have crashed" fullword ascii
	condition:
		1 of them
}

rule EQGRP_BICECREAM {
	meta:
		description = "EQGRP Toolset Firewall - file BICECREAM-2140"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"
		id = "a10819ae-db48-5d30-8e2e-2e4fe33e005b"
	strings:
		$s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
		$s2 = "command data size is invalid for an exec cmd" fullword ascii
		$s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
		$s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
		$s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
		$s6 = "[%d] Execute code." fullword ascii
		$s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
		$s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
		$s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}

rule EQGRP_create_http_injection {
	meta:
		description = "EQGRP Toolset Firewall - file create_http_injection.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"
		id = "92b6dad0-c7d8-5522-8fc1-fbd0aae00960"
	strings:
		$x1 = "required by SECONDDATE" fullword ascii

		$s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
		$s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
		$s3 = "version='%prog 1.0'," fullword ascii
		$s4 = "usage='%prog [ ... options ... ] url'," fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 3KB and ( $x1 or 2 of them ) ) or ( all of them )
}

rule EQGRP_BFLEA_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"
		id = "7dfdc2a2-73d1-5eba-8936-ed14b17495c5"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "readFlashHandler" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "flashRtnsPix6x.c" fullword ascii
		$s6 = "fix_ip_cksum_incr" fullword ascii
		$s7 = "writeFlashHandler" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}

rule EQGRP_BpfCreator_RHEL4 {
	meta:
		description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"
		id = "476185f2-b093-5fb9-8604-891e96fe52a9"
	strings:
		$s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
		$s2 = "error reading dump file: %s" fullword ascii
		$s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
		$s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
		$s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 2000KB and all of them )
}

rule EQGRP_hexdump {
	meta:
		description = "EQGRP Toolset Firewall - file hexdump.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"
		id = "32a7d845-2fa3-5d8f-84e1-2c7f8d2ca8c8"
	strings:
		$s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
		$s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
		$s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
		$s4 = "print >>out, sane(x[i:i+16])" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 1KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_BBALL {
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
	strings:
		$s1 = "Components/Modules/BiosModule/Implant/E28F6/../e28f640j3_asm.S" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "handler_readBIOS" fullword ascii
		$s4 = "cmosReadByte" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
		$s6 = "checksumAreaConfirmed.0" fullword ascii
		$s7 = "writeSpeedPlow.c" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 4 of ($s*) ) or ( all of them )
}

rule EQGRP_tinyexec {
	meta:
		description = "EQGRP Toolset Firewall - from files tinyexec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "b783bafd-52e2-59e8-98ab-47de3250415e"
	strings:
		$s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
		$s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }
	condition:
		uint32(0) == 0x464c457f and filesize < 270 and all of them
}

rule EQGRP_Extrabacon_Output {
	meta:
		description = "EQGRP Toolset Firewall - Extrabacon exploit output"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "b2070ed7-e95a-534a-8f27-63c5ca9251b4"
	strings:
		$s1 = "|###[ SNMPresponse ]###" fullword ascii
		$s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
		$s3 = "[+] building payload for mode pass-disable" fullword ascii
		$s4 = "[+] Executing:  extrabacon" fullword ascii
		$s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii
	condition:
		2 of them
}

rule EQGRP_RC5_RC6_Opcode {
	meta:
		description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
		date = "2016-08-17"
		id = "b12a1a2c-8d32-5318-a658-6aa1a08c3263"
	strings:
		/*
			mov     esi, [ecx+edx*4-4]
			sub     esi, 61C88647h
			mov     [ecx+edx*4], esi
			inc     edx
			cmp     edx, 2Bh
		*/
		$s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }
	condition:
		1 of them
}

rule EquationGroup_modifyAudit_Lp {
   meta:
      description = "EquationGroup Malware - file modifyAudit_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
      id = "9dcfa774-0048-5bd9-ba7d-87bbdff9567a"
   strings:
      $s1 = "Read of audit related process memory failed" fullword wide
      $s2 = "** This may indicate that another copy of modify_audit is already running **" fullword wide
      $s3 = "Pattern match of code failed" fullword wide
      $s4 = "Base for necessary auditing dll not found" fullword wide
      $s5 = "Security auditing has been disabled" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them ) or ( all of them )
}

rule EquationGroup_ProcessHide_Lp {
   meta:
      description = "EquationGroup Malware - file ProcessHide_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"
      id = "b0842897-f591-5213-9a26-0f8732e6f3b8"
   strings:
      $x1 = "Invalid flag.  Can only hide or unhide" fullword wide
      $x2 = "Process elevation failed" fullword wide
      $x3 = "Unknown error hiding process" fullword wide
      $x4 = "Invalid process links found in EPROCESS" fullword wide
      $x5 = "Unable to find SYSTEM process" fullword wide
      $x6 = "Process hidden, but EPROCESS location lost" fullword wide
      $x7 = "Invalid EPROCESS location for given ID" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 3 of them )
}

rule EquationGroup_pwdump_Implant {
   meta:
      description = "EquationGroup Malware - file pwdump_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "dfd5768a4825d1c7329c2e262fde27e2b3d9c810653585b058fcf9efa9815964"
      id = "55984c20-539e-5e51-b3c4-caa6157c993d"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s8 = ".?AVFeFinallySuccess@@" fullword ascii
      $s3 = "\\system32\\win32k.sys" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_LSADUMP_Lp {
   meta:
      description = "EquationGroup Malware - file LSADUMP_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
      id = "8068ca41-6365-5c97-82f2-be9ad89628e0"
   strings:
      $x1 = "LSADUMP - - ERROR - - Injected" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule EquationGroup_nethide_Lp {
   meta:
      description = "EquationGroup Malware - file nethide_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "137749c0fbb8c12d1a650f0bfc73be2739ff084165d02e4cb68c6496d828bf1d"
      id = "39e96239-2189-5993-90ba-27e47f7bfdea"
   strings:
      $x1 = "Error: Attempt to hide all TCP connections (any:any)." fullword wide
      $x2 = "privilegeRunInKernelMode failed" fullword wide
      $x3 = "Failed to unhide requested connection" fullword wide
      $x4 = "Nethide running in USER_MODE" fullword wide
      $x5 = "Not enough slots for all of the list.  Some entries may have not been hidden." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( all of them )
}

rule EquationGroup_processinfo_Implant {
   meta:
      description = "EquationGroup Malware - file processinfo_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "aadfa0b1aec4456b10e4fb82f5cfa918dbf4e87d19a02bcc576ac499dda0fb68"
      id = "b110d819-2298-507b-91bb-2787bb11322e"
   strings:
      $s1 = "hZwOpenProcessToken" fullword ascii
      $s2 = "hNtQueryInformationProcess" fullword ascii
      $s3 = "No mapping" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_2 {
   meta:
      description = "EquationGroup Malware - file PortMap_Implant.dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "964762416840738b1235ed4ae479a4b117b8cdcc762a6737e83bc2062c0cf236"
      id = "662ee1cf-b837-5362-84a8-1af7335d5e1b"
   strings:
      $op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
      $op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
      $op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 250KB and all of them )
}

rule EquationGroup_nethide_Implant {
   meta:
      description = "EquationGroup Malware - file nethide_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
	  modified = "2023-01-27"
      hash1 = "b2daf9058fdc5e2affd5a409aebb90343ddde4239331d3de8edabeafdb3a48fa"
      id = "36559b69-1718-5d9b-8d6f-3db4becba0c4"
   strings:
      $s1 = "\\\\.\\dlcndi" fullword ascii
      $s2 = "s\\drivers\\" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_4 {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "227faeb770ba538fb85692b3dfcd00f76a0a5205d1594bd0969a1e535ee90ee1"
      id = "e3fc376b-f7cc-5dfa-bcf4-4991962a4cf9"
   strings:
      $op1 = { 11 8b da 23 df 8d 1c 9e c1 fb 02 33 da 23 df 33 }
      $op2 = { c3 0c 57 8b 3b eb 27 8b f7 83 7e 08 00 8b 3f 74 }
      $op3 = { 00 0f b7 5e 14 8d 5c 33 18 8b c3 2b 45 08 50 ff }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EquationDrug_msgkd {
   meta:
      description = "EquationGroup Malware - file msgkd.ex_"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
      id = "41019119-9bf4-5a45-b74b-f75ab7738821"
   strings:
      $s1 = "KEysud" fullword ascii
      $s2 = "XWWWPWS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_RunAsChild_Lp {
   meta:
      description = "EquationGroup Malware - file RunAsChild_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
      id = "f0623c3f-3a49-5cdf-89ea-2b3273fd8324"
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Unable to open parent process" fullword wide
      $s4 = "Invalid input to lpRunAsChildPPC" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_3 {
   meta:
      description = "EquationGroup Malware - file mssld.dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "69dcc150468f7707cc8ef618a4cea4643a817171babfba9290395ada9611c63c"
      id = "f664ad78-1820-5434-94cc-94f98b32e654"
   strings:
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule EquationGroup_GetAdmin_Lp {
   meta:
      description = "EquationGroup Malware - file GetAdmin_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"
      id = "3bbe0553-a5a3-5207-a94e-ad978606d9a4"
   strings:
      $x1 = "Current user is System -- unable to join administrators group" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_ModifyGroup_Lp {
   meta:
      description = "EquationGroup Malware - file ModifyGroup_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"
      id = "82c9617a-3d78-525f-a507-76c87aad7c59"
   strings:
      $s1 = "Modify Privileges failed" fullword wide
      $s2 = "Given privilege name not found" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_pwdump_Lp {
   meta:
      description = "EquationGroup Malware - file pwdump_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"
      id = "6f356f13-9ec1-5dd9-91b2-6a3071398e81"
   strings:
      $x1 = "PWDUMP - - ERROR - -" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EventLogEdit_Implant {
   meta:
      description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"
      id = "40239dd0-4159-5c10-96b3-4f1e28c92d97"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
      $s2 = "Ntdll.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_PortMap_Lp {
   meta:
      description = "EquationGroup Malware - file PortMap_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
      id = "e1851a17-9858-5c93-9993-2da0559e5d2e"
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Portmap ended due to max number of ports" fullword wide
      $s3 = "Invalid parameters received for portmap" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}

rule EquationGroup_ProcessOptions_Lp {
   meta:
      description = "EquationGroup Malware - file ProcessOptions_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
      id = "5ccb9751-fbcc-538c-8d55-dfc495067ce5"
   strings:
      $s1 = "Invalid parameter received by implant" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_PassFreely_Lp {
   meta:
      description = "EquationGroup Malware - file PassFreely_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "fe42139748c8e9ba27a812466d9395b3a0818b0cd7b41d6769cb7239e57219fb"
      id = "5fb99194-f0df-54aa-9f20-7f8458155e62"
   strings:
      $s1 = "Unexpected value in memory.  Run the 'CheckOracle' or 'memcheck' command to identify the problem" fullword wide
      $s2 = "Oracle process memory successfully modified!" fullword wide
      $s3 = "Unable to reset the memory protection mask to the memory" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}