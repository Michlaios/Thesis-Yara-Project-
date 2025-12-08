rule WildNeutron_Sample_1 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "2b5065a3d0e0b8252a987ef5f29d9e1935c5863f5718b83440e68dc53c21fa94"
		id = "7bcb407f-7f01-540a-852c-a37456270888"
	strings:
		$s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s8 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
		$s9 = "Key Usage" fullword ascii /* score: '12.00' */
		$s32 = "UPDATE_ID" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00' */
		$s37 = "id-at-commonName" fullword ascii /* score: '8.00' */
		$s38 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
		$s39 = "RSA-alt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00' */
		$s40 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule WildNeutron_Sample_5 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
		id = "0df63255-155d-56b9-b86b-491855983095"
	strings:
		$s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s4 = "sha-1WithRSAEncryption" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s5 = "Postal code" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00' */
		$s6 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
		$s7 = "Key Usage" fullword ascii /* score: '12.00' */
		$s8 = "TLS-RSA-WITH-3DES-EDE-CBC-SHA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.00' */
		$s9 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule WildNeutron_Sample_7 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
		id = "22561c55-4294-50c9-a9b9-7b4ed98eec09"
	strings:
		$s0 = "checking match for '%s' user %s host %s addr %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00' */
		$s1 = "PEM_read_bio_PrivateKey failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s2 = "usage: %s [-ehR] [-f log_facility] [-l log_level] [-u umask]" fullword ascii /* score: '23.00' */
		$s3 = "%s %s for %s%.100s from %.200s port %d%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s4 = "clapi32.dll" fullword ascii /* score: '21.00' */
		$s5 = "Connection from %s port %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s6 = "/usr/etc/ssh_known_hosts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00' */
		$s7 = "Version: %s - %s %s %s %s" fullword ascii /* score: '16.00' */
		$s8 = "[-] connect()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.00' */
		$s9 = "/bin/sh /usr/etc/sshrc" fullword ascii /* score: '12.42' */
		$s10 = "kexecdhs.c" fullword ascii /* score: '12.00' */
		$s11 = "%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s" fullword ascii /* score: '11.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule HKTL_NativeCmd_subTee_Jul15 {
   meta:
      description = "NativeCmd - used by various threat groups"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10"
      modified = "2023-01-06"
      old_rule_name = "subTee_nativecmd"
      score = 40
      hash = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
   strings:
      $x2 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii 
      $x3 = "Error executing CreateProcess()!!" fullword wide 
      $x4 = "cmdcmdline" fullword wide
      $x5 = "Invalid input handle!!!" fullword ascii
      $s5 = "Usage: destination [reference]" fullword wide
      $s6 = ".com;.exe;.bat;.cmd" wide
      $s15 = "%-8s %-3s  %*s %s  %s" fullword wide
      $s16 = " %%%c in (%s) do " fullword wide
   condition:
      uint16(0) == 0x5a4d and ( 2 of ($x*) or 6 of ($s*) )
}

rule APT_MAL_WildNeutron_javacpl {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10"
      modified = "2023-01-06"
      old_rule_name = "WildNeutron_javacpl"
      score = 60
      hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
      hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
      hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
      id = "de82827e-61d4-559e-886a-78d5293ab141"
   strings:
      $s1 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" ascii fullword
      $s2 = "cmdcmdline" wide fullword
      $s3 = "\"%s\" /K %s" wide fullword
      $s4 = "Process is not running any more" wide fullword
      $s5 = "dpnxfsatz" wide fullword

      $op1 = { ff d6 50 ff 15 ?? ?? 43 00 8b f8 85 ff 74 34 83 64 24 0c 00 e8 ?? ?? 02 00 }
      $op2 = { b8 02 00 00 00 01 45 80 01 45 88 6a 00 47 52 89 7d 8c 03 d8 }
      $op3 = { 8b c7 f7 f6 46 89 b5 c8 fd ff ff 0f b7 c0 8b c8 0f af ce 3b cf }
   condition:
      uint16(0) == 0x5a4d and filesize < 5MB and (
         all of ($s*) or 
         all of ($op*)
      )
}