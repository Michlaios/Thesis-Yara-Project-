rule dump_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Related to pwdump6 and fgdump tools"
strings:
	$s1 = "lsremora"
	$s2 = "servpw"
	$s3 = "failed: %d"
	$s4 = "fgdump"
	$s5 = "fgexec"
	$s6 = "fgexecpipe"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule osql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "O/I SQL - SQL query tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "osql\\src"
	$s2 = "OSQLUSER"
	$s3 = "OSQLPASSWORD"
	$s4 = "OSQLSERVER"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule misc_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS Malware"
strings:
	$s1 = "KAPTOXA"
	$s2 = "cmd /c net start %s"
	$s3 = "pid:"
	$s4 = "%ADD%"
	$s5 = "COMSPEC"
	$s6 = "KARTOXA"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule regex_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Regex"
strings:
	$n1 = "REGEXEND" nocase
	$n2 = "RegExpr" nocase
	$n3 = "regex"
	$s4 = "[1-5][0-9]{14}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s5 = "[47][0-9]{13}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s6 = "(?:0[0-5]|[68][0-9])[0-9]{11}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s7 = "(?:011|5[0-9]{2})[0-9]{12}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s8 = "(?:2131|1800|35\\d{3})\\d{11}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s9 = "([0-9]{15,16}[D=](0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9]{8,30})"
	$s10 = "((b|B)[0-9]{13,19}\\^[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\^(0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9\\s]{3,50}[0-9]{1})"
	$s11 = "[0-9]*\\^[a-zA-Z]*/[a-zA-Z ]*\\^[0-9]*"
	$s12 = "\\d{15,19}=\\d{13,}"
	$s13 = "\\;?[3-9]{1}[0-9]{12,19}[D=\\u0061][0-9]{10,30}\\??"
	$s14 = "[0-9]{12}(?:[0-9]{3})?=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
condition:
	uint16(0) == 0x5A4D and 1 of ($n*) and 1 of ($s*)
}

rule regexpr_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "RegExpr" nocase
	$s2 = "Data.txt"
	$s3 = "Track1"
	$s4 = "Track2"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule reg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "T1_FOUND: %s"
	$s2 = "id=%s&log=%s"
	$s3 = "\\d{15,19}=\\d{13,}"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}

rule pstgdump
{
meta:
	author = "@patrickrolsen"
	reference = "pstgdump"
strings:
	$s1 = "fgdump\\pstgdump"
	$s2 = "pstgdump"
	$s3 = "Outlook"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule pos_jack
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
	version = "0.1"
	reference = "http://blog.spiderlabs.com/2014/02/jackpos-the-house-always-wins.html"
	date = "2/22/2014"
strings:
	$pdb1 = "\\ziedpirate.ziedpirate-PC\\"
	$pdb2 = "\\sop\\sop\\"
condition:
	uint16(0) == 0x5A4D and 1 of ($pdb*)
}

rule pos_memory_scrapper_
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware Memory Scraper"
	version = "0.3"
	description = "POS Memory Scraper"
	date = "01/30/2014"
strings:
	$s1 = "kartoxa" nocase
	$s2 = "CC2 region:"
	$s3 = "CC memregion:"
	$s4 = "target pid:"
	$s5 = "scan all processes:"
	$s6 = "<pid> <PATTERN>"
	$s7 = "KAPTOXA"
	$s8 = "ATTERN"
	$s9 = "\\svhst%p"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule pdb_strings_Rescator
{
meta:
	author = "@patrickrolsen"
	maltype = "Target Attack"
	version = "0.3"
	description = "Rescator PDB strings within binaries"
	date = "01/30/2014"
strings:
	$pdb1 = "\\Projects\\Rescator" nocase
condition:
	uint16(0) == 0x5A4D and $pdb1
}

rule pos_chewbacca
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "https://www.securelist.com/en/blog/208214185/ChewBacca_a_new_episode_of_Tor_based_Malware"
    hashes = "21f8b9d9a6fa3a0cd3a3f0644636bf09, 28bc48ac4a92bde15945afc0cee0bd54"
	version = "0.2"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "tor -f <torrc>"
	$s2 = "tor_"
	$s3 = "umemscan"
	$s4 = "CHEWBAC"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}