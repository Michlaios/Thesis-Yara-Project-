rule Havex_Trojan_PHP_Server
{
    meta:
        Author      = "Florian Roth"
        Date        = "2014/06/24"
        Description = "Detects the PHP server component of the Havex RAT"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"

    condition:
        all of them
}

rule SANS_ICS_Cybersecurity_Challenge_400_Havex_Memdump : memory
	{
	meta:
		description = "Detects Havex Windows process executable from memory dump"
		date = "2015-12-2"
		author = "Chris Sistrunk"
		hash = "8065674de8d79d1c0e7b3baf81246e7d"
	strings:
		$magic = { 4d 5a }	
	
	        $s1 = "~tracedscn.yls" fullword wide
		$s2 = "[!]Start" fullword wide
		$s3 = "[+]Get WSADATA" fullword wide
		$s4 = "[-]Can not get local ip" fullword wide
		$s5 = "[+]Local:" fullword wide
		$s6 = "[-]Threads number > Hosts number" fullword wide
		$s7 = "[-]Connection error" fullword wide
		
		$x1 = "bddd4e2b84fa2ad61eb065e7797270ff.exe" fullword wide
	condition:
	    $magic at 0 and ( 3 of ($s*) or $x1 )
}