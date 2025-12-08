rule apt_hellsing_proxytool { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing proxy testing tool"
		id = "54454f07-11a9-5456-b489-9a9610e53123"
	strings: 
		$a1 = "PROXY_INFO: automatic proxy url => %s"
		$a2 = "PROXY_INFO: connection type => %d"
		$a3 = "PROXY_INFO: proxy server => %s"
		$a4 = "PROXY_INFO: bypass list => %s"
		$a5 = "InternetQueryOption failed with GetLastError() %d"
		$a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase
	condition:
		uint16(0) == 0x5a4d and (2 of ($a*)) and filesize < 300000
}

rule apt_hellsing_xkat { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab" copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xKat tool"
		id = "c831ce04-8fb2-5790-8aaf-c88b370835ac"
	strings: 
		$a1 = "\\Dbgv.sys" $a2="XKAT_BIN" $a3="release sys file error."
		$a4 = "driver_load error. "
		$a5 = "driver_create error."
		$a6 = "delete file:%s error." 
		$a7 = "delete file:%s ok."
		$a8 = "kill pid:%d error."
		$a9 = "kill pid:%d ok."
		$a10 = "-pid-delete"
		$a11 = "kill and delete pid:%d error."
		$a12 = "kill and delete pid:%d ok."
	condition:
		uint16(0) == 0x5a4d and (6 of ($a*)) and filesize < 300000
}