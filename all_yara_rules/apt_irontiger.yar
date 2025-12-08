rule IronPanda_Webshell_JSP {
	meta:
		description = "Iron Panda Malware JSP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"
		id = "38125418-7867-5073-a731-4f1d64e07588"
	strings:
		$s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
		$s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
		$s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
	condition:
		filesize < 330KB and 1 of them
}

rule IronPanda_Malware_Htran {
	meta:
		description = "Iron Panda Malware Htran"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "7903f94730a8508e9b272b3b56899b49736740cea5037ea7dbb4e690bcaf00e7"
		id = "7215f0da-9367-59b4-a78b-aeeebc4f2b69"
	strings:
		$s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
		$s2 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s3 = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s4 = "[-] ERROR: Must supply logfile name." fullword ascii
		$s5 = "[SERVER]connection to %s:%d error" fullword ascii
		$s6 = "[+] Make a Connection to %s:%d...." fullword ascii
		$s7 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s8 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s9 = "[+] Make a Connection to %s:%d ......" fullword ascii
		$s10 = "cmshared_get_ptr_from_atom" fullword ascii
		$s11 = "_cmshared_get_ptr_from_atom" ascii
		$s12 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s13 = "[-] TransmitPort invalid." fullword ascii
		$s14 = "[+] Waiting for Client on port:%d ......" fullword ascii
	condition:
		 ( uint16(0) == 0x5a4d and filesize < 125KB and 3 of them ) 
		 or 
		 5 of them
}