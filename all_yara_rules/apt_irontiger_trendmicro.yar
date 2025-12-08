rule IronTiger_ChangePort_Toolkit_driversinstall
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Changeport Toolkit driverinstall"
		reference = "http://goo.gl/T5fSJC"
		id = "fde2728b-9a23-5f35-9727-0834a7b403da"
	strings:
		$str1 = "openmydoor" wide ascii
		$str2 = "Install service error" wide ascii
		$str3 = "start remove service" wide ascii
		$str4 = "NdisVersion" wide ascii
	condition:
		uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_EFH3_encoder
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger EFH3 Encoder"
		reference = "http://goo.gl/T5fSJC"
		id = "ec30782e-8fe9-5843-9db4-5a3c477b7f25"
	strings:
		$str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" wide ascii
		$str2 = "123.EXE 123.EFH" wide ascii
		$str3 = "ENCODER: b[i]: = " wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_HTTP_SOCKS_Proxy_soexe
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
		reference = "http://goo.gl/T5fSJC"
		id = "6ead3d61-c1e3-55d1-894e-ab57bcd09cde"
	strings:
		$str1 = "listen SOCKET error." wide ascii
		$str2 = "WSAAsyncSelect SOCKET error." wide ascii
		$str3 = "new SOCKETINFO error!" wide ascii
		$str4 = "Http/1.1 403 Forbidden" wide ascii
		$str5 = "Create SOCKET error." wide ascii
	condition:
		uint16(0) == 0x5a4d and (3 of ($str*))
}

rule IronTiger_NBDDos_Gh0stvariant_dropper
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
		reference = "http://goo.gl/T5fSJC"
		id = "3610b9e3-45f8-5a8d-8977-817160009818"
	strings:
		$str1 = "This service can't be stoped." wide ascii
		$str2 = "Provides support for media palyer" wide ascii
		$str4 = "CreaetProcess Error" wide ascii
		$bla1 = "Kill You" wide ascii
		$bla2 = "%4.2f GB" wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_PlugX_FastProxy
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX FastProxy"
		reference = "http://goo.gl/T5fSJC"
		id = "14e05823-6288-5f02-8060-add51084c446"
	strings:
		$str1 = "SAFEPROXY HTServerTimer Quit!" wide ascii
		$str2 = "Useage: %s pid" wide ascii
		$str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" wide ascii
		$str4 = "p0: port for listener" wide ascii
		$str5 = "\\users\\whg\\desktop\\plug\\" wide ascii
		$str6 = "[+Y] cwnd : %3d, fligth:" wide ascii
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_ReadPWD86
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - ReadPWD86"
		reference = "http://goo.gl/T5fSJC"
		id = "5db832be-4b8e-536f-8db7-a215a90284e2"
	strings:
		$str1 = "Fail To Load LSASRV" wide ascii
		$str2 = "Fail To Search LSASS Data" wide ascii
		$str3 = "User Principal" wide ascii
	condition:
		uint16(0) == 0x5a4d and (all of ($str*))
}

rule IronTiger_Ring_Gh0stvariant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Ring Gh0stvariant"
		reference = "http://goo.gl/T5fSJC"
		id = "6858550a-4000-581c-b270-370db8ed1c57"
	strings:
		$str1 = "RING RAT Exception" wide ascii
		$str2 = "(can not update server recently)!" wide ascii
		$str4 = "CreaetProcess Error" wide ascii
		$bla1 = "Sucess!" wide ascii
		$bla2 = "user canceled!" wide ascii
	condition:
		uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_wmiexec
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Tool - wmi.vbs detection"
		reference = "http://goo.gl/T5fSJC"
		id = "a3060f50-3594-5da9-98e2-6fa0087451f5"
	strings:
		$str1 = "Temp Result File , Change it to where you like" wide ascii
		$str2 = "wmiexec" wide ascii
		$str3 = "By. Twi1ight" wide ascii
		$str4 = "[both mode] ,delay TIME to read result" wide ascii
		$str5 = "such as nc.exe or Trojan" wide ascii
		$str6 = "+++shell mode+++" wide ascii
		$str7 = "win2008 fso has no privilege to delete file" wide ascii
	condition:
		2 of ($str*)
}