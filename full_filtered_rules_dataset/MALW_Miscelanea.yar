rule tran_duy_linh
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.2"
	reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
	date = "01/03/2014"
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$string1 = "Tran Duy Linh" fullword
	$string2 = "DLC Corporation" fullword
condition:
    ($doc at 0) and (all of ($string*))
}

rule memory_pivy

{
   meta:
	  author = "https://github.com/jackcr/"
   strings:
      $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} // presence of pivy in memory

   condition: 
      any of them

}

rule memory_shylock

{
   meta:
	  author = "https://github.com/jackcr/"

   strings:
      $a = /pipe\\[A-F0-9]{32}/     //Named pipe created by the malware
      $b = /id=[A-F0-9]{32}/     //Portion or the uri beacon
      $c = /MASTER_[A-F0-9]{32}/     //Mutex created by the malware
      $d = "***Load injects by PIPE (%s)" //String found in binary
      $e = "***Load injects url=%s (%s)" //String found in binary
      $f = "*********************** Ping Ok ************************" //String found in binary
      $g = "*** LOG INJECTS *** %s"     //String found in binary

   condition: 
      any of them

}

rule LightFTP_fftp_x86_64 {
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 4 of them
}

rule LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide
	condition:
		uint16(0) == 0xfeff and filesize < 1KB and all of them
}

rule spyeye : banker
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y memory"
		date = "2012-05-23" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$spyeye = "SpyEye"
		$a = "%BOTNAME%"
		$b = "globplugins"
		$c = "data_inject"
		$d = "data_before"
		$e = "data_after"
		$f = "data_end"
		$g = "bot_version"
		$h = "bot_guid"
		$i = "TakeBotGuid"
		$j = "TakeGateToCollector"
		$k = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
		$l = "[ERROR] : Update is not successfull for some reason"
		$m = "[ERROR] : dwErr == %u"
		$n = "GRABBED DATA"
		
	condition:
		$spyeye or (any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k,$l,$m,$n))
}

rule callTogether_certificate
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the CallTogether certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $serial = { 45 21 56 C3 B3 FB 01 76 36 5B DB 5B 77 15 BC 4C }
        $o = "CallTogether, Inc."

    condition:
        $serial and $o
}

rule qti_certificate
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the QTI International Inc certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $cn = "QTI International Inc"
        $serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }

    condition:
        $cn and $serial
}

rule DownExecute_A
{
	meta:
        Author      = "PwC Cyber Threat Operations :: @tlansec"
        Date        = "2015/04/27"
        Description = "Malware is often wrapped/protected, best to run on memory"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2015/04/attacks-against-israeli-palestinian-interests.html"

    strings:
        $winver1 = "win 8.1"
        $winver2 = "win Server 2012 R2"
        $winver3 = "win Srv 2012"
        $winver4 = "win srv 2008 R2"
        $winver5 = "win srv 2008"
        $winver6 = "win vsta"
        $winver7 = "win srv 2003 R2"
        $winver8 = "win hm srv"
        $winver9 = "win Strg srv 2003"
        $winver10 = "win srv 2003"
        $winver11 = "win XP prof x64 edt"
        $winver12 = "win XP"
        $winver13 = "win 2000"

        $pdb1 = "D:\\Acms\\2\\docs\\Visual Studio 2013\\Projects\\DownloadExcute\\DownloadExcute\\Release\\DownExecute.pdb"
        $pdb2 = "d:\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\writer.h"
        $pdb3 = ":\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\internal/stack.h"
        $pdb4 = "\\downloadexcute\\downexecute\\"

        $magic1 = "<Win Get Version Info Name Error"
        $magic2 = "P@$sw0rd$nd"
        $magic3 = "$t@k0v2rF10w"
        $magic4 = "|*|123xXx(Mutex)xXx321|*|6-21-2014-03:06PM" wide

		$str1 = "Download Excute" ascii wide fullword
        $str2 = "EncryptorFunctionPointer %d"
        $str3 = "%s\\%s.lnk"
        $str4 = "Mac:%s-Cpu:%s-HD:%s"
        $str5 = "feed back responce of host"
        $str6 = "GET Token at host"
        $str7 = "dwn md5 err"

    condition:
        all of ($winver*) or any of ($pdb*) or any of ($magic*) or 2 of ($str*)
}

rule CVE_2015_1674_CNGSYS {
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		reference2 = "https://github.com/Neo23x0/Loki/blob/master/signatures/exploit_cve_2015_1674.yar"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
	strings:
		$s1 = "\\Device\\CNG" fullword wide
		
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule CredStealESY : For CredStealer
{
 meta:
description = "Generic Rule to detect the CredStealer Malware"
author = "IsecG – McAfee Labs"
date = "2015/05/08"
strings:
$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module
 condition:
$my_hex_string and $my_hex_string2
}