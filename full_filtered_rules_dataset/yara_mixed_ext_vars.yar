rule SCT_Scriptlet_in_Temp_Inet_Files {
	meta:
		description = "Detects a scriptlet file in the temporary Internet files (see regsvr32 AppLocker bypass)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/KAB8Jw"
		date = "2016-04-26"
		id = "8b729257-3676-59b2-961c-dae1085cbbf6"
	strings:
		$s1 = "<scriptlet>" fullword ascii nocase
		$s2 = "ActiveXObject(\"WScript.Shell\")" ascii
	condition:
		( uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) /* <?XM or <?xm */
		and $s1 and $s2
		and filepath contains "Temporary Internet Files"
}

rule GIFCloaked_Webshell_A {
   meta:
      description = "Looks like a webshell cloaked as GIF"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
      score = 60
      id = "4fdef65c-204a-5019-9b4f-c5877c3e39d4"
   strings:
      $s0 = "input type"
      $s1 = "<%eval request"
      $s2 = "<%eval(Request.Item["
      $s3 = "LANGUAGE='VBScript'"
      $s4 = "$_REQUEST" fullword
      $s5 = ";eval("
      $s6 = "base64_decode"

      $fp1 = "<form name=\"social_form\""
   condition:
      uint32(0) == 0x38464947 and ( 1 of ($s*) )
      and not 1 of ($fp*)
}

rule Exe_Cloaked_as_ThumbsDb
    {
    meta:
        description = "Detects an executable cloaked as thumbs.db - Malware"
        date = "2014-07-18"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 50
        id = "ff09f8cf-de5a-50fc-aa0b-c54f7667e246"
    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}

rule Fake_AdobeReader_EXE
    {
    meta:
      description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
      date = "2014-09-11"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      nodeepdive = 1
      nodeepdive = 1
      id = "e3dd9d94-9f4b-5ff9-bfec-29abfb3555bb"
    strings:
      $s1 = "Adobe Systems" ascii

      $fp1 = "Adobe Reader" ascii wide
      $fp2 = "Xenocode Virtual Appliance Runtime" ascii wide
    condition:
      uint16(0) == 0x5a4d and
      filename matches /AcroRd32.exe/i and
      not $s1 in (filesize-2500..filesize)
      and not 1 of ($fp*)
}

rule lsadump {
   meta:
      description      = "LSA dump programe (bootkey/syskey) - pwdump and others"
      author         = "Benjamin DELPY (gentilkiwi)"
      score         = 80
      nodeepdive = 1
      id = "3bfa8dd8-720d-5326-ac92-0fb96cf21219"
   strings:
      $str_sam_inc   = "\\Domains\\Account" ascii nocase
      $str_sam_exc   = "\\Domains\\Account\\Users\\Names\\" ascii nocase
      $hex_api_call   = {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
      $str_msv_lsa   = { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
      $hex_bkey      = { 4b 53 53 4d [20-70] 05 00 01 00}

      $fp1 = "Sysinternals" ascii
      $fp2 = "Apple Inc." ascii wide
      $fp3 = "Kaspersky Lab" ascii fullword
      $fp4 = "ESET Security" ascii
      $fp5 = "Disaster Recovery Module" wide
      $fp6 = "Bitdefender" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      (($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
      and not 1 of ($fp*)
      and not filename contains "Regdat"
      and not filetype == "EXE"
      and not filepath contains "Dr Watson"
      and not extension == "vbs"
}