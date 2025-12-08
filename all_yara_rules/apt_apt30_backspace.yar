rule APT30_Sample_3 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "d0320144e65c9af0052f8dee0419e8deed91b61b"
		id = "62e81385-26f5-545d-92ff-6604ff4d0186"
	strings:
		$s5 = "Software\\Mic" ascii
		$s6 = "HHOSTR" ascii
		$s9 = "ThEugh" fullword ascii
		$s10 = "Moziea/" ascii
		$s12 = "%s%s(X-" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_4 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "75367d8b506031df5923c2d8d7f1b9f643a123cd"
		id = "e5c6afde-0ab5-54ed-8d18-5ad477a527d7"
	strings:
		$s0 = "GetStartupIn" ascii
		$s1 = "enMutex" ascii
		$s2 = "tpsvimi" ascii
		$s3 = "reateProcesy" ascii
		$s5 = "FreeLibr1y*S" ascii
		$s6 = "foAModuleHand" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_5 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "1a2dd2a0555dc746333e7c956c58f7c4cdbabd4b"
		id = "bdbebe44-7423-5793-8a42-4f9b70de2231"
	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
		$s3 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
		$s7 = "msmsgs" fullword wide
		$s10 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_7 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "868d1f4c106a08bd2e5af4f23139f0e0cd798fba"
		id = "612732d9-8df5-5388-b299-2da4f8118435"
	strings:
		$s0 = "datain" fullword ascii
		$s3 = "C:\\Prog" ascii
		$s4 = "$LDDATA$" ascii
		$s5 = "Maybe a Encrypted Flash" fullword ascii
		$s6 = "Jean-loup Gailly" ascii
		$s8 = "deflate 1.1.3 Copyright" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_B {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
		hash2 = "29395c528693b69233c1c12bef8a64b3"
		hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
		hash4 = "550459b31d8dabaad1923565b7e50242"
		hash5 = "65232a8d555d7c4f7bc0d7c5da08c593"
		hash6 = "853a20f5fc6d16202828df132c41a061"
		hash7 = "ed151602dea80f39173c2f7b1dd58e06"
		id = "df3b8896-7229-5b3b-ad2f-774b0cea167c"
	strings:
		$s2 = "Moziea/4.0" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_I {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "fe211c7a081c1dac46e3935f7c614549"
		hash2 = "8c9db773d387bf9b3f2b6a532e4c937c"
		id = "55046e1a-731a-5418-9a7a-4fe1611c77d0"
	strings:
		$s0 = "Copyright 2012 Google Inc. All rights reserved." fullword wide
		$s1 = "(Prxy%c-%s:%u)" fullword ascii
		$s2 = "Google Inc." fullword wide
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_9 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "442bf8690401a2087a340ce4a48151c39101652f"
		id = "bf24bb57-aff9-579c-b8a2-265a6d2a06d0"
	strings:
		$s0 = "\\Windo" ascii
		$s2 = "oHHOSTR" ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" ascii
		$s6 = "Ora\\%^" ascii
		$s7 = "\\Ohttp=r" ascii
		$s17 = "help32Snapshot0L" ascii
		$s18 = "TimUmoveH" ascii
		$s20 = "WideChc[lobalAl" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_10 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "eb518cda3c4f4e6938aaaee07f1f7db8ee91c901"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
		$s2 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
		$s3 = "!! Use Connect Method !!" fullword ascii
		$s4 = "(Prxy%c-%s:%u)" fullword ascii
		$s5 = "msmsgs" fullword wide
		$s18 = "(Prxy-No)" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_12 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b02b5720ff0f73f01eb2ba029a58b645c987c4bc"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
	strings:
		$s0 = "Richic" fullword ascii
		$s1 = "Accept: image/gif, */*" fullword ascii
		$s2 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
	condition:
		filesize < 250KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_15 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "7a8576804a2bbe4e5d05d1718f90b6a4332df027"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
	strings:
		$s0 = "\\Windo" ascii
		$s2 = "HHOSTR"  ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" fullword ascii
		$s17 = "help32Snapshot0L" fullword ascii
		$s18 = "TimUmoveH" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_A {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
		hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
		hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
		hash4 = "7c9a13f1fdd6452fb6d62067f958bfc5fec1d24e"
		hash5 = "5257ba027abe3a2cf397bfcae87b13ab9c1e9019"
		id = "6b851d94-d3bd-5c76-8fd0-adb42b3fab73"
	strings:
		$s5 = "WPVWhhiA" fullword ascii
		$s6 = "VPWVhhiA" fullword ascii
		$s11 = "VPhhiA" fullword ascii
		$s12 = "uUhXiA" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_G {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "1612b392d6145bfb0c43f8a48d78c75f"
		hash = "53f1358cbc298da96ec56e9a08851b4b"
		hash = "c2acc9fc9b0f050ec2103d3ba9cb11c0"
		hash = "f18be055fae2490221c926e2ad55ab11"
		id = "34269de3-4559-58a5-a621-0ad72857dc9e"
	strings:
		$s0 = "%s\\%s\\%s=%s" fullword ascii
		$s1 = "Copy File %s OK!" fullword ascii
		$s2 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
		$s4 = "open=%s" fullword ascii
		$s5 = "Maybe a Encrypted Flash Disk" fullword ascii
		$s12 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_19 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015/04/03"
      modified = "2023-01-06"
      score = 75
      hash = "cfa438449715b61bffa20130df8af778ef011e15"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
   strings:
      $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
      $s1 = "%s,Volume:%s,Type:%s,TotalSize:%uMB,FreeSize:%uMB" fullword ascii
      $s2 = "\\TEMP\\" ascii
      $s3 = "\\Temporary Internet Files\\" ascii
      $s5 = "%s TotalSize:%u Bytes" fullword ascii
      $s6 = "This Disk Maybe a Encrypted Flash Disk!" fullword ascii
      $s7 = "User:%-32s" fullword ascii
      $s8 = "\\Desktop\\" ascii
      $s9 = "%s.%u_%u" fullword ascii
      $s10 = "Nick:%-32s" fullword ascii
      $s11 = "E-mail:%-32s" fullword ascii
      $s13 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
      $s14 = "Type:%-8s" fullword ascii
   condition:
      filesize < 100KB and uint16(0) == 0x5A4D and 8 of them
}

rule APT30_Sample_20 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b1c37632e604a5d1f430c9351f87eb9e8ea911c0"
		id = "91246101-246b-5da9-9e55-7f361d1f6437"
	strings:
		$s0 = "dizhi.gif" fullword ascii
		$s2 = "Mozilla/u" ascii
		$s3 = "XicrosoftHaveAck" ascii
		$s4 = "flyeagles" ascii
		$s10 = "iexplore." ascii
		$s13 = "WindowsGV" fullword ascii
		$s16 = "CatePipe" fullword ascii
		$s17 = "'QWERTY:/webpage3" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_23 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "9865e24aadb4480bd3c182e50e0e53316546fc01"
		id = "9366dd34-9967-5b40-935e-4b0d8f2f5e9e"
	strings:
		$s0 = "hostid" ascii
		$s1 = "\\Window" ascii
		$s2 = "%u:%u%s" fullword ascii
		$s5 = "S2tware\\Mic" ascii
		$s6 = "la/4.0 (compa" ascii
		$s7 = "NameACKernel" fullword ascii
		$s12 = "ToWideChc[lo" fullword ascii
		$s14 = "help32SnapshotfL" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_24 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "572caa09f2b600daa941c60db1fc410bef8d1771"
		id = "aed2201d-b557-56ec-aa53-fff5b1e17dbd"
	strings:
		$s1 = "dizhi.gif" fullword ascii
		$s3 = "Mozilla/4.0" fullword ascii
		$s4 = "lyeagles" fullword ascii
		$s6 = "HHOSTR" ascii
		$s7 = "#MicrosoftHaveAck7" ascii
		$s8 = "iexplore." fullword ascii
		$s17 = "ModuleH" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_25 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "44a21c8b3147fabc668fee968b62783aa9d90351"
		id = "8b2f2ba2-e9cc-5b3c-8af9-4217d662bc3f"
	strings:
		$s1 = "C:\\WINDOWS" fullword ascii
		$s2 = "aragua" fullword ascii
		$s4 = "\\driver32\\7$" ascii
		$s8 = "System V" fullword ascii
		$s9 = "Compu~r" fullword ascii
		$s10 = "PROGRAM L" fullword ascii
		$s18 = "GPRTMAX" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_26 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "e26588113417bf68cb0c479638c9cd99a48e846d"
		id = "aa80a142-c8fc-504e-b475-e9838607bec6"
	strings:
		$s1 = "forcegue" fullword ascii
		$s3 = "Windows\\Cur" fullword ascii
		$s4 = "System Id" fullword ascii
		$s5 = "Software\\Mic" fullword ascii
		$s6 = "utiBy0ToWideCh&$a" fullword ascii
		$s10 = "ModuleH" fullword ascii
		$s15 = "PeekNamed6G" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_29 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "44492c53715d7c79895904543843a321491cb23a"
		id = "24334885-fcb4-5a13-82e8-c8465f97361e"
	strings:
		$s0 = "LSSAS.exe" fullword ascii
		$s1 = "Software\\Microsoft\\FlashDiskInf" fullword ascii
		$s2 = ".petite" fullword ascii
		$s3 = "MicrosoftFlashExit" fullword ascii
		$s4 = "MicrosoftFlashHaveExit" fullword ascii
		$s5 = "MicrosoftFlashHaveAck" fullword ascii
		$s6 = "\\driver32" ascii
		$s7 = "MicrosoftFlashZJ" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_31 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "8b4271167655787be1988574446125eae5043aca"
		id = "9333870b-7eaa-54dd-a801-7292708fb592"
	strings:
		$s0 = "\\ZJRsv.tem" ascii
		$s1 = "forceguest" fullword ascii
		$s4 = "\\$NtUninstallKB570317$" ascii
		$s8 = "[Can'tGetIP]" fullword ascii
		$s14 = "QWERTY:,`/" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Microfost {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "57169cb4b8ef7a0d7ebd7aa039d1a1efd6eb639e"
		id = "19231001-1da3-5be6-8275-03c9fc7c6377"
	strings:
		$s1 = "Copyright (c) 2007 Microfost All Rights Reserved" fullword wide
		$s2 = "Microfost" fullword wide
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Generic_K {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015/04/03"
      modified = "2023-01-06"
      score = 75
      hash = "142bc01ad412799a7f9ffed994069fecbd5a2f93"
      id = "49629825-4233-5d74-b763-b2500536eb90"
   strings:
      $x1 = "Maybe a Encrypted Flash" fullword ascii

      $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
      $s1 = "\\TEMP\\" ascii
      $s2 = "\\Temporary Internet Files\\" ascii
      $s5 = "%s Size:%u Bytes" fullword ascii
      $s7 = "$.DATA$" fullword ascii
      $s10 = "? Size:%u By s" fullword ascii
      $s12 = "Maybe a Encrypted Flash" fullword ascii
      $s14 = "Name:%-32s" fullword ascii
      $s15 = "NickName:%-32s" fullword ascii
      $s19 = "Email:%-32s" fullword ascii
      $s21 = "C:\\Prog" ascii
      $s22 = "$LDDATA$" ascii
      $s31 = "Copy File %s OK!" fullword ascii
      $s32 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
      $s34 = "open=%s" fullword ascii
   condition:
      filesize < 100KB and uint16(0) == 0x5A4D and ( all of ($x*) and 3 of ($s*) )
}

rule APT30_Sample_35 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "df48a7cd6c4a8f78f5847bad3776abc0458499a6"
		id = "8a30720b-06da-5a82-8bab-bf06121afd68"
	strings:
		$s0 = "WhBoyIEXPLORE.EXE.exe" fullword ascii
		$s5 = "Startup>A" fullword ascii
		$s18 = "olhelp32Snapshot" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}

rule APT30_Sample_1 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "8cea83299af8f5ec6c278247e649c9d91d4cf3bc"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
	strings:
		$s0 = "#hostid" fullword ascii
		$s1 = "\\Windows\\C" ascii
		$s5 = "TimUmove" fullword ascii
		$s6 = "Moziea/4.0 (c" fullword ascii
		$s7 = "StartupNA" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}