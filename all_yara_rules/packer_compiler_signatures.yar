rule IsPE32 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x010B
}

rule IsPE64 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x020B
}

rule IsDLL : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000

}

rule IsConsole : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0003
}

rule IsWindowsGUI : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0002
}

rule HasDigitalSignature : PECheck
{
	meta: 
		author="_pusher_"
		description = "DigitalSignature Check"
		date="2016-07"
	strings:		
		//size check is wildcarded
		$a0 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 68 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 5A 30 58 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
		$a1 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 ?? 30 ?? 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 ?? 03 01 00 A0 ?? A2 ?? 80 00 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
		$a2 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0E 30 ?? 06 ?? ?? 86 48 86 F7 0D 02 05 05 00 30 67 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 59 30 57 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 20 30 0C 06 08 2A 86 48 86 F7 0D 02 05 05 00 04 }
		$a3 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0F 30 ?? 06 ?? ?? 86 48 01 65 03 04 02 01 05 00 30 78 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 6A 30 68 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 }
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in ( (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)..filesize)) )
		//its not always like this:
		//and  uint32(@a0) == (filesize-(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size))
}

rule HasDebugData : PECheck
{
	meta: 
		author = "_pusher_"
		description = "DebugData Check"
		date="2016-07"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//orginal
		//((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
		//((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
		(IsPE32 or IsPE64) and
		((uint32(uint32(0x3C)+0xA8+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0) and (uint32be(uint32(0x3C)+0xAC+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0))
}

rule ExportTableIsBad : PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ExportTable Check"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 		//Export_Table_RVA+Export_Data_Size .. cannot be outside imagesize
		((uint32(uint32(0x3C)+0x78+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x7C+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))     > (uint32(uint32(0x3C)+0x50)) 
		)		
}

rule HasModified_DOS_Message : PECheck
{
	meta: 
		author = "_pusher_"
		description = "DOS Message Check"
		date="2016-07"
	strings:	
		$a0 = "This program must be run under Win32" wide ascii nocase
		$a1 = "This program cannot be run in DOS mode" wide ascii nocase
		//UniLink
		$a2 = "This program requires Win32" wide ascii nocase
		$a3 = "This program must be run under Win64" wide ascii nocase
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and not
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule HasRichSignature : PECheck
{
	meta: 
		author = "_pusher_"
		description = "Rich Signature Check"
		date="2016-07"
	strings:	
		$a0 = "Rich" ascii
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule IsGoLink
{
	meta:
		author="_pusher_"
		date = "2016-08"
		description="www.GoDevTool.com"
	strings:
		$a0 = { 47 6F 4C 69 6E 6B }
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		$a0 at 0x40

}

rule free_pascal {
	meta:
		author = "_pusher_"
		description = "Free Pascal"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { 55 89 E5 83 ?? ?? 89 5D FC B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 75 0C 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 }
		$c1 = { 55 89 E5 53 B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 75 0C 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? B8 }
		$c2 = { 55 89 E5 83 EC 04 89 5D FC B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 75 05 E8 ?? ?? ?? ?? C7 05 }
	condition:
		any of them
}

rule borland_delphi_dll {
	meta:
		author = "_pusher_"
		description = "Borland Delphi DLL"
		date = "2015-08"
		version = "0.1"
		info = "one is at entrypoint"
	strings:
		$c0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
		$c1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }
	condition:
		any of them
}

rule borland_component {
	meta:
		author = "_pusher_"
		description = "Borland Component"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { E9 ?? ?? ?? FF 8D 40 00 }
	condition:
		$c0 at pe.entry_point
}

rule PureBasicDLL : Neil Hodgson
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

condition:
		$a0 at pe.entry_point
}

rule PureBasic4xDLL : Neil Hodgson
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

condition:
		$a0 at pe.entry_point
}

rule MicrosoftVisualCV80
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 6A 14 68 [4] E8 [4] BB 94 00 00 00 53 6A 00 8B [5] FF D7 50 FF [5] 8B F0 85 F6 75 0A 6A 12 E8 [4] 59 EB 18 89 1E 56 FF [5] 56 85 C0 75 14 50 FF D7 50 FF [5] B8 }

condition:
		$a0 at pe.entry_point
}

rule AutoIt
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "www.autoitscript.com/site/autoit/"
	strings:		
		$aa0 = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." wide ascii nocase
		$aa1 = "AutoIt Error" wide ascii nocase
		$aa2 = "Missing right bracket ')' in expression." wide ascii nocase
		$aa3 = "Missing operator in expression." wide ascii nocase
		$aa4 = "Unbalanced brackets in expression." wide ascii nocase
		$aa5 = "Error parsing function call." wide ascii nocase
	
		$aa6 = ">>>AUTOIT NO CMDEXECUTE<<<" wide ascii nocase
		$aa7 = "#requireadmin" wide ascii nocase
		$aa8 = "#OnAutoItStartRegister" wide ascii nocase
		$aa9 = "#notrayicon" wide ascii nocase
		$aa10 = "Cannot parse #include" wide ascii nocase
	condition:
		5 of ($aa*)
}

rule masm32_tasm32
{
	meta:
		author = "PEiD"
		description = "MASM32 / TASM32"
		group = "20"
		function = "0"
	strings:
		$a0 = { 6A ?? E8 ?? ?? ?? ?? A3 }
	condition:
		$a0
}