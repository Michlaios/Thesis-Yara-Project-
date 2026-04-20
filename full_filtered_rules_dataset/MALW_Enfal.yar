rule EnfalCode : Enfal Family 
{
    meta:
        description = "Enfal code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
        $decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }
        
    condition:
        any of them
}

rule ce_enfal_cmstar_debug_msg
{
    meta:
        Author      = "rfalcone"
        Date        = "2015.05.10"
        Description = "Detects the static debug strings within CMSTAR"
        Reference   = "http://researchcenter.paloaltonetworks.com/2015/05/cmstar-downloader-lurid-and-enfals-new-cousin"

    strings:
        $d1 = "EEE\x0d\x0a" fullword
        $d2 = "TKE\x0d\x0a" fullword
        $d3 = "VPE\x0d\x0a" fullword
        $d4 = "VPS\x0d\x0a" fullword
        $d5 = "WFSE\x0d\x0a" fullword
        $d6 = "WFSS\x0d\x0a" fullword
        $d7 = "CM**\x0d\x0a" fullword

    condition:
        uint16(0) == 0x5a4d and all of ($d*)
}