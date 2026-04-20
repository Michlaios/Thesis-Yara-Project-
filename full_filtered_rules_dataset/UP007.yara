rule dubseven_dropper_registry_checks
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for registry keys checked for by the dropper"
    
    strings:
        $reg1 = "SOFTWARE\\360Safe\\Liveup"
        $reg2 = "Software\\360safe"
        $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
        $reg4 = "SOFTWARE\\Avira\\Avira Destop"
        $reg5 = "SOFTWARE\\rising\\RAV"
        $reg6 = "SOFTWARE\\JiangMin"
        $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        all of ($reg*)
}

rule dubseven_dropper_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants. How rude."
    
    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        any of them
}

rule maindll_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches on the maindll mutex"
        
    strings:
        $mutex = "h31415927tttt"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}

rule SLServer_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants."
    
    strings:
        $slserver = "SLServer" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $slserver
}

rule SLServer_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the mutex."
    
    strings:
        $mutex = "M&GX^DSF&DA@F"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}

rule SLServer_campaign_code
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the related campaign code."
    
    strings:
        $campaign = "wthkdoc0106"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $campaign
}

rule SLServer_unknown_string
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for a unique string."
    
    strings:
        $string = "test-b7fa835a39"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $string
}