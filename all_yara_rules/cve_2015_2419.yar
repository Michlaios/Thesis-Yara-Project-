rule Exploit_CVE_2015_2419
{
    strings:
        $s1 = "MOV [ECX+0C],EAX" nocase ascii wide
        $s2 = "\"lIll\":\"kernel32" nocase ascii wide
        $s3 = "\"lIlll\":\"virtualprotect" nocase ascii wide
        $s4 = "prototype" nocase ascii wide
        $s5 = "stringify" nocase ascii wide
    condition:
        all of ($s*)
}