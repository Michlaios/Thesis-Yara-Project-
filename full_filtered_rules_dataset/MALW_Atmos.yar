rule Atmos_Packed_Malware 
{
   
    meta:
    description = "Second Generic Spyware.Citadel.Atmos signture when builder add a packed layer"
    author = "xylitol@temari.fr"
    reference = "http://www.xylibox.com/2016/02/citadel-0011-atmos.html"
    date = "20/08/2016"
    // May only the challenge guide you

    strings:
        $MZ = {4D 5A}
        // Entry point identifier with CreateThread pointer in '??' 
        $a = {55 8B EC 83 EC 0C 53 56 8B 35 ?? ?? ?? 00 57 33 DB BF 00 28 00 00}
        // End of main proc with sleep value in '??' and api call to sleep in '??'
        $b = {68 ?? ?? ?? ?? FF 15 ?? ?? ?? 00 E9 62 FF FF FF E8 69 10 FE FF 5F 5E 5B C9 C3}
        // API String identifier (ShellExecuteExW, SHELL32.dll, GetUserNameExW, Secur32.dll)
        $c = {53 68 65 6C 6C 45 78 65 63 75 74 65 45 78 57 00 53 48 45 4C 4C 33 32 2E 64 6C 6C 00 1E 00 47 65}
        $d = {74 55 73 65 72 4E 61 6D 65 45 78 57 00 00 53 65 63 75 72 33 32 2E 64 6C 6C 00 10 00}
        // New Thread identifier
        $e = {55 8B EC 83 E4 F8 83 EC 1C 83 7D 08 00 57 74 ?? 6A FF FF 75 08 FF 15 ?? ?? ?? 00}

    condition:
    all of them and filesize < 300KB // Standard size (raw from builder) should be arround ~264kb
        // Remove the above line if you want to trig also on memory dumps, etc...
}