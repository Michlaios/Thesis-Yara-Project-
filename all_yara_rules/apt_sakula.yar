rule malware_sakula_xorloop {
  meta:
    description = "XOR loops from Sakula malware"
    author = "David Cannings"
    md5 = "fc6497fe708dbda9355139721b6181e7"
    date = "2016-06-13"
    modified = "2023-01-27"
    id = "9349b7e4-560c-5d8b-94d9-cbb9fd09e132"
  strings:
    // XOR decode loop (non-null, non-key byte only)
    $opcodes_decode_loop01 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }

    // XOR decode
    $opcodes_decode_loop02 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }

  condition:
    uint16(0) == 0x5A4D and any of ($opcodes*)
}

rule malware_sakula_shellcode {
  meta:
    description = "Sakula shellcode - taken from decoded setup.msi but may not be unique enough to identify Sakula"
    author = "David Cannings"

    id = "147e4894-7877-5367-9f6b-588eb7f0379a"
  strings:
    /*
      55                      push    ebp
      89 E5                   mov     ebp, esp
      E8 00 00 00 00          call    $+5
      58                      pop     eax
      83 C0 06                add     eax, 6
      C9                      leave
      C3                      retn
    */
    // Get EIP technique (may not be unique enough to identify Sakula)
    // Note this only appears in memory or decoded files
    $opcodes01 = { 55 89 E5 E8 00 00 00 00 58 83 C0 06 C9 C3 }

    /*
      8B 5E 3C                mov     ebx, [esi+3Ch]  ; Offset to PE header
      8B 5C 1E 78             mov     ebx, [esi+ebx+78h] ; Length of headers
      8B 4C 1E 20             mov     ecx, [esi+ebx+20h] ; Number of data directories
      53                      push    ebx
      8B 5C 1E 24             mov     ebx, [esi+ebx+24h] ; Export table
      01 F3                   add     ebx, esi
    */
    // Export parser
    $opcodes02 = { 8B 5E 3C 8B 5C 1E 78 8B 4C 1E 20 53 8B 5C 1E 24 01 F3 }

  condition:
    any of them
}