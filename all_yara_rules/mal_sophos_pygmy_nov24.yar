rule MAL_EarthWorm_Socks_Proxy_ID_Generation {
   meta:
      description = "Detects EarthWorm - a reverse socks proxy used by the threat group that deployed Pygmy Goat malware on Sophos XG firewall devices. The detection is based on the pool num generation x86 assembly."
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/pygmy-goat/ncsc-mar-pygmy-goat.pdf"
      author = "NCSC"
      date = "2024-10-22"
      score = 75
      hash1 = "71f70d61af00542b2e9ad64abd2dda7e437536ff"
      id = "242777e4-3abb-50d8-8c45-746cc4a8b1f8"
   strings:
      $chartoi = {
         8b 45 ?? // MOV EAX,dword ptr [EBP + ??]
         c1 e0 07 // SHL EAX,0x7
         89 c1 // MOV ECX,EAX
         8b 55 ?? // MOV EDX,dword ptr [EBP + ??]
         8b 45 ?? // MOV EAX,dword ptr [EBP + ??]
         01 d0 // ADD EAX,EDX
         0f b6 00 // MOVZX EAX,byte ptr [EAX]
         0f be c0 // MOVSX EAX,AL
         01 c8 // ADD EAX,ECX
         89 45 ?? // MOV dword ptr [EBP + ??],EAX
         83 6d ?? 01 // SUB dword ptr [EBP + ??],0x1
      }
   condition:
      uint32(0) == 0x464c457f and all of them
}