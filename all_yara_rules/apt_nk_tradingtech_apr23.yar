rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23 {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      score = 85
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      id = "74c403ea-3178-58e8-88b3-a51c1d475868"
    strings:
      $op1 = {B8 AB AA AA AA F7 E1 8B C1 C1 EA 02 8D 14 52 03 D2 2B C2 8A 84 05 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ??} /* xor decryption*/ 
      $op2 = { 50 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 3C 00 00 00 C7 85 ?? ?? ?? ?? 40 00 00 00 C7 85 ?? ?? ?? ?? 05 00 00 00 FF 15} /* shellexecute*/
      $op3 = { 6A 00 8D 85 ?? ?? ?? ?? 50 6A 04 8D 85 ?? ?? ?? ?? 50 57 FF 15 } /* read file*/
    condition:
      uint16(0) == 0x5a4d and all of them
}

rule SUSP_APT_MAL_VEILEDSIGNAL_Backdoor_Apr23 {
   meta:
      description = "Detects marker found in VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      modified = "2023-04-21"
      score = 75
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      id = "8f0d92b6-d9b0-55e3-b2ca-601d095f5279"
   strings:
      $opb1 = { 81 BD ?? ?? ?? ?? 5E DA F3 76} /* marker */
      $opb2 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA 66 C7 85 ?? ?? ?? ?? E5 CF} /* 1st xor key*/
      $opb3 = { C7 85 ?? ?? ?? ?? 74 F2 39 DA B9 00 04 00 00 66 C7 85 ?? ?? ?? ?? E5 CF } /* 2nd xor key*/
   condition:
      2 of them
}

rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "404b09def6054a281b41d309d809a428" 
      hash2 = "c6441c961dcad0fe127514a918eaabd4"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "379e6471-3c4f-5c72-b8fd-17f481e89ac6"
   strings:
      $sb1 = { FF 15 FC 76 01 00 8B F0 85 C0 74 ?? 8D 50 01 [6-16] FF 15 [4] 48 8B D8 48 85 C0 74 ?? 89 ?? 24 28 44 8B CD 4C 8B C? 48 89 44 24 20 }

rule is meant for hunting and is not tested to run in a production environment"
      hash1 = "6727284586ecf528240be21bb6e97f88"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      id = "7d0718fc-4f1c-5293-8dc4-81a5783fbfb2"
   strings:
      $sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }