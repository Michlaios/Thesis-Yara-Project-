rule MAL_ELF_LNX_Mirai_Oct10_2 {
   meta:
      description = "Detects ELF malware Mirai related"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-10-27"
      hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
      id = "421b7708-030e-50d1-bf2e-e91758a48c00"
   strings:
      $c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and all of them
}

rule MAL_Mirai_Nov19_1 {
   meta:
      description = "Detects Mirai malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/bad_packets/status/1194049104533282816"
      date = "2019-11-13"
      hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
      hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"
      id = "40edcb29-9e10-5b87-ba79-8e3f629829e5"
   strings:
      $s1 = "SERVZUXO" fullword ascii
      $s2 = "-loldongs" fullword ascii
      $s3 = "/dev/null" fullword ascii
      $s4 = "/bin/busybox" fullword ascii
      $sc1 = { 47 72 6F 75 70 73 3A 09 30 }
   condition:
      uint16(0) == 0x457f and filesize <= 100KB and 4 of them
}

rule MAL_ARM_LNX_Mirai_Mar13_2022 {
   meta:
      description = "Detects new ARM Mirai variant"
      author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
      date = "2022-03-16"
      hash1 = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"
      id = "54d8860e-fc45-5571-b68c-66590c67a705"
   strings:
      $str1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
      $str4 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
      $attck1 = "attack.c"
      $attck2 = "attacks.c"
      $attck3 = "anti_gdb_entry"
      $attck4 = "resolve_cnc_addr"
      $attck5 = "attack_gre_eth"
      $attck6 = "attack_udp_generic"
      $attck7 = "attack_get_opt_ip"
      $attck8 = "attack_icmpecho"
   condition:
      uint16(0) == 0x457f and ( 3 of ($str*) or 4 of ($attck*) )
}