rule Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549: Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549
{
        meta:
                description = "Specific sample match for WannaCryptor"
                MD5 = "84c82835a5d21bbcf75a61706d8ab549"
                SHA1 = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
                SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
                INFO = "Looks for 'taskdl' and 'taskse' at known offsets"
 
        strings:
                $taskdl = { 00 74 61 73 6b 64 6c }
                $taskse = { 00 74 61 73 6b 73 65 }
 
        condition:
                $taskdl at 3419456 and $taskse at 3422953
}

rule Wanna_Sample_4da1f312a214c07143abeeafb695d904: Wanna_Sample_4da1f312a214c07143abeeafb695d904
{
        meta:
                description = "Specific sample match for WannaCryptor"
                MD5 = "4da1f312a214c07143abeeafb695d904"
                SHA1 = "b629f072c9241fd2451f1cbca2290197e72a8f5e"
                SHA256 = "aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c"
                INFO = "Looks for offsets of r.wry and s.wry instances"
 
        strings:
                $rwnry = { 72 2e 77 72 79 }
                $swnry = { 73 2e 77 72 79 }
 
        condition:
                $rwnry at 88195 and $swnry at 88656 and $rwnry at 4495639
}

rule NHS_Strain_Wanna: NHS_Strain_Wanna
{
        meta:
                description = "Detection for worm-strain bundle of Wcry, DOublePulsar"
                MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"
                SHA1 = "e889544aff85ffaf8b0d0da705105dee7c97fe26"
                SHA256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
                INFO = "Looks for specific offsets of c.wnry and t.wnry strings"
 
        strings:
                $cwnry = { 63 2e 77 6e 72 79 }
                $twnry = { 74 2e 77 6e 72 79 }
 
        condition:
                $cwnry at 262324 and $twnry at 267672 and $cwnry at 284970
}

rule Wanna_Cry_Ransomware_Generic {
       meta:
              description = "Detects WannaCry Ransomware on Disk and in Virtual Page"
              author = "US-CERT Code Analysis Team"
              reference = "not set"                                        
              date = "2017/05/12"
       hash0 = "4DA1F312A214C07143ABEEAFB695D904"
       strings:
              $s0 = {410044004D0049004E0024}
              $s1 = "WannaDecryptor"
              $s2 = "WANNACRY"
              $s3 = "Microsoft Enhanced RSA and AES Cryptographic"
              $s4 = "PKS"
              $s5 = "StartTask"
              $s6 = "wcry@123"
              $s7 = {2F6600002F72}
              $s8 = "unzip 0.15 Copyrigh"
              $s9 = "Global\\WINDOWS_TASKOSHT_MUTEX"        
              $s10 = "Global\\WINDOWS_TASKCST_MUTEX"   
             $s11 = {7461736B736368652E657865000000005461736B5374617274000000742E776E7279000069636163}
             $s12 = {6C73202E202F6772616E742045766572796F6E653A46202F54202F43202F5100617474726962202B68}
             $s13 = "WNcry@2ol7"
             $s14 = "wcry@123"
             $s15 = "Global\\MsWinZonesCacheCounterMutexA"
       condition:
              $s0 and $s1 and $s2 and $s3 or $s4 and $s5 and $s6 and $s7 or $s8 and $s9 and $s10 or $s11 and $s12 or $s13 or $s14 or $s15
}

rule WannaCry_RansomNote {
   meta:
      description = "Detects WannaCry Ransomware Note"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition:
      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

rule lazaruswannacry {
   meta:
      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
   strings:
      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75 04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46 56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00 44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00 68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00 FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0 08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0 10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0 2B C0 2C C0 FF FE }
   condition:
      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}