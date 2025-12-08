rule WannaCry_RansomNote {
   meta:
      description = "Detects WannaCry Ransomware Note"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
      id = "65ce8faf-0981-5382-bc15-f094ccaa9f54"
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition:
      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

rule APT_lazaruswannacry {
   meta:
      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
      id = "e9dd9750-2366-503a-a879-972dbead6bf3"
   strings:
      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75
         04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46
         56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00
         10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00
         30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00
         38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00
         44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00
         68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00
         FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0
         08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0
         10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0
         2B C0 2C C0 FF FE }
   condition:
      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}