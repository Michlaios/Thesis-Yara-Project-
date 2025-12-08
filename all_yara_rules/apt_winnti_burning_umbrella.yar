rule MAL_BurningUmbrella_Sample_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"
      id = "9f8a6831-172b-5310-9763-43657b79b91d"
   strings:
      $s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 }
      $s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 }
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and (
         pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and
         $s1 in (0..1024) and
         $s2 in (0..1024)
      )
}

rule MAL_BurningUmbrella_Sample_2 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
      id = "926b4a29-ce47-559b-94e3-1fabd90f3fbe"
   strings:
      $s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 }
      $s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 }
      $s3 = "ActiveX Manager" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      $s1 in (0..1024) and
      $s2 in (0..1024) and
      $s3
}

rule MAL_BurningUmbrella_Sample_3 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
      id = "b997822a-3f62-51b4-bd96-e780ffe60812"
   strings:
      $s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_8 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
      id = "1b89d5a1-1425-5cb7-b429-563769bc0943"
   strings:
      $s1 = "cmd /c open %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_17 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fa380dac35e16da01242e456f760a0e75c2ce9b68ff18cfc7cfdd16b2f4dec56"
      hash2 = "854b64155f9ceac806b49f3e352949cc292e5bc33f110d965cf81a93f78d2f07"
      hash3 = "1e462d8968e8b6e8784d7ecd1d60249b41cf600975d2a894f15433a7fdf07a0f"
      hash4 = "3cdc149e387ec4a64cce1191fc30b8588df4a2947d54127eae43955ce3d08a01"
      hash5 = "a026b11e15d4a81a449d20baf7cbd7b8602adc2644aa4bea1e55ff1f422c60e3"
      id = "d79d3f65-f27c-582b-9258-7c84dc7682a6"
   strings:
      $s1 = "syshell" fullword wide
      $s2 = "Normal.dotm" fullword ascii
      $s3 = "Microsoft Office Word" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule MAL_BurningUmbrella_Sample_20 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      modified = "2023-01-06"
      hash1 = "5c12379cd7ab3cb03dac354d0e850769873d45bb486c266a893c0daa452aa03c"
      hash2 = "172cd90fd9e31ba70e47f0cc76c07d53e512da4cbfd197772c179fe604b75369"
      hash3 = "1ce88e98c8b37ea68466657485f2c01010a4d4a88587ba0ae814f37680a2e7a8"
      id = "1a39a76a-31e2-5d6e-82cb-ea38d503b6a9"
   strings:
      $s1 = "Wordpad.Document.1\\shell\\open\\command\\" wide
      $s2 = "%s\\shell\\Open\\command" fullword wide
      $s3 = "expanding computer" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         pe.imphash() == "bac338bfe2685483c201e15eae4352d5" or
         2 of them
      )
}

rule MAL_BurningUmbrella_Sample_22 {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "fa116cf9410f1613003ca423ad6ca92657a61b8e9eda1b05caf4f30ca650aee5"
      id = "90c6cda9-95a0-5de7-b1cd-110c238d993d"
   strings:
      $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" ascii
      $s3 = "Content-Disposition: form-data; name=\"txt\"; filename=\"" fullword ascii
      $s4 = "Fail To Enum Service" fullword ascii
      $s5 = "Host Power ON Time" fullword ascii
      $s6 = "%d Hours %2d Minutes %2d Seconds " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}

rule MAL_Winnti_Sample_May18_1 {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
      id = "c2f3339e-269f-5a51-8db6-06e54a707b3a"
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and all of them
}