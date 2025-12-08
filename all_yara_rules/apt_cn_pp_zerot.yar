rule PP_CN_APT_ZeroT_6 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "a16078c6d09fcfc9d6ff7a91e39e6d72e2d6d6ab6080930e1e2169ec002b37d3"
      id = "2e3bb4bd-5e20-56e7-a82b-d717d83eaeeb"
   strings:
      $s1 = "jGetgQ|0h9=" fullword ascii
      $s2 = "\\sfxrar32\\Release\\sfxrar.pdb"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule CN_APT_ZeroT_extracted_Zlh {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT - file Zlh.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04"
      hash1 = "711f0a635bbd6bf1a2890855d0bd51dff79021db45673541972fe6e1288f5705"
      id = "4c8b9a90-6cb3-5aba-a993-f73207341d0e"
   strings:
      $s1 = "nflogger.dll" fullword wide
      $s2 = "%s %d: CreateProcess('%s', '%s') failed. Windows error code is 0x%08x" fullword ascii
      $s3 = "_StartZlhh(): Executed \"%s\"" ascii
      $s4 = "Executable: '%s' (%s) %i" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}