rule OpCloudHopper_Malware_3 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "c21eaadf9ffc62ca4673e27e06c16447f103c0cf7acd8db6ac5c8bd17805e39d"
      id = "ad1d3b48-d48c-5011-ac51-c8047e1ee8ed"
   strings:
      $s6 = "operator \"\" " fullword ascii
      $s7 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s11 = "InvokeMainViaCRT" fullword ascii
      $s12 = ".?AVAES@@" fullword ascii

      $op1 = { b6 4c 06 f5 32 cf 88 4c 06 05 0f b6 4c 06 f9 32 }
      $op2 = { 06 fc eb 03 8a 5e f0 85 c0 74 05 8a 0c 06 eb 03 }
      $op3 = { 7e f8 85 c0 74 06 8a 74 06 08 eb 03 8a 76 fc 85 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( all of ($s*) and 1 of ($op*) ) or all of ($op*) ) or ( 5 of them )
}

rule OpCloudHopper_Malware_4 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      modified = "2023-01-06"
      hash1 = "ae6b45a92384f6e43672e617c53a44225e2944d66c1ffb074694526386074145"
      id = "ebc810e6-f549-5401-9ee9-331888eda127"
   strings:
      $s6 = "operator \"\" " fullword ascii
      $s9 = "InvokeMainViaCRT" fullword ascii
      $s10 = ".?AVAES@@" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and all of them )
}

rule OpCloudHopper_Malware_7 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "44a7bea8a08f4c2feb74c6a00ff1114ba251f3dc6922ea5ffab9e749c98cbdce"
      id = "8d32e379-c902-5330-84f5-693a7649a2e4"
   strings:
      $x1 = "jepsjepsjepsjepsjepsjepsjepsjepsjepsjeps" fullword ascii
      $x2 = "extOextOextOextO" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule OpCloudHopper_Malware_8 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "19aa5019f3c00211182b2a80dd9675721dac7cfb31d174436d3b8ec9f97d898b"
      hash2 = "5cebc133ae3b6afee27beb7d3cdb5f3d675c3f12b7204531f453e99acdaa87b1"
      id = "5e0a09e3-732a-5a90-9d4a-11eae2aa4cc4"
   strings:
      $s1 = "WSHELL32.dll" fullword wide
      $s2 = "operator \"\" " fullword ascii
      $s3 = "\" /t REG_SZ /d \"" fullword wide
      $s4 = " /f /v \"" fullword wide
      $s5 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s6 = "AFX_DIALOG_LAYOUT" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and 4 of them )
}

rule OpCloudHopper_Malware_9 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "f0002b912135bcee83f901715002514fdc89b5b8ed7585e07e482331e4a56c06"
      id = "5a02f2ac-905d-550a-bde0-cfde6ed1a4ab"
   strings:
      $s1 = "MsMpEng.exe" fullword ascii
      $op0 = { 2b c7 50 e8 22 83 ff ff ff b6 c0 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule OpCloudHopper_Malware_10 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "5b4028728d8011a2003b7ce6b9ec663dd6a60b7adcc20e2125da318e2d9e13f4"
      id = "a5d3237e-d6db-54ba-bfa6-f642f8096819"
   strings:
      $x1 = "bakshell.EXE" fullword wide
      $s19 = "bakshell Applicazione MFC" fullword wide
      $op0 = { 83 c4 34 c3 57 8b ce e8 92 18 00 00 68 20 70 40 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule OpCloudHopper_Malware_11 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "a80f6c57f772f20d63021c8971a280c19e8eafe7cc7088344c598d84026dda15"
      id = "18bd2fa9-7eca-5dbc-8e79-953800d5bb0a"
   strings:
      $x1 = "IOGVWDWCXZVRHTE" fullword ascii

      $op1 = { c9 c3 56 6a 00 8b f1 6a 64 e8 dd 34 00 00 c7 06 } /* Opcode */
      $op2 = { 68 38 00 41 00 68 34 00 41 00 e8 d3 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule VBS_WMIExec_Tool_Apr17_1 {
   meta:
      description = "Tools related to Operation Cloud Hopper"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "21bc328ed8ae81151e7537c27c0d6df6d47ba8909aebd61333e32155d01f3b11"
      id = "8175eb74-38f1-5d8f-a668-aa8e215b032e"
   strings:
      $x1 = "strNetUse = \"cmd.exe /c net use \\\\\" & host" fullword ascii
      $x2 = "localcmd = \"cmd.exe /c \" & command " ascii
      $x3 = "& \" > \" & TempFile & \" 2>&1\"  '2>&1 err" fullword ascii
      $x4 = "strExec = \"cmd.exe /c \" & cmd & \" >> \" & resultfile & \" 2>&1\"  '2>&1 err" fullword ascii
      $x5 = "TempFile = objShell.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\wmi.dll\"" fullword ascii

      $a1 = "WMIEXEC ERROR: Command -> " ascii
      $a2 = "WMIEXEC : Command result will output to" fullword ascii
      $a3 = "WMIEXEC : Target ->" fullword ascii
      $a4 = "WMIEXEC : Login -> OK" fullword ascii
      $a5 = "WMIEXEC : Process created. PID:" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them ) or 3 of them
}