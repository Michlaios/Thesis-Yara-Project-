rule SUSP_EXPL_Cleo_Exploitation_Log_Indicators_Dec24_2 {
   meta:
      author = "X__Junior"
      description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "d215d4a0-1726-58d4-90df-8ec6102effe1"
   strings:
      $sa1 = "<Thread type=\"AutoRun\" action=" ascii
      $sa2 = "<Mark date=" ascii
      $sa3 = "<Event>" ascii
      $sa4 = "<Command text" ascii

      $sb1 = "wscript" ascii
      $sb2 = "cscript" ascii
      $sb3 = "mshta" ascii
      $sb4 = "certutil" ascii
      $sb5 = "pwsh" ascii
      $sb6 = "curl" ascii
      $sb7 = "msiexec" ascii
      $sb8 = "taskkill" ascii
      $sb9 = "regsvr32" ascii
      $sb10 = "rundll32" ascii
      $sb11 = "bitsadmin" ascii
      $sb12 = "whoami" ascii
      $sb13 = "bcdedit" ascii
      $sb14 = "systeminfo" ascii
      $sb15 = "reg " ascii
      $sb16 = "schtasks" ascii
      // $sb17 = "query" ascii
   condition:
      filesize < 1MB
      and all of ($sa*)
      and 1 of ($sb*)
}

rule SUSP_EXPL_Cleo_Exploitation_XML_Indicators_Dec24_2 {
   meta:
      author = "X__Junior"
      description = "Detects XML used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "a71c71f3-d36f-5c27-b150-e678bccf2dba"
   strings:
      $sa1 = "<Action actiontype=\"Commands\"" ascii
      $sa2 = "<?xml version=" ascii
      $sa3 = "<Runninglocalrequired>" ascii
      $sa4 = "<Autostartup>" ascii

      $sb1 = "wscript" ascii
      $sb2 = "cscript" ascii
      $sb3 = "mshta" ascii
      $sb4 = "certutil" ascii
      $sb5 = "pwsh" ascii
      $sb6 = "curl" ascii
      $sb7 = "msiexec" ascii
      $sb8 = "taskkill" ascii
      $sb9 = "regsvr32" ascii
      $sb10 = "rundll32" ascii
      $sb11 = "bitsadmin" ascii
      $sb12 = "whoami" ascii
      $sb13 = "bcdedit" ascii
      $sb14 = "systeminfo" ascii
      $sb15 = "reg " ascii
      $sb16 = "schtasks" ascii
      // $sb17 = "query" ascii
   condition:
      filesize < 10KB
      and all of ($sa*)
      and 1 of ($sb*)
}

rule SUSP_EXPL_JAR_Indicators_Dec24 {
   meta:
      description = "Detects characteristics of JAR files used during Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "4e8f6aa8-9efd-5fcf-b795-5042d4ba1708"
   strings:
      $s1 = "TLS v3 " ascii
      $s2 = "java/util/Base64$Decoder" ascii
      $s3 = "AES/CBC/NoPadding" ascii
      $s4 = "getenv" ascii
      $s5 = "ava/util/zip/ZipInputStream" ascii
   condition:
      uint16(0) == 0xfeca
      and filesize < 20KB
      and all of them
}

rule EXPL_Cleo_Exploitation_JAVA_Payloads_Dec24_1_1 {
   meta:
      description = "Detects characteristics of JAVA files used during Cleo software exploitation (as reported by Huntress in December 2024) - files Cli, ScSlot, Slot, SrvSlot"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      hash1 = "0c57b317b572d071afd8ccdb844dd6f117e20f818c6031d7ba8adcbd32be0617"
      id = "2940ddad-3dba-594a-9111-e4741d6ff39b"
   strings:
      $a1 = "java/lang/StringBuffer"

      $x1 = "Start-Sleep 3;del " ascii
      $x2 = "sleep 3;rm -f '" ascii
      $x3 = "powershell -Noninteractive -EncodedCommand " ascii
      $x4 = "runDelFileCmd" ascii fullword
   condition:
      uint16(0) == 0xfeca
      and filesize < 50KB
      and $a1
      and 1 of ($x*)
}

rule EXPL_Cleo_Exploitation_JAVA_Payloads_Dec24_2 {
   meta:
      description = "Detects characteristics of JAVA files used during Cleo software exploitation (as reported by Huntress in December 2024) - file Proc"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      hash1 = "1ba95af21bac45db43ebf02f87ecedde802c7de4d472f33e74ee0a5b5015a726"
      id = "bd575454-7fd0-566d-94e5-ec1368675108"
   strings:
      $s1 = "Timeout getting pipe-data" ascii fullword
      $s2 = "Ftprootpath" ascii fullword
      $s3 = "Rest cmd=" ascii fullword
      $s4 = "writeToProc" ascii fullword
   condition:
      uint16(0) == 0xfeca
      and filesize < 30KB
      and 3 of them
}

rule EXPL_Cleo_Exploitation_JAVA_Payloads_Dec24_3 {
   meta:
      description = "Detects characteristics of JAR files used during Cleo software exploitation"
      author = "X__Junior"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      id = "5c227bb9-0731-5955-a758-6fe86ecc2d86"
   strings:
      $a1 = "java/lang/String" ascii

      $s1 = "#lsz#" ascii
      $s2 = "#dbg#" ascii
      $s3 = "#ll#" ascii
      $s4 = "SvZipDataOverflow=%d OpNotConf=" ascii
   condition:
      uint16(0) == 0xfeca
      and filesize < 20KB
      and 3 of ($s*) and $a1
}