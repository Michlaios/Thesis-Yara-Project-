rule SUSP_JAVA_Loader_Indicators_Aug25 {
   meta:
      description = "Detects indicators of a Java loader used in phishing campaigns"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 70
      hash1 = "c4cf746fce283878dde567e5457a8ebdbb7ff3414be46569ecdd57338bd96fa1"
   strings:
      $s1 = "Loader.classPK" ascii fullword
      $s2 = "stubPK" ascii
      $s3 = "META-INF/MANIFEST.MFPK" ascii
   condition:
      uint16(0) == 0x4b50
      and filesize < 500KB
      and $s1 in (filesize - 224..filesize)
      and $s2 in (filesize - 224..filesize)
      and $s3 in (filesize - 224..filesize)
}

rule SUSP_JAVA_Class_Allatori_Obfuscator_Aug25 {
   meta:
      description = "Detects a relatively small Java class file obfuscated by Allatori Obfuscator"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 50
      hash1 = "0a7fddd91b332c8daee2c0727b884fc92cfaede02883dbad75f7efc299e884e3"
   strings:
      $x1 = "Obfuscation by Allatori Obfuscator" ascii fullword
   condition:
      uint16(0) == 0x4b50
      and filesize < 500KB
      and $x1
}