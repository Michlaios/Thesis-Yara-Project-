rule WEBSHELL_PAS_webshell {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 70
      id = "862aab77-936e-524c-8669-4f48730f4ed5"
   strings:
      $php = "<?php"
      $strreplace = "(str_replace("
      $md5 = ".substr(md5(strrev($"
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   condition:
      ( filesize > 20KB and filesize < 200KB ) and
      all of them
}

rule WEBSHELL_PAS_webshell_ZIPArchiveFile {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects an archive file created by P.A.S. for download operation"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
   strings:
      $s1 = "Archive created by P.A.S. v."
   condition:
      $s1
}

rule WEBSHELL_PAS_webshell_PerlNetworkScript {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects PERL scripts created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "1625b63f-ead7-5712-92b4-0ce6ecc49fd4"
   strings:
      $pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
      $pl_status = "$o=\" [OK]\";$e=\" Error: \""
      $pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
      $msg1 = "print \"$l OK! I\\'m successful connected.$l\""
      $msg2 = "print \"$l OK! I\\'m accept connection.$l\""
   condition:
      filesize < 6000 and
      ( $pl_start at 0 and all of ($pl*) ) or
      any of ($msg*)
}

rule WEBSHELL_PAS_webshell_SQLDumpFile {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects SQL dump file created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
   strings:
      $ = "-- [ SQL Dump created by P.A.S. ] --"
   condition:
      1 of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "763dbb17-2bad-5b40-8a7b-b71bc5849cd9"
   strings:
      $ = { 6F B6 08 E9 A3 0C 8D 5E DD BE D4 } // encrypted with key odhyrfjcnfkdtslt
   condition:
      all of them
}

rule APT_MAL_Sandworm_Exaramel_Struct {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects the beginning of type _type struct for some of the most important structs in Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "8282e485-966c-554d-8e41-70dc1657f5ea"
   strings:
      $struct_le_config = {70 00 00 00 00 00 00 00 58 00 00 00 00 00 00 00 47 2d 28 42 0? [2] 19}
      $struct_le_worker = {30 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 46 6a 13 e2 0? [2] 19}
      $struct_le_client = {20 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 7b 6a 49 84 0? [2] 19}
      $struct_le_report = {30 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 bf 35 0d f9 0? [2] 19}
      $struct_le_task = {50 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 88 60 a1 c5 0? [2] 19}
   condition:
      any of them
}