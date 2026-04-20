rule SUSP_Command_Line_Combos_Feb24_2 : SCRIPT {
   meta:
      description = "Detects suspicious command line combinations often found in post exploitation activities"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "d9bc6083-c3ca-5639-a9df-483fea6d0187"
   strings:
      $sa1 = " | iex"
      $sa2 = "iwr -UseBasicParsing "
   condition:
      filesize < 2MB and all of them
}

rule SUSP_MAL_SigningCert_Feb24_1 {
   meta:
      description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
      hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"
      id = "f25ea77a-1b4e-5c13-9117-eedf0c20335a"
   strings:
      $s1 = "Wisdom Promise Security Technology Co." ascii
      $s2 = "Globalsign TSA for CodeSign1" ascii
      $s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 70000KB
      and all of them
}

rule MAL_RANSOM_LockBit_Indicators_Feb24 {
   meta:
      description = "Detects Lockbit ransomware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "a50d9954c0a50e5804065a8165b18571048160200249766bfa2f75d03c8cb6d0"
      id = "108430c8-4fe5-58a1-b709-539b257c120c"
   strings:
      $op1 = { 76 c1 95 8b 18 00 93 56 bf 2b 88 71 4c 34 af b1 a5 e9 77 46 c3 13 }
      $op2 = { e0 02 10 f7 ac 75 0e 18 1b c2 c1 98 ac 46 }
      $op3 = { 8b c6 ab 53 ff 15 e4 57 42 00 ff 45 fc eb 92 ff 75 f8 ff 15 f4 57 42 00 }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 500KB
      and (
         pe.imphash() == "914685b69f2ac2ff61b6b0f1883a054d"
         or 2 of them
      ) or all of them
}

rule SUSP_ScreenConnect_New_User_2024_Feb24 {
   meta:
      description = "Detects suspicious new ScreenConnect user created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-22"
      score = 50
      id = "f6675ded-39a4-590a-a201-fcfe3c056e60"
   strings:
      $a1 = "<Users xmlns:xsi="

      $s1 = "<CreationDate>2024-"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}

rule SUSP_ScreenConnect_User_2024_No_Logon_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user created in 2024 but without any login, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
      date = "2024-02-23"
      score = 60
      id = "c0861f1c-08e2-565d-a468-2075c51b4004"
   strings:
      $a1 = "<Users xmlns:xsi="
      $a2 = "<CreationDate>"

      $s1 = "<CreationDate>2024-"
      $s2 = "<LastLoginDate>0001-01-01T00:00:00</LastLoginDate>"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}