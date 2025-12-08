rule WindowsCredentialEditor
{
    meta:
       description = "Windows Credential Editor"
      threat_level = 10
      score = 90
       id = "1542c6e4-36b2-5272-85d0-43226869b43e"
    strings:
      $a = "extract the TGT session key"
      $b = "Windows Credentials Editor"
    condition:
       all of them
}

rule PwDump
{
   meta:
      description = "PwDump 6 variant"
      author = "Marc Stroebel"
      date = "2014-04-24"
      score = 70
      id = "e557e548-53e8-5098-93d4-8e899384e67c"
   strings:
      $s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
      $s6 = "Unable to query service status. Something is wrong, please manually check the st"
      $s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword
   condition:
      1 of them
}

rule HackTool_Samples {
   meta:
      description = "Hacktool"
      score = 50
      id = "ecacf84a-f66c-5c21-ae4b-fd9bfb5be384"
   strings:
      $a = "Unable to uninstall the fgexec service"
      $b = "Unable to set socket to sniff"
      $c = "Failed to load SAM functions"
      $d = "Dump system passwords"
      $e = "Error opening sam hive or not valid file"
      $f = "Couldn't find LSASS pid"
      $g = "samdump.dll"
      $h = "WPEPRO SEND PACKET"
      $i = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4"
      $j = "Usage: unshadow PASSWORD-FILE SHADOW-FILE"
      $k = "arpspoof\\Debug"
      $l = "Success: The log has been cleared"
      $m = "clearlogs [\\\\computername"
      $n = "DumpUsers 1."
      $o = "dictionary attack with specified dictionary file"
      $p = "by Objectif Securite"
      $q = "objectif-securite"
      $r = "Cannot query LSA Secret on remote host"
      $s = "Cannot write to process memory on remote host"
      $t = "Cannot start PWDumpX service on host"
      $u = "usage: %s <system hive> <security hive>"
      $v = "username:domainname:LMhash:NThash"
      $w = "<server_name_or_ip> | -f <server_list_file> [username] [password]"
      $x = "Impersonation Tokens Available"
      $y = "failed to parse pwdump format string"
      $z = "Dumping password"
   condition:
      1 of them
}

rule Chinese_Hacktool_1014 {
   meta:
      description = "Detects a chinese hacktool with unknown use"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "10.10.2014"
      hash = "98c07a62f7f0842bcdbf941170f34990"
      id = "e5db5f58-a1fd-51e0-9037-337fcca71f11"
   strings:
      $s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
      $s1 = "msctls_progress32" fullword wide
      $s2 = "Reply-To: %s" fullword ascii
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
      $s4 = "html htm htx asp" fullword ascii
   condition:
      all of them
}

rule CN_Hacktool_1433_Scanner_Comp2 {
   meta:
      description = "Detects a chinese MSSQL scanner - component 2"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 40
      date = "12.10.2014"
      id = "7d707be5-dad0-5d91-965b-908a8603b6c0"
   strings:
      $s0 = "1433" wide fullword
      $s1 = "1433V" wide
      $s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
   condition:
      uint16(0) == 0x5a4d and all of ($s*)
}

rule ReactOS_cmd_valid {
   meta:
      description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "05.11.14"
      reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
      score = 30
      hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
      id = "47df12b4-d202-5520-9c7f-9d0196bc2267"
   strings:
      $s1 = "ReactOS Command Processor" fullword wide
      $s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
      $s3 = "Eric Kohl and others" fullword wide
      $s4 = "ReactOS Operating System" fullword wide
   condition:
      all of ($s*)
}

rule iKAT_startbar {
   meta:
      description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "05.11.14"
      score = 50
      reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
      hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
      id = "f29f15e9-aa29-519a-b4ad-c018aac68fd6"
   strings:
      $s2 = "Shinysoft Limited1" fullword ascii
      $s3 = "Shinysoft Limited0" fullword ascii
      $s4 = "Wellington1" fullword ascii
      $s6 = "Wainuiomata1" fullword ascii
      $s8 = "56 Wright St1" fullword ascii
      $s9 = "UTN-USERFirst-Object" fullword ascii
      $s10 = "New Zealand1" fullword ascii
   condition:
      all of them
}

rule Ncat_Hacktools_CN {
   meta:
      description = "Disclosed hacktool set - file nc.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "001c0c01c96fa56216159f83f6f298755366e528"
      id = "bdbfaf75-f8c0-508e-b6b1-9ddea179a325"
   strings:
      $s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
      $s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
      $s3 = "gethostpoop fuxored" fullword ascii
      $s6 = "VERNOTSUPPORTED" fullword ascii
      $s7 = "%s [%s] %d (%s)" fullword ascii
      $s12 = " `--%s' doesn't allow an argument" fullword ascii
   condition:
      all of them
}

rule sig_238_hunt {
   meta:
      description = "Disclosed hacktool set (old stuff) - file hunt.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
      id = "5d9d1f99-2f12-51e9-a554-b349e19d00fb"
   strings:
      $s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
      $s3 = "Usage - hunt \\\\servername" fullword ascii
      $s4 = ".share = %S - %S" fullword wide
      $s5 = "SMB share enumerator and admin finder " fullword ascii
      $s7 = "Hunt only runs on Windows NT..." fullword ascii
      $s8 = "User = %S" fullword ascii
      $s9 = "Admin is %s\\%s" fullword ascii
   condition:
      all of them
}

rule ByPassFireWall_zip_Folder_Ie {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Ie.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "d1b9058f16399e182c9b78314ad18b975d882131"
      id = "7bd10fa1-be2d-5882-b4c7-b696612343e5"
   strings:
      $s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
      $s1 = "LOADER ERROR" fullword ascii
      $s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
      $s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
   condition:
      all of them
}

rule sig_238_2323 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file 2323.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
      id = "445f6a49-51e6-5eb8-ae08-e5989aafb6c4"
   strings:
      $s0 = "port - Port to listen on, defaults to 2323" fullword ascii
      $s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
      $s3 = "Failed to execute shell" fullword ascii
      $s5 = "/h   - Hide Window" fullword ascii
      $s7 = "Accepted connection from client at %s" fullword ascii
      $s9 = "Error %d: %s" fullword ascii
   condition:
      all of them
}

rule sig_238_concon {
   meta:
      description = "Disclosed hacktool set (old stuff) - file concon.com"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
      id = "ca7862cc-1053-5fce-a569-6ecc069314df"
   strings:
      $s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii
   condition:
      all of them
}

rule LinuxHacktool_eyes_scanssh {
   meta:
      description = "Linux hack tools - file scanssh"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2015/01/19"
      hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
      id = "9546d0d8-42af-5b4c-ac93-195d14bfbb5b"
   strings:
      $s0 = "Connection closed by remote host" fullword ascii
      $s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
      $s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
      $s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
      $s5 = "Server closed connection" fullword ascii
      $s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
      $s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
      $s9 = "Remote host closed connection" fullword ascii
      $s10 = "%s: line %d: bad command `%s'" fullword ascii
      $s13 = "verifying that server is a known host : file %s not found" fullword ascii
      $s14 = "%s: line %d: expected service, found `%s'" fullword ascii
      $s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
      $s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii
   condition:
      all of them
}

rule LinuxHacktool_eyes_pscan2 {
   meta:
      description = "Linux hack tools - file pscan2"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2015/01/19"
      hash = "56b476cba702a4423a2d805a412cae8ef4330905"
      id = "02d96766-6696-5410-ad48-bd8cb642ac51"
   strings:
      $s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
      $s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
      $s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
      $s8 = "Invalid IP." fullword ascii
      $s9 = "# scanning: " fullword ascii
      $s10 = "Unable to allocate socket." fullword ascii
   condition:
      2 of them
}

rule LinuxHacktool_eyes_pscan2_2 {
   meta:
      description = "Linux hack tools - file pscan2.c"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2015/01/19"
      hash = "eb024dfb441471af7520215807c34d105efa5fd8"
      id = "3950b235-70bc-5afd-add5-38c50055b28b"
   strings:
      $s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
      $s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
      $s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
      $s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
      $s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii
   condition:
      2 of them
}

rule CN_Toolset_sig_1433_135_sqlr {
   meta:
      description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://qiannao.com/ls/905300366/33834c0c/"
      date = "2015/03/30"
      score = 70
      hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
      id = "74038975-ef06-53d6-bdcc-02706408b596"
   strings:
      $s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
      $s11 = ";DATABASE=master" fullword ascii
      $s12 = "xp_cmdshell '" fullword ascii
      $s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
   condition:
      all of them
}

rule DarkComet_Keylogger_File
{
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      description = "Looks like a keylogger file created by DarkComet Malware"
      date = "25.07.14"
      score = 50
      id = "65058450-3ae3-5b85-bcc5-8bc1fab14614"
   strings:
      $entry = /\n:: [A-Z]/
      $timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
   condition:
      uint16(0) == 0x3A3A and #entry > 10 and #timestamp > 10
}

rule Netview_Hacktool {
   meta:
      description = "Network domain enumeration tool - often used by attackers - file Nv.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/mubix/netview"
      date = "2016-03-07"
      score = 60
      hash = "52cec98839c3b7d9608c865cfebc904b4feae0bada058c2e8cdbd561cfa1420a"
      id = "087e2fd7-726e-5c6b-ba99-e20dd3337d6a"
   strings:
      $s1 = "[+] %ws - Target user found - %s\\%s" fullword wide
      $s2 = "[*] -g used without group specified - using \"Domain Admins\"" fullword ascii
      $s3 = "[*] -i used without interval specified - ignoring" fullword ascii
      $s4 = "[+] %ws - Session - %s from %s - Active: %d - Idle: %d" fullword wide
      $s5 = "[+] %ws - Backup Domain Controller" fullword wide
      $s6 = "[-] %ls - Share - Error: %ld" fullword wide
      $s7 = "[-] %ls - Session - Error: %ld" fullword wide
      $s8 = "[+] %s - OS Version - %d.%d" fullword ascii
      $s9 = "Enumerating Logged-on Users" fullword ascii
      $s10 = ": Specifies a domain to pull a list of hosts from" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 2 of them ) or 3 of them
}

rule Netview_Hacktool_Output {
   meta:
      description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/mubix/netview"
      date = "2016-03-07"
      score = 60
      id = "259db870-6293-5a55-b56a-f981c060c18f"
   strings:
      $s1 = "[*] Using interval:" fullword
      $s2 = "[*] Using jitter:" fullword
      $s3 = "[+] Number of hosts:" fullword
   condition:
      2 of them
}

rule pstgdump {
   meta:
      description = "Detects a tool used by APT groups - file pstgdump.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"
      id = "86a105a3-b5b5-58b2-99bd-ec05f31adb6b"
   strings:
      $x1 = "\\Release\\pstgdump.pdb" ascii
      $x2 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
      $x3 = "ptsgdump [-h][-q][-u Username][-p Password]" fullword ascii
      $x4 = "Attempting to impersonate domain user '%s' in domain '%s'" fullword ascii
      $x5 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
      $x6 = "Unable to obtain handle to PStoreCreateInstance in pstorec.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule PwDump_B {
   meta:
      description = "Detects a tool used by APT groups - file PwDump.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://goo.gl/igxLyF"
      date = "2016-09-08"
      hash1 = "3c796092f42a948018c3954f837b4047899105845019fce75a6e82bc99317982"
      id = "aad974f1-76bf-5aae-8376-a4fd3f27b345"
   strings:
      $x1 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineName" fullword ascii
      $x2 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword ascii
      $x3 = "where -x targets a 64-bit host" fullword ascii
      $x4 = "Couldn't delete target executable from remote machine: %d" fullword ascii

      $s1 = "lsremora64.dll" fullword ascii
      $s2 = "lsremora.dll" fullword ascii
      $s3 = "servpw.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of ($x*) ) or ( 3 of them )
}

rule Fscan_Portscanner {
   meta:
      description = "Fscan port scanner scan output / strings"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JamesHabben/status/817112447970480128"
      date = "2017-01-06"
      id = "400383dc-8bc0-5e77-a3f3-d6ba9f4c3c0f"
   strings:
      $s1 = "Time taken:" fullword ascii
      $s2 = "Scan finished at" fullword ascii
      $s3 = "Scan started at" fullword ascii
   condition:
      filesize < 20KB and 3 of them
}

rule WPR_loader_DLL {
   meta:
      description = "Windows Password Recovery - file loader64.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "7b074cb99d45fc258e0324759ee970467e0f325e5d72c0b046c4142edc6776f6"
      hash2 = "a1f27f7fd0e03601a11b66d17cfacb202eacf34f94de3c4e9d9d39ea8d1a2612"
      id = "d3102ab6-0473-544b-b9dd-ec7a18ae1c4b"
   strings:
      $x1 = "loader64.dll" fullword ascii
      $x2 = "loader.dll" fullword ascii

      $s1 = "TUlDUk9TT0ZUX0FVVEhFTlRJQ0FUSU9OX1BBQ0tBR0VfVjFfMA==" fullword ascii /* base64 encoded string 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0' */
      $s2 = "UmVtb3RlRGVza3RvcEhlbHBBc3Npc3RhbnRBY2NvdW50" fullword ascii /* base64 encoded string 'RemoteDesktopHelpAssistantAccount' */
      $s3 = "U2FtSVJldHJpZXZlUHJpbWFyeUNyZWRlbnRpYWxz" fullword ascii /* base64 encoded string 'SamIRetrievePrimaryCredentials' */
      $s4 = "VFM6SW50ZXJuZXRDb25uZWN0b3JQc3dk" fullword ascii /* base64 encoded string 'TS:InternetConnectorPswd' */
      $s5 = "TCRVRUFjdG9yQWx0Q3JlZFByaXZhdGVLZXk=" fullword ascii /* base64 encoded string 'L$UEActorAltCredPrivateKey' */
      $s6 = "YXNwbmV0X1dQX1BBU1NXT1JE" fullword ascii /* base64 encoded string 'aspnet_WP_PASSWORD' */
      $s7 = "TCRBTk1fQ1JFREVOVElBTFM=" fullword ascii /* base64 encoded string 'L$ANM_CREDENTIALS' */
      $s8 = "RGVmYXVsdFBhc3N3b3Jk" fullword ascii /* base64 encoded string 'DefaultPassword' */

      $op0 = { 48 8b cd e8 e0 e8 ff ff 48 89 07 48 85 c0 74 72 } /* Opcode */
      $op1 = { e8 ba 23 00 00 33 c9 ff 15 3e 82 } /* Opcode */
      $op2 = { 48 83 c4 28 e9 bc 55 ff ff 48 8d 0d 4d a7 00 00 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      (
         ( 1 of ($x*) and 1 of ($s*) ) or
         ( 1 of ($s*) and all of ($op*) )
      )
}

rule WPR_WindowsPasswordRecovery_EXE {
   meta:
      description = "Windows Password Recovery - file wpr.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
      id = "7fa2062c-75dd-55aa-8775-631a9c1a497e"
   strings:
      $x1 = "UuPipe" fullword ascii
      $x2 = "dbadllgl" fullword ascii
      $x3 = "UkVHSVNUUlkgTU9O" fullword ascii /* base64 encoded string 'REGISTRY MON' */
      $x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii /* base64 encoded string 'FILE MONITOR - SY' */

      $s1 = "WPR.exe" fullword wide
      $s2 = "Windows Password Recovery" fullword wide

      $op0 = { 5f df 27 17 89 } /* Opcode */
      $op1 = { 5f 00 00 f2 e5 cb 97 } /* Opcode */
      $op2 = { e8 ed 00 f0 cc e4 00 a0 17 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and
      filesize < 20000KB and
      (
         1 of ($x*) or
         all of ($s*) or
         all of ($op*)
      )
}

rule WPR_WindowsPasswordRecovery_EXE_64 {
   meta:
      description = "Windows Password Recovery - file ast64.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "4e1ea81443b34248c092b35708b9a19e43a1ecbdefe4b5180d347a6c8638d055"
      id = "0f6c7695-e616-5757-b9cd-8cff5f972c3e"
   strings:
      $s1 = "%B %d %Y  -  %H:%M:%S" fullword wide

      $op0 = { 48 8d 8c 24 50 22 00 00 e8 bf eb ff ff 4c 8b c7 } /* Opcode */
      $op1 = { ff 15 16 25 01 00 f7 d8 1b } /* Opcode */
      $op2 = { e8 c2 26 00 00 83 20 00 83 c8 ff 48 8b 5c 24 30 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule BeyondExec_RemoteAccess_Tool {
   meta:
      description = "Detects BeyondExec Remote Access Tool - file rexesvr.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/BvYurS"
      date = "2017-03-17"
      hash1 = "3d3e3f0708479d951ab72fa04ac63acc7e5a75a5723eb690b34301580747032c"
      id = "fd68cb45-a46f-53d7-bf52-8f7bd3636d0d"
   strings:
      $x1 = "\\BeyondExecV2\\Server\\Release\\Pipes.pdb" ascii
      $x2 = "\\\\.\\pipe\\beyondexec%d-stdin" fullword ascii
      $x3 = "Failed to create dispatch pipe. Do you have another instance running?" fullword ascii

      $op1 = { 83 e9 04 72 0c 83 e0 03 03 c8 ff 24 85 80 6f 40 } /* Opcode */
      $op2 = { 6a 40 33 c0 59 bf e0 d8 40 00 f3 ab 8d 0c 52 c1 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or all of ($op*) ) ) or ( 3 of them )
}

rule Disclosed_0day_POCs_injector {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "ba0e2119b2a6bad612e86662b643a404426a07444d476472a71452b7e9f94041"
      id = "6de89a84-fe16-5064-8cbb-a3b9003f4c0c"
   strings:
      $x1 = "\\Release\\injector.pdb" ascii
      $x2 = "Cannot write the shellcode in the process memory, error: " fullword ascii
      $x3 = "/s shellcode_file PID: shellcode injection." fullword ascii
      $x4 = "/d dll_file PID: dll injection via LoadLibrary()." fullword ascii
      $x5 = "/s shellcode_file PID" fullword ascii
      $x6 = "Shellcode copied in memory: OK" fullword ascii
      $x7 = "Usage of the injector. " fullword ascii
      $x8 = "KO: cannot obtain the SeDebug privilege." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them ) or 3 of them
}

rule Disclosed_0day_POCs_shellcodegenerator {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
      id = "49250cbe-7bbd-5462-9324-1a8f350386f3"
   strings:
      $x1 = "\\Release\\shellcodegenerator.pdb" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule Kekeo_Hacktool {
   meta:
      description = "Detects Kekeo Hacktool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/gentilkiwi/kekeo/releases"
      date = "2017-07-21"
      hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
      hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"
      id = "a4158da8-fc4d-5dc6-b44c-f5325b3bb8ca"
   strings:
      $x1 = "[ticket %u] session Key is NULL, maybe a TGT without enough rights when WCE dumped it." fullword wide
      $x2 = "ERROR kuhl_m_smb_time ; Invalid! Command: %02x - Status: %08x" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) ) )
}

rule KeeTheft_EXE {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file KeeTheft.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "f06789c3e9fe93c165889799608e59dda6b10331b931601c2b5ae06ede41dc22"
      id = "65531239-c5fa-5285-8f44-2d858e211c9b"
   strings:
      $x1 = "Error: Could not create a thread for the shellcode" fullword wide
      $x2 = "Could not find address marker in shellcode" fullword wide
      $x3 = "GenerateDecryptionShellCode" fullword ascii
      $x4 = "KeePassLib.Keys.KcpPassword" fullword wide
      $x5 = "************ Found a CompositeKey! **********" fullword wide
      $x6 = "*** Interesting... there are multiple .NET runtimes loaded in KeePass" fullword wide
      $x7 = "GetKcpPasswordInfo" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule KeeTheft_Out_Shellcode {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"
      id = "1263ad5d-5d50-50e6-ad78-9d5e4e16634b"
   strings:
      $x1 = "Write-Host \"Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))\"" fullword ascii
      $x2 = "$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\\.text\\W+CODE' })[0]" fullword ascii
   condition:
      ( filesize < 2KB and 1 of them )
}

rule PowerShell_Mal_HackTool_Gen {
   meta:
      description = "Detects PowerShell hack tool samples - generic PE loader"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-11-02"
      hash1 = "d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32"
      id = "d1fc4594-d816-5d02-bff6-3f220477b555"
   strings:
      $x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA" wide
      $x2 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword wide
      $x3 = "@($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword wide
      $x4 = "(Shellcode: LoadLibraryA.asm)" fullword wide
   condition:
      filesize < 8000KB and 1 of them
}

rule Sig_RemoteAdmin_1 {
   meta:
      description = "Detects strings from well-known APT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-03"
      score = 45
      id = "da55084c-ec1f-5800-a614-189dce7b5820"
   strings:
      $ = "Radmin, Remote Administrator" wide
      $ = "Radmin 3.0" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule RemCom_RemoteCommandExecution {
   meta:
      description = "Detects strings from RemCom tool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tezXZt"
      date = "2017-12-28"
      score = 50
      id = "90b4ce3c-a690-5b6e-95e8-7e5dc8270152"
   strings:
      $ = "\\\\.\\pipe\\%s%s%d"
      $ = "%s\\pipe\\%s%s%d%s"
      $ = "\\ADMIN$\\System32\\%s%s"
   condition:
      1 of them
}

rule ProcessInjector_Gen : HIGHVOL {
   meta:
      description = "Detects a process injection utility that can be used ofr good and bad purposes"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/cuckoosandbox/monitor/blob/master/bin/inject.c"
      date = "2018-04-23"
      score = 60
      hash1 = "456c1c25313ce2e2eedf24fdcd4d37048bcfff193f6848053cbb3b5e82cd527d"
      id = "9b0b6ac7-8432-5f93-b389-c2356ec75113"
   strings:
      $x1 = "Error injecting remote thread in process:" fullword ascii
      $s5 = "[-] Error getting access to process: %ld!" fullword ascii
      $s6 = "--process-name <name>  Process name to inject" fullword ascii
      $s12 = "No injection target has been provided!" fullword ascii
      $s17 = "[-] An app path is required when not injecting!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and (
         pe.imphash() == "d27e0fa013d7ae41be12aaf221e41f9b" or
         1 of them
      ) or 3 of them
}

rule HKTL_shellpop_socat {
   meta:
      description = "Detects suspicious socat popshell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "267f69858a5490efb236628260b275ad4bbfeebf4a83fab8776e333ca706a6a0"
      id = "23c331ba-217c-5b17-b45e-d553eea76a56"
   strings:
      $s1 = "socat tcp-connect" ascii
      $s2 = ",pty,stderr,setsid,sigint,sane" ascii
   condition:
      filesize < 1KB and 2 of them
}

rule HKTL_shellpop_Perl {
   meta:
      description = "Detects Shellpop Perl script"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"
      id = "d597d213-a70b-5412-adde-791b4d498848"
   strings:
      $ = "perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);" ascii
      $ = ";STDIN->fdopen(\\$c,r);$~->fdopen(\\$c,w);s" ascii
   condition:
      filesize < 2KB and 1 of them
}

rule HKTL_shellpop_PHP_TCP {
   meta:
      description = "Detects malicious PHP shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "0412e1ab9c672abecb3979a401f67d35a4a830c65f34bdee3f87e87d060f0290"
      id = "3bafc225-62e5-5183-84aa-9c3406b6c444"
   strings:
      $x1 = "php -r \"\\$sock=fsockopen" ascii
      $x2 = ";exec('/bin/sh -i <&3 >&3 2>&3');\"" ascii
   condition:
      filesize < 3KB and all of them
}

rule HKTL_shellpop_Powershell_TCP {
   meta:
      description = "Detects malicious powershell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
      id = "4f3a92db-f686-559a-9588-fb79f423c51f"
   strings:
      $ = "Something went wrong with execution of command on the target" ascii
      $ = ";[byte[]]$bytes = 0..65535|%{0};$sendbytes =" ascii
   condition:
      filesize < 3KB and 1 of them
}

rule SUSP_Powershell_ShellCommand_May18_1 {
   meta:
      description = "Detects a supcicious powershell commandline"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
      id = "efa81fd0-b764-5a1a-98a5-fc3135be220b"
   strings:
      $x1 = "powershell -nop -ep bypass -Command" ascii
   condition:
      filesize < 3KB and 1 of them

}

rule HKTL_shellpop_Telnet_TCP {
   meta:
      description = "Detects malicious telnet shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "cf5232bae0364606361adafab32f19cf56764a9d3aef94890dda9f7fcd684a0e"
      id = "dbd5cc65-c6f1-54f3-813f-7a7f9bcca184"
   strings:
      $x1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
      $x2 = "0</tmp/f|/bin/bash 1>/tmp/f" fullword ascii
   condition:
      filesize < 3KB and 1 of them
}

rule SUSP_shellpop_Bash {
   meta:
      description = "Detects susupicious bash command"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      modified = "2025-04-11"
      score = 70
      hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
      id = "771b7d01-272a-5986-af07-7417b84c52ed"
   strings:
      $x1 = "bash -i >& /dev/tcp/" ascii
      $x2 = "bash -i >& /dev/tcp/" ascii base64

      $fp1 = "bash -i >& /dev/tcp/IP/PORT" ascii
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule HKTL_shellpop_netcat {
   meta:
      description = "Detects suspcious netcat shellpop"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "98e3324f4c096bb1e5533114249a9e5c43c7913afa3070488b16d5b209e015ee"
      id = "cd55e912-b57b-5fce-98eb-5a0cd27a6e4d"
   strings:
      $s1 = "if [ -e /tmp/f ]; then rm /tmp/f;"  ascii
      $s2 = "fi;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc" ascii
      $s4 = "mknod /tmp/f p && nc" ascii
      $s5 = "</tmp/f|/bin/bash 1>/tmp/f"  ascii
    condition:
      filesize < 2KB and 1 of them
}

rule HTKL_BlackBone_DriverInjector {
   meta:
      description = "Detects BlackBone Driver injector"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/DarthTon/Blackbone"
      date = "2018-09-11"
      score = 60
      hash1 = "8062a4284c719412270614458150cb4abbdf77b2fc35f770ce9c45d10ccb1f4d"
      hash2 = "2d2fc27200c22442ac03e2f454b6e1f90f2bbc17017f05b09f7824fac6beb14b"
      hash3 = "e45da157483232d9c9c72f44b13fca2a0d268393044db00104cc1afe184ca8d1"
      id = "0d992a6c-c57a-5895-af0d-9c167d922601"
   strings:
      $s1 = "=INITtH=PAGEtA" fullword ascii
      $s2 = "BBInjectDll" fullword ascii
      $s3 = "LdrLoadDll" fullword ascii
      $s4 = "\\??\\pipe\\%ls" fullword wide
      $s5 = "Failed to retrieve Kernel base address. Aborting" fullword ascii

      $x2 = "BlackBone: %s: APC injection failed with status 0x%X" fullword ascii
      $x3 = "BlackBone: PDE_BASE/PTE_BASE not found " fullword ascii
      $x4 = "%s: Invalid injection type specified - %d" fullword ascii
      $x6 = "Trying to map C:\\windows\\system32\\cmd.exe into current process" fullword wide
      $x7 = "\\BlackBoneDrv\\bin\\" ascii
      $x8 = "DosDevices\\BlackBone" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and ( 3 of them or 1 of ($x*) )
}

rule HKTL_SqlMap_backdoor {
   meta:
      description = "Detects SqlMap backdoors"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/sqlmapproject/sqlmap"
      date = "2018-10-09"
      id = "bf09caac-cf15-5936-b5b4-df4f28788961"
   condition:
      ( uint32(0) == 0x8e859c07 or
         uint32(0) == 0x2d859c07 or
         uint32(0) == 0x92959c07 or
         uint32(0) == 0x929d9c07 or
         uint32(0) == 0x29959c07 or
         uint32(0) == 0x2b8d9c07 or
         uint32(0) == 0x2b859c07 or
         uint32(0) == 0x28b59c07 ) and filesize < 2KB
}

rule SUSP_Katz_PDB {
   meta:
      description = "Detects suspicious PDB in file"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-04"
      hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
      id = "79f4f07c-b234-5203-a2ab-aba4a9cb9f8d"
   strings:
      $s1 = /\\Release\\[a-z]{0,8}katz.pdb/
      $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}

rule HKTL_LNX_Pnscan {
   meta:
      description = "Detects Pnscan port scanner"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/ptrrkssn/pnscan"
      date = "2019-05-27"
      score = 55
      id = "46c6c0d9-08bb-5de3-ad14-c1a7ab0542c6"
   strings:
      $x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
      $x2 = "This program implements a multithreaded TCP port scanner." ascii wide
   condition:
      filesize < 6000KB and 1 of them
}

rule HKTL_DomainPasswordSpray {
   meta:
      description = "Detects the Powershell password spray tool DomainPasswordSpray"
      author = "Arnim Rupp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      reference = "https://github.com/dafthack/DomainPasswordSpray"
      date = "2023-01-13"
      score = 60
      hash1 = "44d4c0ae5673d2a076f3b5acdc83063aca49d58e6dd7cf73d0b927f83d359247"
      id = "890e4514-2846-54f8-8f32-cc9d2a4ef81b"
   strings:
      $s = "Invoke-DomainPasswordSpray" fullword ascii wide
   condition:
      filesize < 100KB and
      all of them
}

rule HKTL_RustHound {
   meta:
        description = "Detect hacktool RustHound (Sharphound clone)"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-30"
        reference = "https://github.com/OPENCYBER-FR/RustHound"
        hash = "409f61a34d9771643246f401a9670f6f7dcced9df50cbd89a2e1a5c9ba8d03ab"
        hash = "b1a58a9c94b1df97a243e6c3fc2d04ffd92bc802edc7d8e738573b394be331a9"
        hash = "170f4a48911f3ebef674aade05184ea0a6b1f6b089bcffd658e95b9905423365"
        hash = "e52f6496b863b08296bf602e92a090768e86abf498183aa5b6531a3a2d9c0bdb"
        hash = "847e57a35df29d40858c248e5b278b09cfa89dd4201cb24262c6158395e2e585"
        hash = "4edfed92b54d32a58b2cfc926f98a56637e89850410706abcc469a8bc846bc85"
        hash = "feba0c16830ea0a13819a9ab8a221cc64d5a9b3cc73f3c66c405a171a2069cc1"
        hash = "21d37c2393a6f748fe34c9d2f52693cb081b63c3a02ca0bebe4a584076f5886c"
        hash = "874a1a186eb5808d456ce86295cd5f09d6c819375acb100573c2103608af0d84"
        hash = "bf576bd229393010b2bb4ba17e49604109e294ca38cf19647fc7d9c325f7bcd1"
        id = "d2fd79a5-9a1a-51de-920c-61653c8b0064"
   strings:
        $rh1 = "rusthound" fullword ascii wide
        $rh2 = "Making json/zip files finished!" ascii wide
   condition:
        (
            // PE or elf
            uint16(0) == 0x5A4D or
            uint16(0) == 0x457f
        ) and
        1 of ( $rh* )
}