rule APT_MAL_CN_Wocao_Agent_Csharp {
    meta:
        description = "Strings from CSharp version of Agent"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "e5212226-a82d-558d-abb4-43ad7848764e"
    strings:
        $a = "mysend(client_sock, new byte[] { 0x16, 0x00 }, 2);" ascii wide
        $b = "Dns.GetHostAddresses(sip.Remove(sip.Length - 1));" ascii wide
        $c = "Port = 256 * buf[4] + buf[5];" ascii wide
        $d = "Port = 256 * buf[AddrLen] + buf[AddrLen + 1];" ascii wide
        $e = "StartTransData(CliSock" ascii wide
        $f = "static void ForwardTransmit(object ft_data)" ascii wide

        $key = "0x4c, 0x1b, 0x68, 0x0b, 0x6a, 0x18, 0x09, 0x41, 0x5a, 0x36, 0x1f, 0x56, 0x26, 0x2a, 0x03, 0x44, 0x7d, 0x5f, 0x03, 0x7b, 0x07, 0x6e, 0x03, 0x77, 0x30, 0x70, 0x52, 0x42, 0x53, 0x67, 0x0a, 0x2a" ascii wide
        $key_raw = { 4c1b680b6a1809415a361f56262a03447d5f037b076e03773070524253670a2a }

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_agent_powershell_b64encoded {
    meta:
        description = "Piece of Base64 encoded data from Agent CSharp version"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "14e1702d-6229-5989-8bb7-cc9c0c321676"
    strings:
        $header = "LFNVT0hBBnVfVVJDSx0sU1VPSEEGdV9VUkNLCG9pHSxTVU9IQQZ1X1VSQ0sIZUlK"

    condition:
        all of them
}

rule APT_MAL_CN_Wocao_keylogger_file {
    meta:
        description = "Rule for finding keylogger output files"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "22e866b3-4b02-593a-b9a6-aa86870b6509"
    strings:
        $a = { 0d 0a 20 [3-10] 53 74 61 72 74 75 70 3a 20 [3] 20 [3] 20 [2] 20 [2] 3a [2] 3a [2] 20 }

    condition:
        all of them
}

rule name=powershell dir=in localport=47000 action=allow" ascii wide
        $e = "string TempFile = file_path + \".CT\";" ascii wide
        $f = "Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];"
        $g = "CliSock.Send(new byte[] { 0x05, 0x00 }

rule APT_MAL_CN_Wocao_xserver_powershell_b64encoded {
    meta:
        description = "Piece of Base64 encoded data from the XServer PowerShell dropper"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "01e38cfb-b245-5398-b037-6d1d2fb726ee"
    strings:
        $header_47000 = "5T39c9u2kr/nr2A0Ny2VKIzkfLRJntuJHafPN/nwWG777rUZDy3BNq8UqSEpx26b"
        $header_25667 = "5T1rc9u2st/zKxjNmZZKFEZyErdJ6nZsx+nxnTjxWGp77mkzHlqCbd5SpIak/Gjr"
    condition:
        any of them
}

rule APT_MAL_CN_Wocao_injector_bin {
    meta:
        description = "Process injector/launcher"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "389279f1-6531-594f-97b6-5adbc8fa4d3d"
    strings:
        $a = "%s{%04d-%02d%02d-%02d%02d-%d%ld}.tmp"
        $b = "s% > s% c/ exe.d"
        $c = {
            48 89 5C 24 08 48 89 74  24 10 57 48 83 EC 50 48
            8B 71 08 48 8D 59 10 48  8B F9 48 8B CB FF 17 33
            C9 48 8D 47 78 48 89 44  24 48 4C 8D 87 9C 03 00
            00 48 89 5C 24 40 48 8D  97 90 00 00 00 4C 89 44
            24 38 45 33 C9 48 89 4C  24 30 45 33 C0 89 4C 24
            28 C7 44 24 20 01 00 00  00 66 89 4B 40 FF D6 48
            8B 5C 24 60 33 C0 48 8B  74 24 68 48 83 C4 50 5F
            C3
        }

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_timeliner_bin {
    meta:
        description = "Timeliner utility"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "3d81a4ae-0ce0-5867-ac93-a706556481b6"
    strings:
        $a = "[+] Work completed." ascii wide
        $b = "[-] Create a new file failed." ascii wide
        $c = "[-] This is not a correct path." ascii wide
        $d = "%s [TargetPath] <Num> <SavePath>" ascii wide
        $e = "D\t%ld\t%ld\t%ld\t%d\t%d\t%s\t" ascii wide
        $f = "D\t%ld\t%ld\t%ld\t-1\t%d\t%s\t" ascii wide
        $g = "%s\t%ld\t%ld\t%ld\t%I64d\t%d\t%s\t%s" ascii wide

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_checkadmin_bin {
    meta:
        description = "Checkadmin utility"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "2f819213-ade1-525b-af18-d77b7fc96093"
    strings:
        $a = "[-] %s * A system error has occurred: %d" ascii wide
        $b = {
            0D 00 0A 00 25 00 6C 00 64 00 20 00 72 00 65 00
            73 00 75 00 6C 00 74 00 73 00 2E 00 0D 00 0A 00
        }
        $c = "%s\t<Access denied>" ascii wide

    condition:
        1 of them
}

rule APT_MAL_CN_Wocao_getos_py {
    meta:
        description = "Python getos utility"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "4a731dde-87e4-566a-b559-d23e0bef5841"
    strings:
        $smb_1 = {
            00 00 00 85 ff 53 4d 42 72 00 00 00 00 18 53 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 ff b4 00 62 00 02 50 43 20 4e 45 54 57 4f
            52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 00 02
            4c 41 4e 4d 41 4e 31 2e 30 00 02 57 69 6e 64 6f
            77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70
            73 20 33 2e 31 61 00 02 4c 4d 31 2e 32 58 30 30
            32 00 02 4c 41 4e 4d 41 4e 32 2e 31 00 02 4e 54
            20 4c 4d 20 30 2e 31 32 00
        }
        $smb_2 = {
            00 00 00 c8 ff 53 4d 42 73 00 00 00 00 18 03 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 3f b5 0c ff 00 c8 00 04 11 32 00 00 00 00
            00 00 00 28 00 00 00 00 00 d4 00 00 a0 8d 00 4e
            54 4c 4d 53 53 50 00 01 00 00 00 07 82 88 a2 00
            00 00 00 28 00 00 00 00 00 00 00 28 00 00 00 05
            01 28 0a 00 00 00 0f 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
        }
        $smbstr_1 = "\\x00\\x00\\x00\\x85\\xffSMBr\\x00\\x00\\x00\\x00\\x18S\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00\\xff\\xb4\\x00b\\x00\\x02PC NETWORK PROGRAM 1.0\\x00\\x02LANMAN1.0\\x00\\x02Windows for Workgroups 3.1a\\x00\\x02LM1.2X002\\x00\\x02LANMAN2.1\\x00\\x02NT LM 0.12\\x00"
        $smbstr_2 = "\\x00\\x00\\x00\\xc8\\xffSMBs\\x00\\x00\\x00\\x00\\x18\\x03\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00?\\xb5\\x0c\\xff\\x00\\xc8\\x00\\x04\\x112\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\xd4\\x00\\x00\\xa0\\x8d\\x00NTLMSSP\\x00\\x01\\x00\\x00\\x00\\x07\\x82\\x88\\xa2\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x05\\x01(\\n\\x00\\x00\\x00\\x0f\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"

        $code_1 = "return 'Other error.'" ascii wide
        $code_2 = "sblob = buf[47:47 + sbl]" ascii wide
        $code_3 = "re.split('[\\x00-,]+', y[-4])" ascii wide
        $code_4 = "('').join(sblob[off:off + hlen].split('\\x00'))" ascii wide
        $code_5 = "banner = '%s    %s' % (hostname, native)" ascii wide
        $code_6 = "banner = '%s\\\\%s    %s' % (dm, hostname, native)" ascii wide

        $tsk_1 = "PushTask" ascii wide
        $tsk_2 = "parse_task" ascii wide
        $tsk_3 = "commit_task" ascii wide

        $str_1 = "Usage: getos.py <ip-range|ip-file>" ascii wide
        $str_2 = "The path '%s' write fails." ascii wide
        $str_3 = "Receive a signal %d," ascii wide
        $str_4 = "Scan Complete!" ascii wide
        $str_5 = "line: %d, %s: %s" ascii wide
        $str_6 = "Other error." ascii wide

    condition:
        (all of ($smb_*)) or
        (all of ($smbstr_*)) or
        (3 of ($code_*)) or
        (all of ($tsk_*)) or
        (3 of ($str_*))
}