rule Suspicious_PowerShell_Code_1 : FILE {
   meta:
      description = "Detects suspicious PowerShell code"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      id = "ec3c3682-d2de-52b7-bb49-b021ddf7f8ac"
   strings:
      $s1 = /$[a-z]=new-object net.webclient/ ascii
      $s2 = /$[a-z].DownloadFile\("http:/ ascii
      $s3 = /IEX $[a-zA-Z]{1,8}.downloadstring\(["']http/ ascii nocase
		$s4 = "powershell.exe -w hidden -ep bypass -Enc" ascii
		$s5 = "-w hidden -noni -nop -c \"iex(New-Object" ascii
		$s6 = "powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run" nocase
   condition:
      1 of them
}

rule PowerShell_in_Word_Doc {
   meta:
      description = "Detects a powershell and bypass keyword in a Word document"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - ME"
      date = "2017-06-27"
      score = 50
      hash1 = "4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905"
      id = "c9d073ff-25c6-5751-92bf-e22ae7cfd5f5"
   strings:
      $s1 = "POwErSHELl.ExE" fullword ascii nocase
      $s2 = "BYPASS" fullword ascii nocase
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}

rule WScript_Shell_PowerShell_Combo {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      score = 50
      hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
      id = "265ec471-d9ed-5cb6-a32b-cfa62fccdf64"
   strings:
      $s1 = ".CreateObject(\"WScript.Shell\")" ascii

      $p1 = "powershell.exe" fullword ascii
      $p2 = "-ExecutionPolicy Bypass" fullword ascii
      $p3 = "[System.Convert]::FromBase64String(" ascii

      $fp1 = "Copyright: Microsoft Corp." ascii
   condition:
      filesize < 400KB and $s1 and 1 of ($p*)
      and not 1 of ($fp*)
}

rule SUSP_PowerShell_String_K32_RemProcess {
   meta:
      description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/nccgroup/redsnarf"
      date = "2018-03-31"
      hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
      hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"
      id = "ad646e19-b132-5594-bea2-d74e96c06ebb"
   strings:
      $x1 = "Throw \"Unable to allocate memory in the remote process for shellcode\"" fullword ascii
      $x2 = "$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke(\"kernel32.dll\")" fullword ascii
      $s3 = "$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants." ascii
      $s7 = "if ($RemoteProcHandle -eq [IntPtr]::Zero)" fullword ascii
      $s8 = "if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))" fullword ascii
      $s9 = "$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, " ascii
      $s15 = "$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 6000KB and 1 of them
}

rule PowerShell_JAB_B64 {
   meta:
      description = "Detects base464 encoded $ sign at the beginning of a string"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
      date = "2018-04-02"
      score = 60
      id = "c18fa17b-aaa5-5a89-bc25-3cc51b5af103"
   strings:
      $s1 = "('JAB" ascii wide
      $s2 = "powershell" nocase
   condition:
      filesize < 30KB and all of them
}

rule SUSP_PS1_FromBase64String_Content_Indicator : FILE {
   meta:
      description = "Detects suspicious base64 encoded PowerShell expressions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639"
      date = "2020-01-25"
      id = "326c83ff-5d21-508f-b935-03ccdab6efa7"
   strings:
      $ = "::FromBase64String(\"H4s" ascii wide
      $ = "::FromBase64String(\"TVq" ascii wide
      $ = "::FromBase64String(\"UEs" ascii wide
      $ = "::FromBase64String(\"JAB" ascii wide
      $ = "::FromBase64String(\"SUVY" ascii wide
      $ = "::FromBase64String(\"SQBFAF" ascii wide
      $ = "::FromBase64String(\"SQBuAH" ascii wide
      $ = "::FromBase64String(\"PAA" ascii wide
      $ = "::FromBase64String(\"cwBhA" ascii wide
      $ = "::FromBase64String(\"aWV4" ascii wide
      $ = "::FromBase64String(\"aQBlA" ascii wide
      $ = "::FromBase64String(\"R2V0" ascii wide
      $ = "::FromBase64String(\"dmFy" ascii wide
      $ = "::FromBase64String(\"dgBhA" ascii wide
      $ = "::FromBase64String(\"dXNpbm" ascii wide
      $ = "::FromBase64String(\"H4sIA" ascii wide
      $ = "::FromBase64String(\"Y21k" ascii wide
      $ = "::FromBase64String(\"Qzpc" ascii wide
      $ = "::FromBase64String(\"Yzpc" ascii wide
      $ = "::FromBase64String(\"IAB" ascii wide

      $ = "::FromBase64String('H4s" ascii wide
      $ = "::FromBase64String('TVq" ascii wide
      $ = "::FromBase64String('UEs" ascii wide
      $ = "::FromBase64String('JAB" ascii wide
      $ = "::FromBase64String('SUVY" ascii wide
      $ = "::FromBase64String('SQBFAF" ascii wide
      $ = "::FromBase64String('SQBuAH" ascii wide
      $ = "::FromBase64String('PAA" ascii wide
      $ = "::FromBase64String('cwBhA" ascii wide
      $ = "::FromBase64String('aWV4" ascii wide
      $ = "::FromBase64String('aQBlA" ascii wide
      $ = "::FromBase64String('R2V0" ascii wide
      $ = "::FromBase64String('dmFy" ascii wide
      $ = "::FromBase64String('dgBhA" ascii wide
      $ = "::FromBase64String('dXNpbm" ascii wide
      $ = "::FromBase64String('H4sIA" ascii wide
      $ = "::FromBase64String('Y21k" ascii wide
      $ = "::FromBase64String('Qzpc" ascii wide
      $ = "::FromBase64String('Yzpc" ascii wide
      $ = "::FromBase64String('IAB" ascii wide
   condition:
      filesize < 5000KB and 1 of them
}