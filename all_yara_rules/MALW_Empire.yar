rule Empire_Invoke_MetasploitPayload {
   meta:
      description = "Detects Empire component - file Invoke-MetasploitPayload.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a85ca27537ebeb79601b885b35ddff6431860b5852c6a664d32a321782808c54"
   strings:
      $s1 = "$ProcessInfo.Arguments=\"-nop -c $DownloadCradle\"" fullword ascii
      $s2 = "$PowershellExe=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 9KB and 1 of them ) or all of them
}

rule Empire_Invoke_PowerDump {
   meta:
      description = "Detects Empire component - file Invoke-PowerDump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "095c5cf5c0c8a9f9b1083302e2ba1d4e112a410e186670f9b089081113f5e0e1"
   strings:
      $x16 = "$enc = Get-PostHashdumpScript" fullword ascii
      $x19 = "$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;" fullword ascii
      $x20 = "$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);" fullword ascii
   condition:
      ( uint16(0) == 0x2023 and filesize < 60KB and 1 of them ) or all of them
}

rule Empire__Users_neo_code_Workspace_Empire_4sigs_PowerUp {
   meta:
      description = "Detects Empire component - file PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
   strings:
      $x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}

rule Empire_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - file Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
      $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_SmbScanner {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_dumpCredStore {
   meta:
      description = "Detects Empire component - file dumpCredStore.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c1e91a5f9cc23f3626326dab2dcdf4904e6f8a332e2bce8b9a0854b371c2b350"
   strings:
      $x1 = "[DllImport(\"Advapi32.dll\", SetLastError = true, EntryPoint = \"CredReadW\"" ascii
      $s12 = "[String] $Msg = \"Failed to enumerate credentials store for user '$Env:UserName'\"" fullword ascii
      $s15 = "Rtn = CredRead(\"Target\", CRED_TYPE.GENERIC, out Cred);" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 40KB and 1 of them ) or all of them
}

rule Empire_Invoke_EgressCheck {
   meta:
      description = "Detects Empire component - file Invoke-EgressCheck.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
   strings:
      $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Invoke_PsExec {
   meta:
      description = "Detects Empire component - file Invoke-PsExec.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
   strings:
      $s1 = "Invoke-PsExecCmd" fullword ascii
      $s2 = "\"[*] Executing service .EXE" fullword ascii
      $s3 = "$cmd = \"%COMSPEC% /C echo $Command ^> %systemroot%\\Temp\\" ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 50KB and 1 of them ) or all of them
}

rule Empire_Invoke_PostExfil {
   meta:
      description = "Detects Empire component - file Invoke-PostExfil.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
   strings:
      $s1 = "# upload to a specified exfil URI" fullword ascii
      $s2 = "Server path to exfil to." fullword ascii
   condition:
      ( uint16(0) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}

rule Empire_Invoke_SMBAutoBrute {
   meta:
      description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"
   strings:
      $s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
      $s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Get_Keystrokes {
   meta:
      description = "Detects Empire component - file Get-Keystrokes.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"
   strings:
      $s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig {
   meta:
      description = "Detects Empire component - file KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
   strings:
      $s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_SSHCommand {
   meta:
      description = "Detects Empire component - file Invoke-SSHCommand.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "cbaf086b14d5bb6a756cbda42943d4d7ef97f8277164ce1f7dd0a1843e9aa242"
   strings:
      $s1 = "$Base64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA" ascii
      $s2 = "Invoke-SSHCommand -ip 192.168.1.100 -Username root -Password test -Command \"id\"" fullword ascii
      $s3 = "Write-Verbose \"[*] Error loading dll\"" fullword ascii
   condition:
      ( uint16(0) == 0x660a and filesize < 2000KB and 1 of them ) or all of them
}

rule = 1
      hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
      hash2 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
   strings:
      $s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
      $s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
      $s3 = "if ($script:AgentDelay -ne 0){" fullword ascii
   condition:
      ( uint16(0) == 0x660a and filesize < 100KB and 1 of them ) or all of them
}