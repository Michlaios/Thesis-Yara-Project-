rule Empire_portscan {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"
		id = "23a0f769-9155-5aa0-9200-2baf827bdda4"
	strings:
		$s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii 
		$s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii 
	condition:
		filesize < 14KB and all of them
}

rule Empire_Write_HijackDll {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "155fa7168e28f15bb34f67344f47234a866e2c63b3303422ff977540623c70bf"
		id = "6a80af21-fb01-5996-b14d-44ff55b7fb3e"
	strings:
		$s1 = "$DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString \"debug.bat\" -ReplaceString $BatchPath" fullword ascii 
		$s2 = "$DllBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii 
		$s3 = "[Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)" fullword ascii 
	condition:
		filesize < 500KB and 2 of them
}

rule Empire_skeleton_key {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "3d02f16dcc38faaf5e97e4c5dbddf761f2816004775e6af8826cde9e29bb750f"
		id = "d508e09e-13e8-5866-bb5b-0d886f960bb5"
	strings:
		$s1 = "script += \"Invoke-Mimikatz -Command '\\\"\" + command + \"\\\"';\"" fullword ascii 
		$s2 = "script += '\"Skeleton key implanted. Use password \\'mimikatz\\' for access.\"'" fullword ascii 
		$s3 = "command = \"misc::skeleton\"" fullword ascii 
		$s4 = "\"ONLY APPLICABLE ON DOMAIN CONTROLLERS!\")," fullword ascii 
	condition:
		filesize < 6KB and 2 of them
}