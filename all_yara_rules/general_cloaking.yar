rule EXE_cloaked_as_TXT {
	meta:
		description = "Executable with TXT extension"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		id = "2188c0fe-71b0-5dee-bde9-f310c66e39c6"
	condition:
		uint16(0) == 0x5a4d 					// Executable
		and filename matches /\.txt$/is   // TXT extension (case insensitive)
}

rule Gen_Base64_EXE: HIGHVOL {
   meta:
      description = "Detects Base64 encoded Executable in Executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-04-21"
      id = "ef919a63-9a29-5624-a084-b92e3578e3a6"
   strings:
      $s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" wide ascii // 14 samples
      $s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" wide ascii // 26 samples
      $s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" wide ascii // 75 samples
      $s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" wide ascii // 168 samples
      $s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii // 28,529 samples

      $fp1 = "BAM Management class library"
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and 1 of ($s*)
      and not 1 of ($fp*)
}

rule Binary_Drop_Certutil {
	meta:
		description = "Drop binary as base64 encoded cert trick"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/9DNn8q"
		date = "2015-07-15"
		score = 70
		id = "19791e51-d041-524d-80fa-9f3ec54eb084"
	strings:
		$s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
		$s1 = "echo -----END CERTIFICATE----- >>" ascii
		$s2 = "certutil -decode " ascii
	condition:
		filesize < 10KB and all of them
}

rule StegoKatz {
	meta:
		description = "Encoded Mimikatz in other file types"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/jWPBBY"
		date = "2015-09-11"
		score = 70
		id = "78868bb0-af69-573d-afd2-350a46f69137"
	strings:
		$s1 = "VC92Ny9TSXZMNk5jLy8vOUlqUTFVRlFNQTZMLysvdjlJaTh2L0ZUNXJBUUJJaTFRa1NFaUx6K2hWSS8vL1NJME44bklCQU9pZC92Ny9USTJjSkpBQUFBQXp3RW1MV3hCSmkyc1lTWXR6S0VtTDQxL0R6TXhNaTl4SmlWc0lUWWxMSUUySlF4aFZWbGRCVkVGVlFWWkJWMGlCN1BBQUFBQklnMlFrYUFDNE1BQUFBRW1MNkVTTmNPQ0pSQ1JnaVVRa1pFbU5RN0JKaTlsTWpRWFBGQU1BU0ls" ascii
		$s2 = "Rpd3ovN3FlalVtNklLQ0xNNGtOV1BiY0VOVHROT0Zud25CWGN0WS9BcEdMR28rK01OWm85Nm9xMlNnY1U5aTgrSTBvNkFob1FOTzRHQWdtUElEVmlqald0Tk90b2FmN01ESWJUQkF5T0pYbTB4bFVHRTBZWEFWOXVoNHBkQnRrS0VFWWVBSEE2TDFzU0c5a2ZFTEc3QWd4WTBYY1l3ZzB6QUFXS09JZE9wQVhEK3lnS3lsR3B5Q1ljR1NJdFNseGZKWUlVVkNFdEZPVjRJUldERUl1QXpKZ2pCQWdsd0Va" ascii
	condition:
		filesize < 1000KB and 1 of them
}

rule Obfuscated_VBS_April17 {
   meta:
      description = "Detects cloaked Mimikatz in VBS obfuscation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-04-21"
      id = "ca60b885-bb56-55ee-a2b3-dea6958883c2"
   strings:
      $s1 = "::::::ExecuteGlobal unescape(unescape(" ascii
   condition:
      filesize < 500KB and all of them
}