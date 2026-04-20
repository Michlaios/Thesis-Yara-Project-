rule MAL_Xbash_PY_Sep18 {
   meta:
      description = "Detects Xbash malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18"
      hash1 = "7a18c7bdf0c504832c8552766dcfe0ba33dd5493daa3d9dbe9c985c1ce36e5aa"
      id = "97512fe8-002f-5cbc-a915-d55c087fbef7"
   strings:
      $s1 = { 73 58 62 61 73 68 00 00 00 00 00 00 00 00 } /* sXbash\x00\x00\x00\x00\x00\x00 */
   condition:
      uint16(0) == 0x457f and filesize < 10000KB and 1 of them
}

rule MAL_Xbash_JS_Sep18 {
   meta:
      description = "Detects XBash malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18"
      modified = "2023-01-06"
      hash1 = "f888dda9ca1876eba12ffb55a7a993bd1f5a622a30045a675da4955ede3e4cb8"
      id = "e891d146-f92d-5144-a1f2-ad308e309870"
   strings:
      $s1 = "var path=WSHShell" fullword ascii
      $s2 = "var myObject= new ActiveXObject(" ascii
      $s3 = "window.resizeTo(0,0)" fullword ascii
      $s4 = "<script language=\"JScript\">" fullword ascii /* Goodware String - occured 4 times */
   condition:
      filesize < 5KB and 3 of them
}