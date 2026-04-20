rule AdGholas_mem
{
  meta:
      malfamily = "AdGholas"

  strings:
       $a1 = "(3e8)!=" ascii wide
       $a2 = /href=\x22\.\x22\+[a-z]+\,mimeType\}

rule AdGholas_mem_antisec_M2
{
  meta:
      malfamily = "AdGholas"
  strings:
      $s1 = "ActiveXObject(\"Microsoft.XMLDOM\")" nocase ascii wide
      $s2 = "loadXML" nocase ascii wide fullword
      $s3 = "parseError.errorCode" nocase ascii wide
      $s4 = /res\x3a\x2f\x2f[\x27\x22]\x2b/ nocase ascii wide
      $s5 = /\x251e3\x21\s*\x3d\x3d\s*[a-zA-Z]+\x3f1\x3a0/ nocase ascii wide 
  condition:
      all of ($s*)
}

rule AdGholas_mem_MIME_M2
{
  meta:
      malfamily = "AdGholas"
  strings:
      $s1 = "halog" nocase ascii wide fullword 
      $s2 = "pcap" nocase ascii wide fullword
      $s3 = "saz" nocase ascii wide fullword
      $s4 = "chls" nocase ascii wide fullword
      $s5 = /return[^\x3b\x7d\n]+href\s*=\s*[\x22\x27]\x2e[\x27\x22]\s*\+\s*[^\x3b\x7d\n]+\s*,\s*[^\x3b\x7d\n]+\.mimeType/ nocase ascii wide
      $s6 = /\x21==[a-zA-Z]+\x3f\x210\x3a\x211/ nocase ascii wide
  condition:
      all of ($s*)
}