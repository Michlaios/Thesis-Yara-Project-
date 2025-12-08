rule FE_PCAPs
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT"
	date = "29/07/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0
}

rule pcap_positives
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT with +3 detection rate"
	date = "21/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and positives > 3
}

rule ek_submissions				
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
	date = "23/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and tags contains "exploit-kit"
}

rule ek_submissions_2				
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
	date = "23/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and tags contains "exploit-kit" and positives >3
}