rule OPCLEAVER_SynFlooder
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "bdaf02f4-1226-569b-9f55-999be7ff397a"
	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "s IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."
	condition:
		all of them
}

rule OPCLEAVER_kagent
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "32d20495-eeed-5b2b-915d-cad60fa991f6"
	strings:
		$s1 = "kill command is in last machine, going back"
		$s2 = "message data length in B64: %d Bytes"
	condition:
		all of them
}

rule OPCLEAVER_wndTest
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "f8daa0a8-f0f0-5bf7-b9ab-eaf5335ff2b9"
	strings:
		$s1 = "[Alt]" wide
		$s2 = "<< %s >>:" wide
		$s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
	condition:
		all of them
}

rule OPCLEAVER_Parviz_Developer
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "2bfa90a0-0495-5b21-98f7-5ed7ebc74b2d"
	strings:
		$s1 = "Users\\parviz\\documents\\" nocase
	condition:
		$s1
}