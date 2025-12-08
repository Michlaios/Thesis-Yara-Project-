rule DridexCfgBotID
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex Bot ID"
		malfamily = "dridex"

    strings:
        $buf = /(\<cfg net)?=\"\d+\"\shash=.*bottickmin=\"\d+\"\sbottickmax=\"\d+\"\snodetickmin=\"\d+\"\snodetickmax=\"\d+\"\sport=\"\d+\"\sstatus=\"\d+\"\sbuild=\"\d+\"\>/s

    condition:
        $buf
}

rule DridexCfgNodeList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex node list"
		malfamily = "dridex"

    strings:
        $buf = /\<node\>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\<\/node\>/s

    condition:
        $buf
}