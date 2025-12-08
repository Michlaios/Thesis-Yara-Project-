rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
        category = "INFO"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }

rule PS_in_LNK
{
    meta:
        id = "5PjnTrwMNGYdZahLd6yrPa"
        fingerprint = "d89b0413d59b57e5177261530ed1fb60f0f6078951a928caf11b2db1c2ec5109"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerShell artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = ".ps1" ascii wide nocase
        $ = "powershell" ascii wide nocase
        $ = "invoke" ascii wide nocase
        $ = "[Convert]" ascii wide nocase
        $ = "FromBase" ascii wide nocase
        $ = "-exec" ascii wide nocase
        $ = "-nop" ascii wide nocase
        $ = "-noni" ascii wide nocase
        $ = "-w hidden" ascii wide nocase
        $ = "-enc" ascii wide nocase
        $ = "-decode" ascii wide nocase
        $ = "bypass" ascii wide nocase

    condition:
        isLNK and 2 of them
}

rule Script_in_LNK
{
    meta:
        id = "24OwxeALdNyMpIq2oeeatL"
        fingerprint = "bed7b00cdd2966629d9492097d357b729212d6d90251b9f1319634af05f40fdc"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies scripting artefacts in shortcut (LNK) files."
        category = "INFO"

    strings:
        $ = "javascript" ascii wide nocase
        $ = "jscript" ascii wide nocase
        $ = "vbscript" ascii wide nocase
        $ = "wscript" ascii wide nocase
        $ = "cscript" ascii wide nocase
        $ = ".js" ascii wide nocase
        $ = ".vb" ascii wide nocase
        $ = ".wsc" ascii wide nocase
        $ = ".wsh" ascii wide nocase
        $ = ".wsf" ascii wide nocase
        $ = ".sct" ascii wide nocase
        $ = ".cmd" ascii wide nocase
        $ = ".hta" ascii wide nocase
        $ = ".bat" ascii wide nocase
        $ = "ActiveXObject" ascii wide nocase
        $ = "eval" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Large_filesize_LNK
{
    meta:
        id = "2N6jerukOyU2qFFtcMtnWt"
        fingerprint = "a8168e65294bfc0b9ffca544891b818b37feb5b780ab357efbb56638c6578242"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file larger than 100KB. Most goodware LNK files are smaller than 100KB."
        category = "INFO"

    condition:
        isLNK and filesize >100KB
}

rule WebDAV_in_LNK
{
    meta:
        id = "1Be4RxPZQBGIyDOiKzgw"
        fingerprint = "v1_sha256_ee6d3555011e9eec0b9724327fc17394c45f985249a5a3ce000cad505399a10b"
        version = "1.0"
        date = "2025-11-20"
        modified = "2025-11-20"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WebDAV in shortcut (LNK) file."
        category = "INFO"

    strings:
        $ = "\\DavWWWRoot\\" ascii wide nocase
        $ = "\\webdav\\" ascii wide nocase

    condition:
        isLNK and any of them
}