rule Prometei_PDB
{
    meta:
        id = "6RxW5l6ySxPS5K2HD7b6wX"
        fingerprint = "c9342fa61b7e5e711016dab5e6360e836726cf622feed88da92b7aaa4dd79f4a"
        version = "1.0"
        first_imported = "2023-03-24"
        last_modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies debug paths for Prometei botnet."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"

strings:
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\walker\\/ ascii wide
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\prometei\\/ ascii wide
    $ = /C:\\(Work|WORK)\\Tools_20[0-9]{2}\\misc\\/ ascii wide

condition:
    any of them
}

rule Prometei_Spreader
{
    meta:
        id = "EH3oMrAkcLfDxYgZXKd8o"
        fingerprint = "4eb71a189ef2651539d70f8202474394972a9dc0ad3218260c8af8a48e3ccdc5"
        version = "1.0"
        first_imported = "2023-03-24"
        last_modified = "2023-03-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SSH spreader used by Prometei botnet, specifically windrlver."
        category = "MALWARE"
        malware = "PROMETEI"
        malware_type = "BOT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"

strings:
    $code = {8a 01 41 84 c0 75 ?? 2b ce 8d 04 13 2b cb 03 c7 2b cf 51 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 83 c4 0c 33 db 8d 9b 00 00 00 00}

condition:
    $code
}