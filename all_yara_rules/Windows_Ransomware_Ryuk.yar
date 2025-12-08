rule Windows_Ransomware_Ryuk_25d3c5ba : beta {
    meta:
        author = "Elastic Security"
        id = "25d3c5ba-8f80-4af0-8a5d-29c974fb016a"
        fingerprint = "18e70599e3a187e77697844fa358dd150e7e25ac74060e8c7cf2707fb7304efd"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $g1 = { 41 8B C0 45 03 C7 99 F7 FE 48 63 C2 8A 4C 84 20 }
    condition:
        1 of ($g*)
}

rule Windows_Ransomware_Ryuk_1a4ad952 : beta {
    meta:
        author = "Elastic Security"
        id = "1a4ad952-cc99-4653-932b-290381e7c871"
        fingerprint = "d8c5162850e758e27439e808e914df63f42756c0b8f7c2b5f9346c0731d3960c"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $e1 = { 8B 0A 41 8D 45 01 45 03 C1 48 8D 52 08 41 3B C9 41 0F 45 C5 44 8B E8 49 63 C0 48 3B C3 72 E1 }
    condition:
        1 of ($e*)
}

rule Windows_Ransomware_Ryuk_72b5fd9d : beta {
    meta:
        author = "Elastic Security"
        id = "72b5fd9d-23db-4f18-88d9-a849ec039135"
        fingerprint = "7c394aa283336013b74a8aaeb56e8363033958b4a1bd8011f3b32cfe2d37e088"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $d1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Ryuk_88daaf8e : beta {
    meta:
        author = "Elastic Security"
        id = "88daaf8e-0bfe-46c4-9a75-2527d0e10538"
        fingerprint = "b1f218a9bc6bf5f3ec108a471de954988e7692de208e68d7d4ee205194cbbb40"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $f1 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }
    condition:
        1 of ($f*)
}