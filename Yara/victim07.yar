rule Malware_ADB_DDoS_Botnet_Gafgyt_Variant {
    meta:
        description = "Detects Gafgyt DDoS Botnet variant spreading via ADB with miner killer module"
        author = "Ei"
        date = "2026-02-16"
        version = "1.1"
        threat_level = "Critical"
        usage = "Scan suspicious ELF files on Linux/Android systems"

    strings:
        // 1. Characteristic identifiers
        $token = "GDQDPROJH" ascii wide nocase
        $magic_xor_load = { 22 30 a0 e3 } // mov r3, 0x22 (Decryption key found at 0x181f8)

        // 2. ADB infection module (Spreader)
        $adb_cmd = "shell:cd /data/local/tmp/; busybox wget" ascii wide
        $adb_script = "adb-shell.sh" ascii wide
        $c2_url = "http://130.12.180.151" ascii wide

        // 3. Competitor killer module (Process Killer)
        $killer_1 = "kdevtmpfsi" ascii wide
        $killer_2 = "xmrig" ascii wide
        $killer_3 = "kinsing" ascii wide
        $killer_4 = "cpuminer" ascii wide
        $killer_5 = ".uhavenobotsxd" ascii wide

        // 4. Attack command parser module
        $debug_log_1 = "[DEBUG_MODE_ATTACK] attack_parse:" ascii wide
        $debug_log_2 = "starting attack vector=%u duration=%u targets=%u" ascii wide
        $debug_log_3 = "received %d bytes" ascii wide

        // 5. HTTP Flood attack module
        $http_header = "HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: %s" ascii wide
        $ua_firefox = "Gecko/20100101 Firefox/147.0" ascii wide

    condition:
        // Check ELF file format (Header: 7F 45 4C 46)
        uint32(0) == 0x464c457f and
        
        (
            // Case 1: Contains identifier token and XOR key (Highly characteristic)
            ($token and $magic_xor_load) or

            // Case 2: Contains ADB infection script and server URL
            ($adb_cmd and ($adb_script or $c2_url)) or

            // Case 3: Contains Debug Log strings and miner killer module
            (any of ($debug_log_*) and 2 of ($killer_*)) or

            // Case 4: Contains specific HTTP attack structure
            ($http_header and $ua_firefox)
        )
}
