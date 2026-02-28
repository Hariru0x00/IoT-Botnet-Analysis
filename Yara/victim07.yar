rule Malware_ADB_DDoS_Botnet_Gafgyt_Variant {
    meta:
        description = "Phát hiện biến thể Botnet DDoS Gafgyt lây nhiễm qua ADB và có module diệt miner"
        author = "Reverse Engineering Assistant"
        date = "2026-02-16"
        version = "1.1"
        threat_level = "Critical"
        usage = "Quét các file ELF nghi ngờ trên hệ thống Linux/Android"

    strings:
        // 1. Dấu hiệu nhận biết đặc trưng (Identifiers)
        $token = "GDQDPROJH" ascii wide nocase
        $magic_xor_load = { 22 30 a0 e3 } // mov r3, 0x22 (Khóa giải mã tìm thấy tại 0x181f8)

        // 2. Module lây nhiễm qua ADB (Spreader)
        $adb_cmd = "shell:cd /data/local/tmp/; busybox wget" ascii wide
        $adb_script = "adb-shell.sh" ascii wide
        $c2_url = "http://130.12.180.151" ascii wide

        // 3. Module diệt đối thủ (Process Killer)
        $killer_1 = "kdevtmpfsi" ascii wide
        $killer_2 = "xmrig" ascii wide
        $killer_3 = "kinsing" ascii wide
        $killer_4 = "cpuminer" ascii wide
        $killer_5 = ".uhavenobotsxd" ascii wide

        // 4. Module phân tích lệnh tấn công (Attack Parser)
        $debug_log_1 = "[DEBUG_MODE_ATTACK] attack_parse:" ascii wide
        $debug_log_2 = "starting attack vector=%u duration=%u targets=%u" ascii wide
        $debug_log_3 = "received %d bytes" ascii wide

        // 5. Module tấn công HTTP Flood
        $http_header = "HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: %s" ascii wide
        $ua_firefox = "Gecko/20100101 Firefox/147.0" ascii wide

    condition:
        // Kiểm tra định dạng file ELF (Header: 7F 45 4C 46)
        uint32(0) == 0x464c457f and
        
        (
            // Trường hợp 1: Có chứa Token định danh và khóa XOR (Rất đặc trưng)
            ($token and $magic_xor_load) or

            // Trường hợp 2: Có chứa kịch bản lây nhiễm ADB và URL máy chủ
            ($adb_cmd and ($adb_script or $c2_url)) or

            // Trường hợp 3: Có các chuỗi Log Debug và module diệt miner
            (any of ($debug_log_*) and 2 of ($killer_*)) or

            // Trường hợp 4: Có cấu trúc tấn công HTTP đặc thù
            ($http_header and $ua_firefox)
        )
}
