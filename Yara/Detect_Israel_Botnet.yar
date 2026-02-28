rule Detect_Israel_Botnet_Mirai_Variant {
    meta:
        author = "Security_Analyst_Termux"
        description = "Nhận diện biến thể Botnet Israel (Gafgyt/Mirai) - Đã sửa lỗi tham chiếu"
        severity = "Critical"

    strings:
        // 1. Tên file trên server 64.89.163.109
        $s1 = "israel.armv4l" ascii fullword
        $s2 = "israel.mips" ascii fullword
        $s3 = "israel.x86_64" ascii fullword
        $s4 = "cat.sh" ascii fullword

        // 2. Các hàm tấn công (DDoS Engine)
        $h1 = "sh4_flood" ascii
        $h2 = "udp_flood" ascii
        $h3 = "tcp_flood" ascii
        $h4 = "http_flood" ascii

        // 3. Dấu vết thiết bị IoT từ Pentest Report
        $d1 = "hi3511_dvr" ascii
        $d2 = "gmDVR" ascii
        $d3 = "dvr_main" ascii

        // 4. Lệnh C2
        $c1 = "LISTEN" ascii
        $c2 = "RESOLVE" ascii
        $c3 = "KILL" ascii fullword

        // 5. Đường dẫn hệ thống bị lộ (Path Disclosure)
        $p1 = "/proc/self/exe" ascii
        $p2 = "/dev/null" ascii
        $p3 = "/bin/bash" ascii

    condition:
        // Kiểm tra định dạng ELF (7F 45 4C 46)
        uint32(0) == 0x464c457f and
        (
            // Khớp ít nhất 2 tên file israel
            2 of ($s*) or 
            // Hoặc khớp ít nhất 2 hàm flood
            2 of ($h*) or
            // Hoặc khớp dấu vết DVR kết hợp với đường dẫn hệ thống
            (1 of ($d*) and 1 of ($p*)) or
            // Hoặc khớp lệnh C2 kết hợp với đường dẫn hệ thống
            (1 of ($c*) and any of ($p*))
        )
}
