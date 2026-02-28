rule Malware_Yakuza_Scarface_MIPS_v2 {
    meta:
        description = "Nhận diện biến thể Yakuza Botnet (Scarface) trên kiến trúc MIPS"
        author = "Gemini AI"
        date = "2024-05-22"
        severity = "Critical"

    strings:
        // 1. Chuỗi định danh bí mật
        $auth_key = "PozHlpiND4xPDPuGE6tq"
        
        // 2. Các chuỗi thương hiệu
        $brand1 = "YakuzaBotnet"
        $brand2 = "Scarface1337"
        $brand3 = "Self Rep Fucking NeTiS"
        
        // 3. Các lệnh điều khiển
        $cmd1 = "UDPRAW" fullword
        $cmd2 = "RANDHEX" fullword
        $cmd3 = "SendSTD" fullword
        $cmd4 = "GETLOCALIP" fullword
        
        // 4. Các User-Agent
        $ua1 = "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)"
        $ua2 = "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30"
        
        // 5. Byte ký hiệu module UDPRAW
        $udp_magic = { 38 46 4a 93 49 44 9a }

    condition:
        // Kiểm tra định dạng ELF (7F 45 4c 46)
        uint32(0) == 0x464c457f and (
            // Thỏa mãn 1 trong các điều kiện nhận diện đặc hiệu
            $auth_key or 
            $udp_magic or
            (2 of ($brand*)) or 
            (2 of ($cmd*)) or
            // Thêm dòng này để giải quyết lỗi unreferenced string
            (1 of ($ua*))
        )
}
