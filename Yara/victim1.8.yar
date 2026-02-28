rule Gafgyt_Hitta_Variant {
    meta:
        description = "Nhận diện biến thể Gafgyt/Bashlite (Hitta) từ mẫu victim_08"
        author = "Gemini AI"
        date = "2026-02-28"

    strings:
        // 1. Hằng số Delta của TEA (Little-endian)
        $tea_delta = { B9 79 37 9E } 

        // 2. Các lệnh điều khiển tấn công
        $cmd_1 = "BOTKILL"
        $cmd_2 = "HTTP %s Flooding"
        $cmd_3 = "sendTCP"
        $cmd_4 = "sendHTTP"
        $cmd_5 = "sendUDP"

        // 3. Tên định danh biến thể
        $moniker = "[CONNECTED] [HITTA]"

        // 4. Các kịch bản lây nhiễm
        $dropper_1 = "deltahaxsyeaok.sh"
        $dropper_2 = "ukloltftp1.sh"
        $dropper_3 = "ukloltftp2.sh"
        
        // 5. Dấu hiệu User-Agent ngụy trang
        $ua_1 = "Mozilla/5.0 Slackware/13.37"
        $ua_2 = "Camino/1.5.4"

    condition:
        // Kiểm tra định dạng ELF
        uint32(0) == 0x464c457f and (
            $tea_delta or 
            $moniker or 
            // Sử dụng "any of" để tham chiếu tất cả chuỗi bắt đầu bằng $cmd, $dropper, $ua
            any of ($cmd_*) or 
            any of ($dropper_*) or
            any of ($ua_*)
        )
}
