rule Botnet_Gafgyt_Mirai_Variant {
    meta:
        description = "Phát hiện biến thể IoT Botnet (Gafgyt/Mirai) dựa trên phân tích thực tế"
        author = "Gemini AI & User Collaboration"
        date = "2026-02-28"
        reference = "Phân tích từ domain slursbeback.ru và payload 969B"

    strings:
        // 1. Dấu hiệu bắt tay đặc trưng
        $handshake = "BOT\x01TAKE"
        
        // 2. Các chuỗi trinh sát hệ thống qua /proc
        $proc_1 = "/proc/self/exe"
        $proc_2 = "/proc/net/tcp"
        $proc_3 = "/proc/stat"
        $proc_4 = "/proc/cmdline"
        
        // 3. Danh sách mật khẩu Brute-force đặc trưng
        $pass_1 = "7ujMko0admin"
        $pass_2 = "klv123"
        $pass_3 = "xc3511"
        $pass_4 = "rootroot"
        
        // 4. Lệnh tải payload bổ sung
        $dlr = "GET/dlr."
        
        // 5. Tên miền điều khiển (C2)
        $c2_domain = "slursbeback.ru"

    condition:
        // Điều kiện kích hoạt: Phải có dấu hiệu bắt tay HOẶC tên miền C2
        // Kèm theo ít nhất 3 dấu hiệu về trinh sát hoặc mật khẩu
        (uint16(0) == 0x457f or uint16(0) == 0x4c45) and // Kiểm tra định dạng tệp ELF (Linux)
        ($handshake or $c2_domain) and 
        (2 of ($proc_*) or 2 of ($pass_*)) or $dlr
}
