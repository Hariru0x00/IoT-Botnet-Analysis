rule Malware_Lnx_DDoSia_NoName057_v2 {
    meta:
        description = "Nhận diện Botnet DDoSia (NoName057(16)) phiên bản Go cho ARM"
        author = "Gemini AI & Reverse Engineering Peer"
        date = "2026-02-28"
        version = "1.1"
        reference = "Phân tích mẫu d_lin_arm_wr - IP 35.67.150.230"
        severity = "Critical"

    strings:
        // 1. Thuật toán băm FNV-1 đặc trưng mà chúng ta tìm thấy (0x01000193)
        $fnv1_const = { 93 01 00 01 }

        // 2. Các chuỗi ký tự định danh dự án và cơ chế hoạt động
        $str_project = "ddosia" nocase
        $str_ua = "User-Agent"
        $str_c2_path = "/client/login"
        
        // 3. Các đoạn mã Hex liên quan đến Syscall SVC trên ARM (143 điểm hit)
        // Chúng ta quét tìm lệnh gọi hệ thống SVC điển hình của malware này
        $arm_svc = { 80 ef ?? ?? } 

        // 4. Các đặc trưng của Go Runtime (Statically Linked)
        $go_magic = "Go build ID:"
        $go_pclntab = { FB FF FF FF } // Magic number của bảng Go pclntab

    condition:
        // Điều kiện để xác định tệp
        uint32(0) == 0x464c457f and // Phải là tệp ELF (7f 45 4c 46)
        (
            (all of ($fnv1_const, $go_magic)) or // Có thuật toán băm và là Go
            (2 of ($str_project, $str_ua, $str_c2_path)) or // Có các chuỗi nhạy cảm
            ($arm_svc and $go_pclntab) // Có lệnh SVC đặc trưng kết hợp cấu trúc Go
        )
}
