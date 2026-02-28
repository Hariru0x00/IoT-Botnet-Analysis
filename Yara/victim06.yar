rule Gafgyt_MIPS_Variant_Feb2024 {
    meta:
        description = "Nhận diện mã độc Gafgyt/Bashlite trên kiến trúc MIPS sử dụng XOR 0x21"
        author = "Phân tích Malware IoT"
        date = "2024-02-28"
        architecture = "MIPS"
        target_platform = "Linux/IoT"

    strings:
        /* 1. Các chuỗi đặc trưng của module tấn công Layer 7 */
        $str_http_1 = "Mozilla/5.0 (%s) %s %s"
        $str_http_2 = "TSource Engine Query"
        $str_http_3 = "User-Agent:"
        $str_http_4 = "/admin/login"

        /* 2. Các chuỗi phục vụ Module Quét (Scanner) */
        $str_scan_1 = "rootPon521"
        $str_scan_2 = "Zte521"
        $str_scan_3 = "ping; sh"
        $str_scan_4 = "/dev/null"

        /* 3. Chữ ký mã máy (Opcode signatures) */
        // Lệnh nạp Syscall Connect (0x104a) trong MIPS
        $op_connect = { 24 02 10 4a 00 00 00 0c }
        
        // Thuật toán PRNG đặc trưng: nạp hằng số 0x08421085 và thực hiện phép nhân
        $op_prng = { 3c 05 08 42 34 a5 10 85 00 45 00 19 }

        // Vòng lặp giải mã XOR với khóa 0x21 (XORI $reg, $reg, 0x21)
        // Dấu hiệu: Opcode 38 kèm theo byte 21
        $op_xor_key = { 38 ?? 00 21 } 

    condition:
        // Kiểm tra file định dạng ELF (7F 45 4c 46)
        uint32(0) == 0x464c457f and
        
        // Điều kiện nhận diện: Có ít nhất 2 nhóm dấu hiệu xuất hiện
        (
            (all of ($str_http_*)) or 
            (2 of ($str_scan_*)) or
            ($op_connect and $op_prng) or
            $op_xor_key
        )
}
