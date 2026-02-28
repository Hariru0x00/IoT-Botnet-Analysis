rule Mirai_Gafgyt_GraphQL_Variant {
    meta:
        description = "Nhận diện biến thể Gafgyt/Mirai tấn công Layer 7 GraphQL"
        author = "Security_Analyst"
        date = "2024-05-24"
        threat_level = "High"
        target_arch = "MIPS"

    strings:
        // 1. Các chuỗi GraphQL Payload đặc trưng tìm thấy trong file
        $gql_1 = "{ id name email }"
        $gql_2 = "{ id title content }"
        $gql_3 = "{ id name price }"
        
        // 2. Các hàm (Symbols) điều khiển bot đặc trưng
        $func_1 = "process_killer_loop"
        $func_2 = "tcpFl00d"
        $func_3 = "dns_flood"
        $func_4 = "watchdog_maintain"
        $func_5 = "makevsepacket"

        // 3. Dấu hiệu cấu hình bị mã hóa (XOR 0xe0)
        // IP 193.199.93.31 (c1 c7 5d 1f) XOR 0xe0 = 21 27 bd ff
        $c2_encrypted = { 21 27 bd ff }

    condition:
        // Điều kiện: Phải là file ELF và thỏa mãn các đặc điểm trên
        uint32(0) == 0x464c457f and 
        (
            (all of ($gql_*)) or 
            (3 of ($func_*)) or
            ($c2_encrypted)
        )
}
