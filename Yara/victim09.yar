rule Malware_MIPS_Gafgyt_Mirai_Variant {
    meta:
        description = "Nhận diện biến thể Malware Gafgyt/Mirai trên kiến trúc MIPS"
        author = "Analysis_Assistant"
        date = "2024-05-21"
        file_type = "ELF MIPS"
        severity = "Critical"
        // Thêm các IOCs (Indicator of Compromise) chúng ta đã tìm thấy
        c2_ip_1 = "185.207.225.218"
        c2_ip_2 = "180.196.247.222"

    strings:
        // 1. Các chuỗi điều khiển không mã hóa
        $s1 = "TAKE" fullword
        $s2 = "/tmp/.h" fullword
        $s3 = "/dev/null" fullword

        // 2. Các chuỗi đặc trưng của module DDoS
        $d1 = "HTTPFLOOD"
        $d2 = "UDP"
        $d3 = "TCP"

        // 3. Dấu hiệu của Raw Sockets (MIPS Opcode)
        // Lệnh tạo socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        $op_raw_socket = { 24 04 00 02 24 05 00 03 24 06 00 12 }

        // 4. Các Key XOR đặc trưng (dạng hex cho chuẩn)
        $key1 = { 2e 67 6a 3d } // .gj=
        $key2 = { 27 60 71 3d } // '`q=

    condition:
        // Kiểm tra định dạng file ELF kiến trúc MIPS (Big Endian hoặc Little Endian)
        uint32(0) == 0x464c457f and 
        (uint16(0x12) == 0x0008 or uint16(0x12) == 0x0800) and
        
        // Điều kiện logic mới:
        (
            all of ($s*) or             // Có đủ TAKE, /tmp/.h, /dev/null
            $op_raw_socket or           // HOẶC có mã máy tạo Raw Socket
            any of ($key*) or           // HOẶC có các Key XOR đặc trưng
            2 of ($d*)                  // HOẶC có ít nhất 2 chuỗi tấn công (UDP, TCP, HTTP...)
        )
}
