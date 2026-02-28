rule Malware_ARM_Bot_Generic {
    meta:
        description = "Nhận diện Botnet dòng Mirai/Gafgyt trên kiến trúc ARM"
        author = "Gemini_Researcher"
        date = "2026-02-28"
        file_type = "ELF 32-bit LSB ARM"

    strings:
        // Các hàm mạng đặc trưng đã phát hiện
        $func1 = "initConnection"
        $func2 = "connectTimeout"
        $func3 = "make_garbage"
        
        // Các hàm hệ thống thường bị lợi dụng
        $sys1 = "setresuid"
        $sys2 = "__libc_nanosleep"
        
        // Dấu hiệu của việc giải mã hoặc tấn công (thường có trong các bot này)
        $s1 = "invalid password" nocase
        $s2 = "REPORT %s:%s" // Chuỗi báo cáo về C2
        $s3 = "HTTP/1.1" // Dùng cho HTTP Flood

    condition:
        // Kiểm tra header ELF (7F 45 4C 46) và kiến trúc ARM (offset 18 là 0x28)
        uint32(0) == 0x464c457f and uint16(0x12) == 0x28 and
        
        // Phải có ít nhất 3 trong số các hàm đặc trưng
        3 of ($func*) and
        
        // Hoặc có các chuỗi tấn công kết hợp với hàm hệ thống
        (any of ($s*) and all of ($sys*))
}
