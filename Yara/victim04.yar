rule Malware_MIPS_FlyLegit_Gafgyt {
    meta:
        description = "Nhận diện biến thể Gafgyt/Mirai nhắm vào MIPS với chữ ký FlyLegit"
        author = "Gemini_Research_Collaborator"
        file_type = "ELF 32-bit LSB MIPS"

    strings:
        /* Nhóm 1: Chữ ký định danh */
        $c2_ip = "176.65.139.18" ascii fullword
        $telegram = "t.me/flylegit" ascii
        $arch = "mips" ascii fullword
        
        /* Nhóm 2: Lệnh điều khiển */
        $cmd_1 = "udpplain" ascii fullword
        $cmd_2 = "syn" ascii fullword
        $cmd_3 = "ping" ascii fullword
        $cmd_4 = "pong" ascii fullword
        
        /* Nhóm 3: Hành vi hệ thống */
        $proc_path = "/proc/%s/comm" ascii
        $self_exe = "/proc/self/exe" ascii

        /* Nhóm 4: Mã máy đặc trưng (Opcode) */
        $hex_checksum = { 97 a3 00 0a 97 a2 00 08 97 a9 00 0c 00 a0 50 21 }

    condition:
        /* Kiểm tra Header ELF */
        uint32(0) == 0x464c457f and
        (
            /* Điều kiện 1: Có thông tin kẻ tạo ra hoặc IP C2 */
            ($c2_ip or $telegram) or
            
            /* Điều kiện 2: Có ít nhất 3 lệnh điều khiển và kiến trúc mips */
            (3 of ($cmd_*) and $arch) or
            
            /* Điều kiện 3: Có mã máy checksum và các đường dẫn hệ thống nghi vấn */
            ($hex_checksum and ($proc_path or $self_exe))
        )
}
