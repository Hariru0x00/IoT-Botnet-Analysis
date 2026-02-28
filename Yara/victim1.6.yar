rule Gafgyt_Custom_SPARC_Hacker {
    meta:
        description = "Detects custom Gafgyt/Bashlite variant on SPARC architecture"
        author = "Security_Analyst"
        date = "2026-02-28"
        hash = "Victim_06_elf_hash"
        threat_level = "High"

    strings:
        /* Dấu hiệu nhận diện chuỗi đặc biệt của Hacker */
        $hacker_mark = "KHserverHACKER"
        
        /* Khóa XOR 4-byte (de de ff ba) dùng để giải mã IP và User-Agents */
        $xor_key = { DE DE FF BA }
        
        /* Các hàm tấn công DDoS đặc trưng của dòng này */
        $func_cf = "generate_cf_ray_http"
        $func_killer = "process_killer_loop"
        $func_obf = "toggle_obf"
        
        /* Chuỗi IP đã mã hóa XOR tại địa chỉ 0x1c419 (BGf.GG*b) */
        $encrypted_ip = { 9C 99 99 94 99 99 D5 D8 }

    condition:
        /* Kiểm tra định dạng file ELF và kiến trúc SPARC (Machine: 0x02) */
        uint32(0) == 0x464c457f and
        
        /* Kết hợp các điều kiện: Phải có dấu ấn hacker hoặc khóa XOR cùng các hàm tấn công */
        ($hacker_mark or ($xor_key and 2 of ($func_*))) and $encrypted_ip
}
