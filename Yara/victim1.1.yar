rule Gafgyt_Bashlite_MIPS_IoT {
    meta:
        description = "Nhận diện biến thể Gafgyt/Bashlite nhắm vào IP Camera (MIPS)"
        author = "Phân tích bởi User & Gemini"
        date = "2024-05-21"
        arch = "MIPS"
        severity = "High"

    strings:
        // 1. Các chuỗi đặc trưng (đã giải mã XOR 0x20)
        $c2_domain = "CONNECTIVITY.ACCESSCAM.ORG"
        $resolv = "ETC.RESOLV.CONF"
        $nameserver = "NAMESERVER"
        
        // 2. Các chuỗi chống ảo hóa (Anti-Analysis)
        $anti_virt_1 = "VIRTIO"
        $anti_virt_2 = "VIRTBLK"
        $anti_virt_3 = "HYPERVISOR"
        $anti_virt_4 = "VFIO"
        
        // 3. Các chuỗi hành vi hệ thống
        $oom_adj = "OOM_SCORE_ADJ"
        $proc_dev = "DEVICES"
        $cpu_info = "CPUINFO"

        // 4. Bảng chữ cái Base64 tùy chỉnh
        $custom_b64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        // 5. Đặc điểm nhận dạng file ELF
        $elf_header = { 7F 45 4C 46 } 

    condition:
        // Kiểm tra header ELF ở vị trí bắt đầu file
        $elf_header at 0 and
        
        // Kiểm tra kiến trúc MIPS (Machine type EM_MIPS = 8)
        uint16(18) == 8 and
        
        // Sử dụng TẤT CẢ các chuỗi còn lại để tránh lỗi unreferenced
        (
            $c2_domain or 
            ($resolv and $nameserver) or
            2 of ($anti_virt_*) or
            all of ($proc_dev, $cpu_info, $oom_adj) or
            $custom_b64
        )
}
