import "elf"

rule Linux_Botnet_Gafgyt_SH4_Variant {
    meta:
        description = "Nhận diện biến thể mã độc Gafgyt/Mirai trên kiến trúc SH4"
        author = "Security_Analysis_Assistant"
        date = "2024-05-20"
        severity = "Critical"
        sample_ip = "50.183.49.88"

    strings:
        // 1. Các chuỗi đặc trưng dùng trong quét thiết bị (Discovery)
        $str_ssdp = "M-SEARCH * HTTP/1.1" ascii
        $str_ssdp_host = "ST: upnp:rootdevice" ascii
        $str_dns_query = "SNQUERY" ascii
        
        // 2. Các file hệ thống mà mã độc kiểm tra
        $path_dvr = "/root/dvr_app" ascii
        $path_watchdog = "/etc/watchdog" ascii

        // 3. Các đoạn mã máy đặc trưng của kiến trúc SH4 (Opcode)
        // mov 0x02, r5 (SOCK_DGRAM) kết hợp với jsr @rX (socket call)
        $op_udp_socket = { 02 E5 [0-4] 0B 4? }
        
        // mov 0x01, r5 (SOCK_STREAM) kết hợp với jsr @rX (socket call)
        $op_tcp_socket = { 01 E5 [0-4] 0B 4? }

        // Cấu trúc nạp địa chỉ C2 50.183.49.88 (0x00416304) từ Literal Pool
        $op_load_c2 = { D? ?? [0-2] 04 63 41 00 }

    condition:
        // Kiểm tra định dạng ELF và kiến trúc SH (EM_SH = 42)
        uint32(0) == 0x464c457f and elf.machine == 42 and
        (
            // Sử dụng các nhóm chuỗi để tránh lỗi "unreferenced"
            any of ($str_*) or 
            any of ($path_*) or
            any of ($op_*)
        )
}
