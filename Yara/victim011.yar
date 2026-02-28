import "elf"

rule Linux_Gafgyt_Mirai_SH4_Botnet {
    meta:
        description = "Phát hiện biến thể mã độc Botnet Gafgyt/Mirai trên kiến trúc SH4"
        author = "Security_Analysis_Assistant"
        threat_level = "Critical"
        target_arch = "Hitachi SH"
        c2_ip = "50.183.49.88"
        date = "2024-05-20"

    strings:
        /* 1. Các chuỗi đặc trưng của Module Discovery (Quét thiết bị) */
        $str_ssdp_1 = "M-SEARCH * HTTP/1.1" ascii
        $str_ssdp_2 = "ST: upnp:rootdevice" ascii
        $str_dns = "SNQUERY" ascii

        /* 2. Các đường dẫn file hệ thống mục tiêu (Target/Anti-Analysis) */
        $path_dvr = "/root/dvr_app" ascii
        $path_watchdog = "/etc/watchdog" ascii

        /* 3. Dấu hiệu mã máy (Opcodes) đặc trưng trên kiến trúc SH4 */
        
        // Module UDP Flood: mov 0x02, r5 (SOCK_DGRAM) + jsr (gọi socket)
        $op_udp_flood = { 02 E5 [0-6] 0B 4? }

        // Module TCP Flood: mov 0x01, r5 (SOCK_STREAM) + jsr (gọi socket)
        $op_tcp_flood = { 01 E5 [0-6] 0B 4? }

        // Cấu trúc nạp địa chỉ IP C2 (50.183.49.88) từ Literal Pool
        // Địa chỉ: 0x00416304 -> Little Endian: 04 63 41 00
        $op_load_c2_config = { D? ?? [0-2] 04 63 41 00 }

    condition:
        // Kiểm tra định dạng file là ELF và kiến trúc là SH (Machine ID: 42)
        uint32(0) == 0x464c457f and 
        elf.machine == 42 and
        (
            // Khớp bất kỳ chuỗi quét mạng hoặc đường dẫn hệ thống nào
            any of ($str_*) or 
            any of ($path_*) or
            
            // Hoặc khớp các dấu hiệu mã máy của module tấn công
            all of ($op_*)
        )
}
