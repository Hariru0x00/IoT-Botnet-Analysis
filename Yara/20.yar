import "elf"

rule Mirai_Gafgyt_SuperRule_Combined {
    meta:
        description = "Quy tắc tổng hợp nhận diện chiến dịch Botnet Mirai/Gafgyt từ 22 tệp mẫu - Fixed Version"
        author = "Security Analysis Assistant"
        version = "2.1"
        severity = "Critical"

    strings:
        /* --- NHÓM 1: HẠ TẦNG C2 & DOMAINS (IOCs) --- */
        $c2_1 = "ciobabaservices.duckdns.org" ascii wide
        $c2_2 = "slursbeback.ru" ascii wide
        $c2_3 = "blueblackside.com" ascii
        $c2_4 = "connectivity.accesscam.org" ascii
        $c2_5 = "hakaiboatnet.pw" ascii
        $c2_6 = "intranet.milnetstresser.ru" ascii
        $c2_7 = "130.12.180.151" ascii
        $c2_8 = "141.98.10.50" ascii
        $c2_ip_hex = { 32 B7 31 58 } // 50.183.49.88 (encoded)

        /* --- NHÓM 2: ĐẶC TRƯNG KIẾN TRÚC CPU (OPCODES) --- */
        $op_sh4_socket = { 02 E5 [0-6] 0B 4? }
        $op_mips_connect = { 24 02 10 4a 00 00 00 0c }
        $op_arm_svc = { 80 ef ?? ?? } 
        $hacker_mark = "KHserverHACKER"

        /* --- NHÓM 3: HÀNH VI HỆ THỐNG & ANTI-ANALYSIS --- */
        $sys_1 = "/proc/self/exe" ascii
        $sys_2 = "/dev/watchdog" ascii
        $sys_3 = "/proc/net/tcp" ascii
        $sys_4 = "OOM_SCORE_ADJ" ascii
        $anti_virt = "HYPERVISOR" ascii // Biến đã gây lỗi trước đó
        
        /* --- NHÓM 4: MODULE TẤN CÔNG & KILLER --- */
        $killer_1 = "kdevtmpfsi" ascii wide
        $killer_2 = "xmrig" ascii wide
        $killer_3 = "kinsing" ascii wide
        $attack_1 = "HTTPFLOOD" ascii
        $attack_2 = "sh4_flood" ascii
        $attack_3 = "{ id name email }" // GraphQL variant

        /* --- NHÓM 5: BẢNG MÃ & TOKEN ĐẶC TRƯNG --- */
        $token = "GDQDPROJH" ascii wide nocase
        $custom_b32 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        $go_magic = "Go build ID:"

    condition:
        // 1. Kiểm tra định dạng ELF
        uint32(0) == 0x464c457f and
        (
            // 2. Ưu tiên khớp hạ tầng C2 hoặc Token định danh
            any of ($c2_*) or $token or $custom_b32 or $hacker_mark or
            
            // 3. Hoặc khớp cơ chế chống ảo hóa + hành vi hệ thống
            ($anti_virt and any of ($sys_*)) or
            
            // 4. Hoặc kết hợp Kiến trúc CPU + Hành vi + Tấn công
            (
                any of ($op_*) and 
                2 of ($sys_*) and 
                (any of ($attack_*) or any of ($killer_*))
            ) or
            
            // 5. Đặc trưng mã nguồn Go
            ($go_magic and any of ($attack_*))
        )
}
