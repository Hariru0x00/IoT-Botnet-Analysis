rule Botnet_Yakuza_NeTiS_Scanner {
    meta:
        description = "Nhận diện biến thể Botnet Yakuza (Scarface) chuyên quét Netis trên MIPS"
        author = "Security_Researcher"
        date = "2024-05-22"
        version = "1.0"
        threat_level = "Critical"
        impact = "DDoS, Network Scanning, Router Compromise"

    strings:
        /* --- Dấu hiệu định danh (Branding) --- */
        $brand_1 = "Self Rep Fucking NeTiS" ascii
        $brand_2 = "Thisity 0n Ur FuCkInG FoReHeAd" ascii
        $brand_3 = "We BiG L33T HaxErS" ascii
        $auth_key = "PozHlpiND4xPDPuGE6tq" ascii

        /* --- Chuỗi khai thác & Quét (Exploitation) --- */
        $exp_netis = "SNQUERY: 127.0.0.1" ascii
        $exp_dvr_1 = "/root/dvr_gui/" ascii
        $exp_dvr_2 = "/root/dvr_app/" ascii
        $telnet_port = { 00 00 00 17 } // Hex của Port 23

        /* --- Lệnh điều khiển mạng (Network Commands) --- */
        $cmd_1 = "M-SEARCH * HTTP/1.1" ascii
        $cmd_2 = "ssdp:discover" ascii
        $cmd_3 = "USER-AGENT: Google Chrome/60.0.3112.90" ascii

        /* --- Đặc trưng mã máy MIPS (MIPS Opcodes) --- */
        // Cú pháp nạp địa chỉ IP 8.8.8.8 (lui v0, 0x808; ori v0, v0, 0x808)
        $op_google_dns = { 3c 02 08 08 34 42 08 08 }
        
        // Kỹ thuật Position Independent Code (bal; addu gp, gp, ra)
        $op_pic_mips = { 04 11 00 01 [0-4] 03 9f e0 21 }

    condition:
        // Kiểm tra xem có phải định dạng ELF cho MIPS không
        uint32(0) == 0x464c457f and 
        (
            // Phát hiện ít nhất 2 chuỗi định danh hoặc 1 chuỗi + mã máy đặc trưng
            (2 of ($brand_*)) or 
            ($auth_key and $exp_netis) or
            ($op_google_dns and $exp_netis) or
            (all of ($exp_dvr*))
        )
}
