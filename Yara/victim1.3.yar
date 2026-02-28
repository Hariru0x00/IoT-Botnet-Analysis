rule Linux_Botnet_MIPS_Mirai_Custom {
    meta:
        description = "Phát hiện biến thể Mirai MIPS LE với bảng mã Custom và dấu hiệu Killer"
        author = "Reverse_Engineer_Termux"
        date = "2026-02-17"

    strings:
        // 1. Dấu hiệu định dạng file
        $elf_header = { 7F 45 4C 46 01 01 01 00 }
        
        // 2. Dấu hiệu hạ tầng (Infrastructure)
        $c2_domain = "blueblackside.com" ascii
        $handshake = "TS3INIT1" ascii
        $custom_base32 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        
        // 3. Dấu hiệu hành vi (Behavior)
        $watchdog = "/dev/watchdog" ascii
        $killer_msg = "listening tun0" ascii fullword

    condition:
        // Phải là file ELF MIPS ở offset 0
        $elf_header at 0 and 
        (
            // Khớp domain HOẶC bảng mã (dấu hiệu cực mạnh)
            $c2_domain or $custom_base32 or
            // HOẶC khớp ít nhất 2 dấu hiệu hành vi/handshake
            2 of ($handshake, $watchdog, $killer_msg)
        )
}
