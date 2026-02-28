rule Linux_Botnet_MIPS_Mirai_Custom {
    meta:
        description = "Detects Mirai MIPS LE variant with Custom encoding table and Killer signature"
        author = "Reverse_Engineer"
        date = "2026-02-17"

    strings:
        // 1. File format signatures
        $elf_header = { 7F 45 4C 46 01 01 01 00 }
        
        // 2. Infrastructure signatures
        $c2_domain = "blueblackside.com" ascii
        $handshake = "TS3INIT1" ascii
        $custom_base32 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii
        
        // 3. Behavior signatures
        $watchdog = "/dev/watchdog" ascii
        $killer_msg = "listening tun0" ascii fullword

    condition:
        // Must be MIPS ELF file at offset 0
        $elf_header at 0 and 
        (
            // Match domain OR encoding table (very strong indicator)
            $c2_domain or $custom_base32 or
            // OR match at least 2 behavior/handshake signatures
            2 of ($handshake, $watchdog, $killer_msg)
        )
}
