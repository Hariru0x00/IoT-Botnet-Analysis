rule Gafgyt_Hitta_Variant {
    meta:
        description = "Detects Gafgyt/Bashlite (Hitta) variant from victim_08 sample"
        author = "toki"
        date = "2026-02-28"

    strings:
        // 1. TEA Delta constant (Little-endian)
        $tea_delta = { B9 79 37 9E } 

        // 2. Attack control commands
        $cmd_1 = "BOTKILL"
        $cmd_2 = "HTTP %s Flooding"
        $cmd_3 = "sendTCP"
        $cmd_4 = "sendHTTP"
        $cmd_5 = "sendUDP"

        // 3. Variant identifier name
        $moniker = "[CONNECTED] [HITTA]"

        // 4. Infection scripts
        $dropper_1 = "deltahaxsyeaok.sh"
        $dropper_2 = "ukloltftp1.sh"
        $dropper_3 = "ukloltftp2.sh"
        
        // 5. Disguised User-Agent signatures
        $ua_1 = "Mozilla/5.0 Slackware/13.37"
        $ua_2 = "Camino/1.5.4"

    condition:
        // Check ELF format
        uint32(0) == 0x464c457f and (
            $tea_delta or 
            $moniker or 
            // Use "any of" to reference all strings starting with $cmd, $dropper, $ua
            any of ($cmd_*) or 
            any of ($dropper_*) or
            any of ($ua_*)
        )
}
