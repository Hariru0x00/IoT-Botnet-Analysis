rule Malware_Yakuza_Scarface_MIPS_v2 {
    meta:
        description = "Detects Yakuza Botnet (Scarface) variants on MIPS architecture"
        author = "hatoky"
        date = "2024-05-22"
        severity = "Critical"

    strings:
        // 1. Secret authentication key
        $auth_key = "PozHlpiND4xPDPuGE6tq"
        
        // 2. Branding strings
        $brand1 = "YakuzaBotnet"
        $brand2 = "Scarface1337"
        $brand3 = "Self Rep Fucking NeTiS"
        
        // 3. Control commands
        $cmd1 = "UDPRAW" fullword
        $cmd2 = "RANDHEX" fullword
        $cmd3 = "SendSTD" fullword
        $cmd4 = "GETLOCALIP" fullword
        
        // 4. User-Agents
        $ua1 = "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)"
        $ua2 = "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30"
        
        // 5. UDPRAW module signature bytes
        $udp_magic = { 38 46 4a 93 49 44 9a }

    condition:
        // Check for ELF format (7F 45 4c 46)
        uint32(0) == 0x464c457f and (
            // Satisfy one of the specific identification conditions
            $auth_key or 
            $udp_magic or
            (2 of ($brand*)) or 
            (2 of ($cmd*)) or
            // Add this line to resolve unreferenced string error
            (1 of ($ua*))
        )
}
