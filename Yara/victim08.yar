rule Botnet_Gafgyt_Mirai_Variant {
    meta:
        description = "Detects IoT Botnet variants (Gafgyt/Mirai) based on real-world analysis"
        author = "yae miko"
        date = "2026-02-28"
        reference = "Analysis from domain slursbeback.ru and 969B payload"

    strings:
        // 1. Characteristic handshake signature
        $handshake = "BOT\x01TAKE"
        
        // 2. System reconnaissance strings via /proc
        $proc_1 = "/proc/self/exe"
        $proc_2 = "/proc/net/tcp"
        $proc_3 = "/proc/stat"
        $proc_4 = "/proc/cmdline"
        
        // 3. Characteristic Brute-force password list
        $pass_1 = "7ujMko0admin"
        $pass_2 = "klv123"
        $pass_3 = "xc3511"
        $pass_4 = "rootroot"
        
        // 4. Additional payload download command
        $dlr = "GET/dlr."
        
        // 5. Command & Control (C2) domain
        $c2_domain = "slursbeback.ru"

    condition:
        // Activation condition: Must have handshake signature OR C2 domain
        // Accompanied by at least 3 reconnaissance or password indicators
        (uint16(0) == 0x457f or uint16(0) == 0x4c45) and // Check ELF file format (Linux)
        ($handshake or $c2_domain) and 
        (2 of ($proc_*) or 2 of ($pass_*)) or $dlr
}
