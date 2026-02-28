rule Malware_Lnx_DDoSia_NoName057_v2 {
    meta:
        description = "Detects DDoSia Botnet (NoName057(16)) Go version for ARM"
        author = "Gemini AI & Reverse Engineering Peer"
        date = "2026-02-28"
        version = "1.1"
        reference = "Analysis of sample d_lin_arm_wr - IP 35.67.150.230"
        severity = "Critical"

    strings:
        // 1. Characteristic FNV-1 hash algorithm we discovered (0x01000193)
        $fnv1_const = { 93 01 00 01 }

        // 2. Project identifier strings and operational mechanisms
        $str_project = "ddosia" nocase
        $str_ua = "User-Agent"
        $str_c2_path = "/client/login"
        
        // 3. Hex code segments related to ARM Syscall SVC (143 hits)
        // Scanning for typical SVC system call instructions used by this malware
        $arm_svc = { 80 ef ?? ?? } 

        // 4. Go Runtime characteristics (Statically Linked)
        $go_magic = "Go build ID:"
        $go_pclntab = { FB FF FF FF } // Magic number for Go pclntab table

    condition:
        // Conditions for file identification
        uint32(0) == 0x464c457f and // Must be ELF file (7f 45 4c 46)
        (
            (all of ($fnv1_const, $go_magic)) or // Contains hash algorithm and is Go
            (2 of ($str_project, $str_ua, $str_c2_path)) or // Contains sensitive strings
            ($arm_svc and $go_pclntab) // Contains characteristic SVC instruction combined with Go structures
        )
}
