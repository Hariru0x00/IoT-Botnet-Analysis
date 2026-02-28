rule Gafgyt_MIPS_Variant_Feb2024 {
    meta:
        description = "Detects Gafgyt/Bashlite malware on MIPS architecture using XOR 0x21"
        author = "IoT Malware Analyst"
        date = "2024-02-28"
        architecture = "MIPS"
        target_platform = "Linux/IoT"

    strings:
        /* 1. Characteristic strings from Layer 7 attack module */
        $str_http_1 = "Mozilla/5.0 (%s) %s %s"
        $str_http_2 = "TSource Engine Query"
        $str_http_3 = "User-Agent:"
        $str_http_4 = "/admin/login"

        /* 2. Strings for Scanner Module */
        $str_scan_1 = "rootPon521"
        $str_scan_2 = "Zte521"
        $str_scan_3 = "ping; sh"
        $str_scan_4 = "/dev/null"

        /* 3. Machine code signatures (Opcode signatures) */
        // Connect Syscall load instruction (0x104a) in MIPS
        $op_connect = { 24 02 10 4a 00 00 00 0c }
        
        // Characteristic PRNG algorithm: load constant 0x08421085 and perform multiplication
        $op_prng = { 3c 05 08 42 34 a5 10 85 00 45 00 19 }

        // XOR decryption loop with key 0x21 (XORI $reg, $reg, 0x21)
        // Signature: Opcode 38 followed by byte 21
        $op_xor_key = { 38 ?? 00 21 } 

    condition:
        // Check for ELF file format (7F 45 4c 46)
        uint32(0) == 0x464c457f and
        
        // Detection condition: At least 2 signature groups present
        (
            (all of ($str_http_*)) or 
            (2 of ($str_scan_*)) or
            ($op_connect and $op_prng) or
            $op_xor_key
        )
}
