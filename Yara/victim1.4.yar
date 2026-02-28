rule Mirai_Gafgyt_GraphQL_Variant {
    meta:
        description = "Detects Gafgyt/Mirai variants targeting Layer 7 GraphQL"
        author = "Guuji"
        date = "2024-05-24"
        threat_level = "High"
        target_arch = "MIPS"

    strings:
        // 1. Characteristic GraphQL Payload strings found in the file
        $gql_1 = "{ id name email }"
        $gql_2 = "{ id title content }"
        $gql_3 = "{ id name price }"
        
        // 2. Characteristic bot control functions (Symbols)
        $func_1 = "process_killer_loop"
        $func_2 = "tcpFl00d"
        $func_3 = "dns_flood"
        $func_4 = "watchdog_maintain"
        $func_5 = "makevsepacket"

        // 3. Encrypted configuration signature (XOR 0xe0)
        // IP 193.199.93.31 (c1 c7 5d 1f) XOR 0xe0 = 21 27 bd ff
        $c2_encrypted = { 21 27 bd ff }

    condition:
        // Condition: Must be an ELF file and satisfy the above characteristics
        uint32(0) == 0x464c457f and 
        (
            (all of ($gql_*)) or 
            (3 of ($func_*)) or
            ($c2_encrypted)
        )
}
