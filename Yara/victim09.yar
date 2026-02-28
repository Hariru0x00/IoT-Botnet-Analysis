rule Malware_MIPS_Gafgyt_Mirai_Variant {
    meta:
        description = "Detects Gafgyt/Mirai malware variants on MIPS architecture"
        author = "Hinata"
        date = "2024-05-21"
        file_type = "ELF MIPS"
        severity = "Critical"
        // Added IOCs (Indicators of Compromise) we discovered
        c2_ip_1 = "185.207.225.218"
        c2_ip_2 = "180.196.247.222"

    strings:
        // 1. Unencrypted control strings
        $s1 = "TAKE" fullword
        $s2 = "/tmp/.h" fullword
        $s3 = "/dev/null" fullword

        // 2. Characteristic DDoS module strings
        $d1 = "HTTPFLOOD"
        $d2 = "UDP"
        $d3 = "TCP"

        // 3. Raw Socket signatures (MIPS Opcode)
        // Socket creation instruction: socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        $op_raw_socket = { 24 04 00 02 24 05 00 03 24 06 00 12 }

        // 4. Characteristic XOR Keys (in hex format for standardization)
        $key1 = { 2e 67 6a 3d } // .gj=
        $key2 = { 27 60 71 3d } // '`q=

    condition:
        // Check ELF file format and MIPS architecture (Big Endian or Little Endian)
        uint32(0) == 0x464c457f and 
        (uint16(0x12) == 0x0008 or uint16(0x12) == 0x0800) and
        
        // New logical conditions:
        (
            all of ($s*) or             // Contains all: TAKE, /tmp/.h, /dev/null
            $op_raw_socket or           // OR contains Raw Socket machine code
            any of ($key*) or           // OR contains characteristic XOR Keys
            2 of ($d*)                  // OR contains at least 2 attack strings (UDP, TCP, HTTP...)
        )
}
