rule Malware_ARM_Bot_Generic {
    meta:
        description = "Detects Mirai/Gafgyt family Botnets on ARM architecture"
        author = "yae miko"
        date = "2026-02-28"
        file_type = "ELF 32-bit LSB ARM"

    strings:
        // Characteristic network functions discovered
        $func1 = "initConnection"
        $func2 = "connectTimeout"
        $func3 = "make_garbage"
        
        // System functions commonly exploited
        $sys1 = "setresuid"
        $sys2 = "__libc_nanosleep"
        
        // Indicators of decryption or attack mechanisms (commonly found in these bots)
        $s1 = "invalid password" nocase
        $s2 = "REPORT %s:%s" // Reporting string to C2
        $s3 = "HTTP/1.1" // Used for HTTP Flood

    condition:
        // Check ELF header (7F 45 4C 46) and ARM architecture (offset 18 is 0x28)
        uint32(0) == 0x464c457f and uint16(0x12) == 0x28 and
        
        // Must have at least 3 of the characteristic functions
        3 of ($func*) and
        
        // Or have attack strings combined with system functions
        (any of ($s*) and all of ($sys*))
}
