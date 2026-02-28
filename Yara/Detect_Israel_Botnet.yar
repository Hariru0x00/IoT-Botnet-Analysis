import "elf"

rule Detect_Israel_Botnet_Mirai_Variant {
    meta:
        author = "Security_Analyst_Termux"
        description = "Detects Israel-themed Botnet variants (Gafgyt/Mirai) - Fixed reference errors"
        severity = "Critical"

    strings:
        // 1. Filenames on server 64.89.163.109
        $s1 = "israel.armv4l" ascii fullword
        $s2 = "israel.mips" ascii fullword
        $s3 = "israel.x86_64" ascii fullword
        $s4 = "cat.sh" ascii fullword

        // 2. Attack functions (DDoS Engine)
        $h1 = "sh4_flood" ascii
        $h2 = "udp_flood" ascii
        $h3 = "tcp_flood" ascii
        $h4 = "http_flood" ascii

        // 3. IoT device traces from Pentest Report
        $d1 = "hi3511_dvr" ascii
        $d2 = "gmDVR" ascii
        $d3 = "dvr_main" ascii

        // 4. C2 Commands
        $c1 = "LISTEN" ascii
        $c2 = "RESOLVE" ascii
        $c3 = "KILL" ascii fullword

        // 5. Exposed system paths (Path Disclosure)
        $p1 = "/proc/self/exe" ascii
        $p2 = "/dev/null" ascii
        $p3 = "/bin/bash" ascii

    condition:
        // Check for ELF format (7F 45 4C 46)
        uint32(0) == 0x464c457f and
        (
            // Match at least 2 israel filenames
            2 of ($s*) or 
            // Or match at least 2 flood functions
            2 of ($h*) or
            // Or match DVR traces combined with system paths
            (1 of ($d*) and 1 of ($p*)) or
            // Or match C2 commands combined with system paths
            (1 of ($c*) and any of ($p*))
        )
}
