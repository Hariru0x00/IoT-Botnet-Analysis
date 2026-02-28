import "elf"

rule Linux_Gafgyt_Mirai_SH4_Botnet {
    meta:
        description = "Detects Gafgyt/Mirai Botnet malware variants on SH4 architecture"
        author = "Security_Analysis_Assistant"
        threat_level = "Critical"
        target_arch = "Hitachi SH"
        c2_ip = "50.183.49.88"
        date = "2024-05-20"

    strings:
        /* 1. Characteristic strings from Discovery Module (Device Scanning) */
        $str_ssdp_1 = "M-SEARCH * HTTP/1.1" ascii
        $str_ssdp_2 = "ST: upnp:rootdevice" ascii
        $str_dns = "SNQUERY" ascii

        /* 2. Target system file paths (Target/Anti-Analysis) */
        $path_dvr = "/root/dvr_app" ascii
        $path_watchdog = "/etc/watchdog" ascii

        /* 3. Characteristic machine code patterns (Opcodes) on SH4 architecture */
        
        // UDP Flood Module: mov 0x02, r5 (SOCK_DGRAM) + jsr (socket call)
        $op_udp_flood = { 02 E5 [0-6] 0B 4? }

        // TCP Flood Module: mov 0x01, r5 (SOCK_STREAM) + jsr (socket call)
        $op_tcp_flood = { 01 E5 [0-6] 0B 4? }

        // Structure loading C2 IP address (50.183.49.88) from Literal Pool
        // Address: 0x00416304 -> Little Endian: 04 63 41 00
        $op_load_c2_config = { D? ?? [0-2] 04 63 41 00 }

    condition:
        // Check for ELF file format and SH architecture (Machine ID: 42)
        uint32(0) == 0x464c457f and 
        elf.machine == 42 and
        (
            // Match any network scan strings or system paths
            any of ($str_*) or 
            any of ($path_*) or
            
            // Or match machine code patterns from attack modules
            all of ($op_*)
        )
}
