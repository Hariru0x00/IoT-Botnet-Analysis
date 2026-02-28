import "elf"

rule Linux_Botnet_Gafgyt_SH4_Variant {
    meta:
        description = "Detects Gafgyt/Mirai malware variants on the SH4 architecture"
        author = "đcm"
        date = "2024-05-20"
        severity = "Critical"
        sample_ip = "50.183.49.88"

    strings:
        // 1. Characteristic strings used in device scanning (Discovery)
        $str_ssdp = "M-SEARCH * HTTP/1.1" ascii
        $str_ssdp_host = "ST: upnp:rootdevice" ascii
        $str_dns_query = "SNQUERY" ascii
        
        // 2. System files that the malware checks
        $path_dvr = "/root/dvr_app" ascii
        $path_watchdog = "/etc/watchdog" ascii

        // 3. Characteristic machine code for SH4 architecture (Opcode)
        // mov 0x02, r5 (SOCK_DGRAM) combined with jsr @rX (socket call)
        $op_udp_socket = { 02 E5 [0-4] 0B 4? }
        
        // mov 0x01, r5 (SOCK_STREAM) combined with jsr @rX (socket call)
        $op_tcp_socket = { 01 E5 [0-4] 0B 4? }

        // Structure loading C2 address 50.183.49.88 (0x00416304) from Literal Pool
        $op_load_c2 = { D? ?? [0-2] 04 63 41 00 }

    condition:
        // Check for ELF format and SH architecture (EM_SH = 42)
        uint32(0) == 0x464c457f and elf.machine == 42 and
        (
            // Use string groups to avoid "unreferenced" errors
            any of ($str_*) or 
            any of ($path_*) or
            any of ($op_*)
        )
}
