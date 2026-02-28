rule Gafgyt_Bashlite_MIPS_IoT {
    meta:
        description = "Detects Gafgyt/Bashlite variants targeting IP Cameras (MIPS)"
        author = "Eimiko"
        date = "2024-05-21"
        arch = "MIPS"
        severity = "High"

    strings:
        // 1. Characteristic strings (decoded with XOR 0x20)
        $c2_domain = "CONNECTIVITY.ACCESSCAM.ORG"
        $resolv = "ETC.RESOLV.CONF"
        $nameserver = "NAMESERVER"
        
        // 2. Anti-Virtualization strings (Anti-Analysis)
        $anti_virt_1 = "VIRTIO"
        $anti_virt_2 = "VIRTBLK"
        $anti_virt_3 = "HYPERVISOR"
        $anti_virt_4 = "VFIO"
        
        // 3. System behavior strings
        $oom_adj = "OOM_SCORE_ADJ"
        $proc_dev = "DEVICES"
        $cpu_info = "CPUINFO"

        // 4. Custom Base64 alphabet
        $custom_b64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        // 5. ELF file identification characteristics
        $elf_header = { 7F 45 4C 46 } 

    condition:
        // Check for ELF header at file start
        $elf_header at 0 and
        
        // Check MIPS architecture (Machine type EM_MIPS = 8)
        uint16(18) == 8 and
        
        // Use ALL remaining strings to avoid unreferenced errors
        (
            $c2_domain or 
            ($resolv and $nameserver) or
            2 of ($anti_virt_*) or
            all of ($proc_dev, $cpu_info, $oom_adj) or
            $custom_b64
        )
}
