rule Gafgyt_LizardStresser_Custom_Campaign {
    meta:
        description = "Detects Gafgyt variant with specific C2 and campaign ID"
        author = "Gemini AI"
        threat_level = "High"

    strings:
        $campaign_id = "someoffdeeznuts"
        $c2_ip = { 32 B7 31 58 }
        $decoy_ip1 = { 02 04 05 14 }
        $decoy_ip2 = { 01 03 03 07 }
        
        // Chuỗi hệ thống đã XOR 0x1F
        $sys_path1 = { 30 7A 6B 7C 30 6D 7A 6C 70 73 69 31 7C 70 71 79 }

    condition:
        // Kiểm tra header ELF (7F 45 4C 46)
        uint32(0) == 0x464c457f and 
        (
            $campaign_id or 
            $c2_ip or 
            any of ($decoy_ip*) or
            $sys_path1
        )
}
