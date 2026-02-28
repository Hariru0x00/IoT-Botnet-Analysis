rule Malware_MIPS_FlyLegit_Gafgyt {
    meta:
        description = "Detects Gafgyt/Mirai variants targeting MIPS with FlyLegit signature"
        author = "Gemini_Research_Collaborator"
        file_type = "ELF 32-bit LSB MIPS"

    strings:
        /* Group 1: Identification signatures */
        $c2_ip = "176.65.139.18" ascii fullword
        $telegram = "t.me/flylegit" ascii
        $arch = "mips" ascii fullword
        
        /* Group 2: Control commands */
        $cmd_1 = "udpplain" ascii fullword
        $cmd_2 = "syn" ascii fullword
        $cmd_3 = "ping" ascii fullword
        $cmd_4 = "pong" ascii fullword
        
        /* Group 3: System behavior */
        $proc_path = "/proc/%s/comm" ascii
        $self_exe = "/proc/self/exe" ascii

        /* Group 4: Characteristic machine code (Opcode) */
        $hex_checksum = { 97 a3 00 0a 97 a2 00 08 97 a9 00 0c 00 a0 50 21 }

    condition:
        /* Check ELF Header */
        uint32(0) == 0x464c457f and
        (
            /* Condition 1: Contains creator information or C2 IP */
            ($c2_ip or $telegram) or
            
            /* Condition 2: Contains at least 3 control commands and mips architecture */
            (3 of ($cmd_*) and $arch) or
            
            /* Condition 3: Contains checksum machine code and suspicious system paths */
            ($hex_checksum and ($proc_path or $self_exe))
        )
}
